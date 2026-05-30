package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andyleap/tinyoauth/internal/apps"
	"github.com/andyleap/tinyoauth/internal/config"
	"github.com/andyleap/tinyoauth/internal/oidc"
	"github.com/andyleap/tinyoauth/internal/session"
	"github.com/andyleap/tinyoauth/internal/tokens"
)

type Server struct {
	Cfg        *config.Config
	Codec      *session.Codec
	SessionTTL time.Duration
	Apps       *apps.Resolver
	Minter     *tokens.Minter
	Logger     *slog.Logger
}

const flowCookieName = "_tinyoauth_flow"

func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/check/", s.handleCheck)
	m.HandleFunc("/start", s.handleStart)
	m.HandleFunc("/callback", s.handleCallback)
	m.HandleFunc("/sign_out", s.handleSignOut)
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	return m
}

func parseAppPath(p string) (ns, name string, ok bool) {
	rest := strings.TrimPrefix(p, "/check/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func appKey(ns, name string) string { return ns + "/" + name }

func (s *Server) redirectURI() string {
	return "https://" + s.Cfg.AuthHost + "/callback"
}

func originalURL(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	if proto == "" {
		proto = "https"
	}
	if host == "" {
		return ""
	}
	if uri == "" {
		uri = "/"
	}
	return proto + "://" + host + uri
}

func forwardedPath(r *http.Request) string {
	uri := r.Header.Get("X-Forwarded-Uri")
	if uri == "" {
		return "/"
	}
	if i := strings.IndexAny(uri, "?#"); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	ns, name, ok := parseAppPath(r.URL.Path)
	if !ok {
		http.Error(w, "bad /check path; expected /check/<namespace>/<name>", http.StatusBadRequest)
		return
	}
	app, err := s.Apps.Resolve(r.Context(), ns, name)
	if err != nil {
		s.Logger.Error("resolve app", "ns", ns, "name", name, "err", err)
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}

	c, err := r.Cookie(s.Cfg.CookieName)
	if err != nil {
		s.redirectToStart(w, r, ns, name)
		return
	}
	var sess session.Session
	if err := s.Codec.Open(c.Value, &sess); err != nil || !sess.Valid() || sess.App != appKey(ns, name) {
		s.redirectToStart(w, r, ns, name)
		return
	}
	if !app.Permit(forwardedPath(r), sess.Subject, sess.Groups) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("X-Auth-Request-User", sess.Subject)
	if sess.Email != "" {
		h.Set("X-Auth-Request-Email", sess.Email)
	}
	if sess.PreferredUsername != "" {
		h.Set("X-Auth-Request-Preferred-Username", sess.PreferredUsername)
	}
	if sess.Name != "" {
		h.Set("X-Auth-Request-Name", sess.Name)
	}
	if len(sess.Groups) > 0 {
		h.Set("X-Auth-Request-Groups", strings.Join(sess.Groups, ","))
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) redirectToStart(w http.ResponseWriter, r *http.Request, ns, name string) {
	rd := originalURL(r)
	q := url.Values{}
	q.Set("app", appKey(ns, name))
	if rd != "" {
		q.Set("rd", rd)
	}
	u := "https://" + s.Cfg.AuthHost + "/start?" + q.Encode()
	http.Redirect(w, r, u, http.StatusFound)
}

func splitAppKey(s string) (string, string, bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("app")
	ns, name, ok := splitAppKey(key)
	if !ok {
		http.Error(w, "missing/invalid app", http.StatusBadRequest)
		return
	}
	app, err := s.Apps.Resolve(r.Context(), ns, name)
	if err != nil {
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}
	cli, err := oidc.Get(r.Context(), s.Cfg.Issuer, app.ClientID, app.Scopes)
	if err != nil {
		s.Logger.Error("oidc client", "err", err)
		http.Error(w, "oidc init failed", http.StatusBadGateway)
		return
	}
	state := randString(24)
	nonce := randString(24)
	cv := randString(48)
	cc := pkceS256(cv)

	flow := session.FlowState{
		App:          appKey(ns, name),
		State:        state,
		Nonce:        nonce,
		CodeVerifier: cv,
		RedirectTo:   r.URL.Query().Get("rd"),
		Expiry:       time.Now().Add(10 * time.Minute),
	}
	enc, err := s.Codec.Seal(&flow)
	if err != nil {
		http.Error(w, "seal flow", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    enc,
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  flow.Expiry,
	})
	http.Redirect(w, r, cli.AuthorizeURL(state, nonce, cc, s.redirectURI()), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if errStr := q.Get("error"); errStr != "" {
		http.Error(w, "auth error: "+errStr+" "+q.Get("error_description"), http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		http.Error(w, "missing code/state", http.StatusBadRequest)
		return
	}

	c, err := r.Cookie(flowCookieName)
	if err != nil {
		http.Error(w, "missing flow cookie", http.StatusBadRequest)
		return
	}
	var flow session.FlowState
	if err := s.Codec.Open(c.Value, &flow); err != nil || !flow.Valid() {
		http.Error(w, "invalid flow state", http.StatusBadRequest)
		return
	}
	if flow.State != state {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}

	ns, name, ok := splitAppKey(flow.App)
	if !ok {
		http.Error(w, "invalid flow app key", http.StatusBadRequest)
		return
	}
	app, err := s.Apps.Resolve(r.Context(), ns, name)
	if err != nil {
		http.Error(w, "unknown app", http.StatusNotFound)
		return
	}
	cli, err := oidc.Get(r.Context(), s.Cfg.Issuer, app.ClientID, app.Scopes)
	if err != nil {
		s.Logger.Error("oidc client", "err", err)
		http.Error(w, "oidc init failed", http.StatusBadGateway)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	audience := app.Audience
	if audience == "" {
		audience = s.Cfg.Issuer
	}
	assertion, err := s.Minter.Token(ctx, audience)
	if err != nil {
		s.Logger.Error("mint sa token", "err", err, "aud", audience)
		http.Error(w, "sa token mint failed", http.StatusBadGateway)
		return
	}

	tok, err := cli.ExchangeCode(ctx, code, flow.CodeVerifier, s.redirectURI(), assertion)
	if err != nil {
		s.Logger.Error("token exchange", "err", err, "app", flow.App)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	claims, err := cli.VerifyIDToken(ctx, tok.IDToken)
	if err != nil {
		s.Logger.Error("verify id_token", "err", err)
		http.Error(w, "id_token verify failed", http.StatusBadGateway)
		return
	}
	if claims.Nonce != flow.Nonce {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}
	if !app.Permit("/", claims.Subject, claims.Groups) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	sess := session.Session{
		App:               flow.App,
		Subject:           claims.Subject,
		Email:             claims.Email,
		PreferredUsername: claims.PreferredUsername,
		Name:              claims.Name,
		Groups:            claims.Groups,
		Expiry:            time.Now().Add(s.SessionTTL),
	}
	enc, err := s.Codec.Seal(&sess)
	if err != nil {
		http.Error(w, "seal session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.Cfg.CookieName,
		Value:    enc,
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.Expiry,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     flowCookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	})

	dest := flow.RedirectTo
	if dest == "" || !strings.HasPrefix(dest, "https://") {
		dest = "https://" + s.Cfg.AuthHost + "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.Cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.Cfg.CookieDomain,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	})
	if rd := r.URL.Query().Get("rd"); strings.HasPrefix(rd, "https://") {
		http.Redirect(w, r, rd, http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func randString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Errorf("rand: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
