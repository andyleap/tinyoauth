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

	// AdminGroups/AdminSubs are the parsed CSV forms of the corresponding config
	// fields; they gate access to the /debug page via the synthetic "self" app.
	AdminGroups []string
	AdminSubs   []string

	// Build information, surfaced on the homepage and /debug.
	Version string
	Commit  string
	Date    string
}

const flowCookieName = "_tinyoauth_flow"

// selfAppKey is a reserved, synthetic app key used to log an admin into
// tinyoauth itself (for the /debug page) without a Kubernetes-backed app. Both
// halves contain underscores, which RFC1123 Kubernetes names cannot, so it can
// never collide with a real namespace/middleware while still round-tripping
// through splitAppKey.
const selfAppKey = "_self_/_self_"

func (s *Server) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/check/", s.handleCheck)
	m.HandleFunc("/start", s.handleStart)
	m.HandleFunc("/callback", s.handleCallback)
	m.HandleFunc("/sign_out", s.handleSignOut)
	m.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	m.HandleFunc("/debug", s.handleDebug)
	m.HandleFunc("/", s.handleHome)
	return m
}

// debugEnabled reports whether the authenticated /debug page is reachable. It
// requires an admin OIDC client plus at least one admin group or subject;
// otherwise it fails closed (an empty allowlist would otherwise admit every
// authenticated user via App.Permit).
func (s *Server) debugEnabled() bool {
	return s.Cfg.AdminClientID != "" && (len(s.AdminGroups) > 0 || len(s.AdminSubs) > 0)
}

// selfApp builds the synthetic admin app used for /debug self-login. It returns
// an error when /debug is disabled, so the OIDC flow refuses to start.
func (s *Server) selfApp() (*apps.App, error) {
	if !s.debugEnabled() {
		return nil, fmt.Errorf("debug self-login disabled")
	}
	ns, name, _ := splitAppKey(selfAppKey)
	return &apps.App{
		Namespace:     ns,
		Name:          name,
		ClientID:      s.Cfg.AdminClientID,
		Audience:      s.Cfg.Issuer,
		Scopes:        []string{"openid", "profile", "email", "groups"},
		DefaultGroups: s.AdminGroups,
		AllowedSubs:   s.AdminSubs,
	}, nil
}

// resolveApp resolves an app key, intercepting the reserved self key with the
// synthetic admin app and delegating everything else to the Kubernetes-backed
// resolver. Only /start and /callback use this; /check stays on Apps.Resolve so
// the self app is never reachable via forward-auth.
func (s *Server) resolveApp(ctx context.Context, ns, name string) (*apps.App, error) {
	if appKey(ns, name) == selfAppKey {
		return s.selfApp()
	}
	return s.Apps.Resolve(ctx, ns, name)
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
	if appKey(ns, name) == selfAppKey {
		http.Error(w, "unknown app", http.StatusNotFound)
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
	app, err := s.resolveApp(r.Context(), ns, name)
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
	app, err := s.resolveApp(r.Context(), ns, name)
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
