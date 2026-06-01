package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andyleap/tinyoauth/internal/apps"
	"github.com/andyleap/tinyoauth/internal/config"
	"github.com/andyleap/tinyoauth/internal/session"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestServer builds a Server with a usable codec and config. When admin is
// true, the /debug page is enabled with an "admins" group.
func newTestServer(t *testing.T, admin bool) (*Server, *session.Codec) {
	t.Helper()
	codec, err := session.NewCodec(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthHost: "auth.example.com", Issuer: "https://idp", CookieName: "_tinyoauth"}
	s := &Server{Cfg: cfg, Codec: codec, SessionTTL: time.Hour, Apps: &apps.Resolver{}, Logger: discardLogger(), Version: "test"}
	if admin {
		cfg.AdminClientID = "admin-client"
		cfg.AdminGroups = "admins"
		s.AdminGroups = []string{"admins"}
	}
	return s, codec
}

func sessionCookie(t *testing.T, c *session.Codec, sess session.Session) *http.Cookie {
	t.Helper()
	v, err := c.Seal(&sess)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "_tinyoauth", Value: v}
}

func TestHandleHome(t *testing.T) {
	s, c := newTestServer(t, false)

	rr := httptest.NewRecorder()
	s.handleHome(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "not signed in") {
		t.Fatalf("signed-out home: code=%d body=%s", rr.Code, rr.Body)
	}

	rr = httptest.NewRecorder()
	s.handleHome(rr, httptest.NewRequest("GET", "/favicon.ico", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("stray path: want 404 got %d", rr.Code)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(t, c, session.Session{App: "ns/app", Subject: "u1", Email: "u@e.com", Expiry: time.Now().Add(time.Hour)}))
	rr = httptest.NewRecorder()
	s.handleHome(rr, req)
	if !strings.Contains(rr.Body.String(), "u@e.com") || !strings.Contains(rr.Body.String(), "Sign out") {
		t.Fatalf("signed-in home: %s", rr.Body)
	}
}

func TestHandleDebugDisabled(t *testing.T) {
	s, _ := newTestServer(t, false)
	rr := httptest.NewRecorder()
	s.handleDebug(rr, httptest.NewRequest("GET", "/debug", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled debug: want 404 got %d", rr.Code)
	}
}

func TestHandleDebugAuth(t *testing.T) {
	s, c := newTestServer(t, true)

	// No session -> redirect into self-login.
	rr := httptest.NewRecorder()
	s.handleDebug(rr, httptest.NewRequest("GET", "/debug", nil))
	if rr.Code != http.StatusFound || !strings.Contains(rr.Header().Get("Location"), "app=_self_%2F_self_") {
		t.Fatalf("debug redirect: code=%d loc=%s", rr.Code, rr.Header().Get("Location"))
	}

	// Self session but not in admin group -> forbidden.
	req := httptest.NewRequest("GET", "/debug", nil)
	req.AddCookie(sessionCookie(t, c, session.Session{App: selfAppKey, Subject: "u1", Groups: []string{"users"}, Expiry: time.Now().Add(time.Hour)}))
	rr = httptest.NewRecorder()
	s.handleDebug(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-admin: want 403 got %d", rr.Code)
	}

	// Self session in admin group -> 200, no secret leak.
	req = httptest.NewRequest("GET", "/debug", nil)
	req.AddCookie(sessionCookie(t, c, session.Session{App: selfAppKey, Subject: "u1", Email: "a@e.com", Groups: []string{"admins"}, Expiry: time.Now().Add(time.Hour)}))
	rr = httptest.NewRecorder()
	s.handleDebug(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin: want 200 got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "cookie_secret") {
		t.Fatal("debug page leaked cookie_secret")
	}
	if !strings.Contains(rr.Body.String(), "admin_client_id") {
		t.Fatal("debug page missing config view")
	}
}
