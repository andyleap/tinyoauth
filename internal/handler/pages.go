package handler

import (
	"bytes"
	"html/template"
	"net/http"
	"net/url"

	"github.com/andyleap/tinyoauth/internal/apps"
	"github.com/andyleap/tinyoauth/internal/session"
)

// render executes tmpl into a buffer first so a template error yields a clean
// 500 instead of a half-written 200 response.
func (s *Server) render(w http.ResponseWriter, tmpl *template.Template, data any) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		s.Logger.Error("render template", "tmpl", tmpl.Name(), "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(w)
}

// sessionFromCookie decodes and validates the session cookie, returning nil when
// there is no usable session.
func (s *Server) sessionFromCookie(r *http.Request) *session.Session {
	c, err := r.Cookie(s.Cfg.CookieName)
	if err != nil {
		return nil
	}
	var sess session.Session
	if err := s.Codec.Open(c.Value, &sess); err != nil || !sess.Valid() {
		return nil
	}
	return &sess
}

func displayName(sess *session.Session) string {
	switch {
	case sess.Email != "":
		return sess.Email
	case sess.Name != "":
		return sess.Name
	case sess.PreferredUsername != "":
		return sess.PreferredUsername
	default:
		return sess.Subject
	}
}

type homeData struct {
	Version      string
	SignedIn     bool
	User         string
	DebugEnabled bool
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data := homeData{Version: s.Version, DebugEnabled: s.debugEnabled()}
	if sess := s.sessionFromCookie(r); sess != nil {
		data.SignedIn = true
		data.User = displayName(sess)
	}
	s.render(w, homeTmpl, data)
}

type kv struct{ Key, Value string }

type debugData struct {
	Version  string
	Commit   string
	Date     string
	AuthHost string
	Config   []kv
	Session  *session.Session
	Cache    []apps.CacheEntry
}

func (s *Server) handleDebug(w http.ResponseWriter, r *http.Request) {
	if !s.debugEnabled() {
		http.NotFound(w, r)
		return
	}

	sess := s.sessionFromCookie(r)
	if sess == nil || sess.App != selfAppKey {
		q := url.Values{}
		q.Set("app", selfAppKey)
		q.Set("rd", "https://"+s.Cfg.AuthHost+"/debug")
		http.Redirect(w, r, "https://"+s.Cfg.AuthHost+"/start?"+q.Encode(), http.StatusFound)
		return
	}

	self, err := s.selfApp()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !self.Permit("/", sess.Subject, sess.Groups) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	s.render(w, debugTmpl, debugData{
		Version:  s.Version,
		Commit:   s.Commit,
		Date:     s.Date,
		AuthHost: s.Cfg.AuthHost,
		Config:   s.redactedConfig(),
		Session:  sess,
		Cache:    s.Apps.Snapshot(),
	})
}

// redactedConfig returns an explicit allowlist of non-secret config values. It
// deliberately never includes CookieSecret/cookieKey.
func (s *Server) redactedConfig() []kv {
	c := s.Cfg
	return []kv{
		{"listen", c.Listen},
		{"auth_host", c.AuthHost},
		{"issuer", c.Issuer},
		{"cookie_name", c.CookieName},
		{"cookie_domain", c.CookieDomain},
		{"session_ttl", c.SessionTTL},
		{"annotation_prefix", c.AnnotationPrefix},
		{"namespace", c.Namespace},
		{"service_account", c.ServiceAccount},
		{"admin_client_id", c.AdminClientID},
		{"admin_groups", c.AdminGroups},
		{"admin_subs", c.AdminSubs},
	}
}

const pageCSS = `
:root { color-scheme: light dark; }
body { font: 15px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 3rem auto; padding: 0 1.25rem; }
h1 { margin-bottom: 0.25rem; }
.muted { color: #888; }
a { color: #2563eb; }
table { border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }
th, td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid #8884; vertical-align: top; }
th { white-space: nowrap; }
code { font-family: ui-monospace, monospace; }
.tag { font-size: 0.8em; padding: 0.05rem 0.4rem; border-radius: 0.4rem; background: #8883; }
`

var homeTmpl = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tinyoauth</title><style>` + pageCSS + `</style></head>
<body>
<h1>tinyoauth</h1>
<p class="muted">A tiny OIDC forward-auth service for Traefik. <span class="tag">{{.Version}}</span></p>
{{if .SignedIn}}
<p>Signed in as <strong>{{.User}}</strong>. <a href="/sign_out">Sign out</a></p>
{{else}}
<p>You are not signed in. Access to protected apps will prompt you to log in automatically.</p>
{{end}}
{{if .DebugEnabled}}<p><a href="/debug">Debug &amp; diagnostics &rarr;</a></p>{{end}}
</body></html>
`))

var debugTmpl = template.Must(template.New("debug").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tinyoauth &middot; debug</title><style>` + pageCSS + `</style></head>
<body>
<h1>tinyoauth debug</h1>
<p class="muted"><a href="/">&larr; home</a> &middot; <a href="/sign_out?rd=https://{{.AuthHost}}/">sign out</a></p>

<h2>Build</h2>
<table>
<tr><th>version</th><td><code>{{.Version}}</code></td></tr>
<tr><th>commit</th><td><code>{{.Commit}}</code></td></tr>
<tr><th>date</th><td><code>{{.Date}}</code></td></tr>
</table>

<h2>Config <span class="muted">(secrets redacted)</span></h2>
<table>
{{range .Config}}<tr><th>{{.Key}}</th><td><code>{{if .Value}}{{.Value}}{{else}}<span class="muted">(unset)</span>{{end}}</code></td></tr>
{{end}}</table>

<h2>Current session</h2>
<table>
<tr><th>app</th><td><code>{{.Session.App}}</code></td></tr>
<tr><th>subject</th><td><code>{{.Session.Subject}}</code></td></tr>
<tr><th>email</th><td>{{.Session.Email}}</td></tr>
<tr><th>preferred_username</th><td>{{.Session.PreferredUsername}}</td></tr>
<tr><th>name</th><td>{{.Session.Name}}</td></tr>
<tr><th>groups</th><td>{{range .Session.Groups}}<span class="tag">{{.}}</span> {{else}}<span class="muted">(none)</span>{{end}}</td></tr>
<tr><th>expiry</th><td>{{.Session.Expiry}}</td></tr>
</table>

<h2>Resolver cache <span class="muted">({{len .Cache}})</span></h2>
{{if .Cache}}<table>
<tr><th>app</th><th>client_id</th><th>groups</th><th>rules</th><th>expires</th></tr>
{{range .Cache}}<tr>
<td><code>{{.Key}}</code>{{if .Expired}} <span class="tag">expired</span>{{end}}</td>
<td><code>{{.App.ClientID}}</code></td>
<td>{{range .App.DefaultGroups}}<span class="tag">{{.}}</span> {{else}}<span class="muted">(any)</span>{{end}}</td>
<td>{{len .App.Rules}}</td>
<td>{{.Expires}}</td>
</tr>
{{end}}</table>
{{else}}<p class="muted">empty</p>{{end}}
</body></html>
`))
