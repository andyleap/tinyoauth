package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/andyleap/tinyoauth/internal/apps"
	"github.com/andyleap/tinyoauth/internal/config"
	"github.com/andyleap/tinyoauth/internal/handler"
	"github.com/andyleap/tinyoauth/internal/session"
	"github.com/andyleap/tinyoauth/internal/tokens"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Build information, set via -ldflags at release time by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfgPath := flag.String("config", envOr("TINYOAUTH_CONFIG", "/etc/tinyoauth/config.yaml"), "path to config file")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("tinyoauth %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	cfg, err := config.Load(*cfgPath)
	must(logger, "load config", err)

	codec, err := session.NewCodec(cfg.CookieKey())
	must(logger, "init codec", err)

	ttl, err := time.ParseDuration(cfg.SessionTTL)
	must(logger, "parse session_ttl", err)

	rc, err := rest.InClusterConfig()
	must(logger, "in-cluster k8s config", err)

	kube, err := kubernetes.NewForConfig(rc)
	must(logger, "kubernetes client", err)

	dyn, err := dynamic.NewForConfig(rc)
	must(logger, "dynamic client", err)

	resolver := apps.New(dyn, kube, cfg.AnnotationPrefix)
	minter := tokens.New(kube, cfg.Namespace, cfg.ServiceAccount)

	srv := &handler.Server{
		Cfg:        cfg,
		Codec:      codec,
		SessionTTL: ttl,
		Apps:       resolver,
		Minter:     minter,
		Logger:     logger,
	}

	hs := &http.Server{
		Addr:         cfg.Listen,
		Handler:      logMiddleware(logger, srv.Routes()),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	logger.Info("tinyoauth listening",
		"version", version,
		"commit", commit,
		"addr", cfg.Listen,
		"auth_host", cfg.AuthHost,
		"issuer", cfg.Issuer,
		"namespace", cfg.Namespace,
		"service_account", cfg.ServiceAccount,
	)
	if err := hs.ListenAndServe(); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func must(l *slog.Logger, what string, err error) {
	if err != nil {
		l.Error(what, "err", err)
		os.Exit(2)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func logMiddleware(l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t0 := time.Now()
		ww := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r)
		l.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.status,
			"dur_ms", time.Since(t0).Milliseconds(),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
