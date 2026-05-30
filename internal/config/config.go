package config

import (
	"encoding/hex"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen           string `yaml:"listen"`
	AuthHost         string `yaml:"auth_host"`
	Issuer           string `yaml:"issuer"`
	CookieName       string `yaml:"cookie_name"`
	CookieDomain     string `yaml:"cookie_domain"`
	CookieSecret     string `yaml:"cookie_secret"`
	SessionTTL       string `yaml:"session_ttl"`
	AnnotationPrefix string `yaml:"annotation_prefix"`
	Namespace        string `yaml:"namespace"`
	ServiceAccount   string `yaml:"service_account"`

	cookieKey []byte
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Listen == "" {
		c.Listen = ":4180"
	}
	if c.CookieName == "" {
		c.CookieName = "_tinyoauth"
	}
	if c.SessionTTL == "" {
		c.SessionTTL = "12h"
	}
	if c.AnnotationPrefix == "" {
		c.AnnotationPrefix = "tinyoauth.andyleap.dev"
	}
	if c.Namespace == "" {
		c.Namespace = os.Getenv("POD_NAMESPACE")
	}
	if c.ServiceAccount == "" {
		c.ServiceAccount = os.Getenv("POD_SERVICE_ACCOUNT")
	}

	missing := []string{}
	if c.AuthHost == "" {
		missing = append(missing, "auth_host")
	}
	if c.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if c.CookieSecret == "" {
		missing = append(missing, "cookie_secret")
	}
	if c.Namespace == "" {
		missing = append(missing, "namespace (or POD_NAMESPACE env)")
	}
	if c.ServiceAccount == "" {
		missing = append(missing, "service_account (or POD_SERVICE_ACCOUNT env)")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("config missing required: %v", missing)
	}

	key, err := hex.DecodeString(c.CookieSecret)
	if err != nil {
		return nil, fmt.Errorf("cookie_secret must be hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("cookie_secret must be 32 bytes (64 hex chars), got %d", len(key))
	}
	c.cookieKey = key

	return &c, nil
}

func (c *Config) CookieKey() []byte { return c.cookieKey }
