package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"

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

	// AdminClientID enables the authenticated /debug page via OIDC self-login.
	// When empty, /debug is disabled. AdminGroups/AdminSubs (CSV) restrict who
	// may view it; if AdminClientID is set but both are empty, /debug stays
	// disabled (fail closed).
	AdminClientID string `yaml:"admin_client_id"`
	AdminGroups   string `yaml:"admin_groups"`
	AdminSubs     string `yaml:"admin_subs"`

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
	applyEnvFallbacks(&c)

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
		missing = append(missing, "namespace (or TINYOAUTH_NAMESPACE env)")
	}
	if c.ServiceAccount == "" {
		missing = append(missing, "service_account (or TINYOAUTH_SERVICE_ACCOUNT env)")
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

// applyEnvFallbacks fills any empty string field from the environment, using
// the env var TINYOAUTH_<YAML_TAG> derived from each field's yaml tag. Values
// already set from the config file are left untouched, so the config file
// always takes precedence over the environment.
func applyEnvFallbacks(c *Config) {
	v := reflect.ValueOf(c).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.String || !f.CanSet() || f.String() != "" {
			continue
		}
		yamlTag := strings.Split(t.Field(i).Tag.Get("yaml"), ",")[0]
		if yamlTag == "" || yamlTag == "-" {
			continue
		}
		if val := os.Getenv("TINYOAUTH_" + strings.ToUpper(yamlTag)); val != "" {
			f.SetString(val)
		}
	}
}
