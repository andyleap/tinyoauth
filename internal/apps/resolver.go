package apps

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var middlewareGVR = schema.GroupVersionResource{
	Group:    "traefik.io",
	Version:  "v1alpha1",
	Resource: "middlewares",
}

type App struct {
	Namespace     string
	Name          string
	ClientID      string
	Audience      string
	Scopes        []string
	DefaultGroups []string
	AllowedSubs   []string
	Rules         []Rule
}

type Rule struct {
	PathPrefix    string   `yaml:"path_prefix"`
	AllowedGroups []string `yaml:"allowed_groups"`
}

type policyFile struct {
	DefaultAllowedGroups []string `yaml:"default_allowed_groups"`
	AllowedSubs          []string `yaml:"allowed_subs"`
	Rules                []Rule   `yaml:"rules"`
}

type Resolver struct {
	Dynamic          dynamic.Interface
	Kube             kubernetes.Interface
	AnnotationPrefix string
	CacheTTL         time.Duration

	mu    sync.Mutex
	cache map[string]cachedApp
}

type cachedApp struct {
	app     *App
	expires time.Time
}

func New(dyn dynamic.Interface, kube kubernetes.Interface, prefix string) *Resolver {
	return &Resolver{
		Dynamic:          dyn,
		Kube:             kube,
		AnnotationPrefix: prefix,
		CacheTTL:         30 * time.Second,
		cache:            map[string]cachedApp{},
	}
}

func (r *Resolver) ann(key string) string { return r.AnnotationPrefix + "/" + key }

// CacheEntry is a read-only view of a single resolved app held in the cache.
type CacheEntry struct {
	Key     string
	App     *App
	Expires time.Time
	Expired bool
}

// Snapshot returns a stable, sorted copy of the resolver cache for diagnostics.
// The *App values are immutable after caching, so sharing the pointers is safe.
func (r *Resolver) Snapshot() []CacheEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	out := make([]CacheEntry, 0, len(r.cache))
	for k, c := range r.cache {
		out = append(out, CacheEntry{Key: k, App: c.app, Expires: c.expires, Expired: now.After(c.expires)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func (r *Resolver) Resolve(ctx context.Context, namespace, name string) (*App, error) {
	cacheKey := namespace + "/" + name

	r.mu.Lock()
	if c, ok := r.cache[cacheKey]; ok && time.Now().Before(c.expires) {
		r.mu.Unlock()
		return c.app, nil
	}
	r.mu.Unlock()

	mw, err := r.Dynamic.Resource(middlewareGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get middleware %s/%s: %w", namespace, name, err)
	}
	anns := mw.GetAnnotations()

	configRef := anns[r.ann("config-ref")]
	if configRef == "" {
		return nil, fmt.Errorf("middleware %s/%s missing annotation %s", namespace, name, r.ann("config-ref"))
	}
	cfgCM, err := r.Kube.CoreV1().ConfigMaps(namespace).Get(ctx, configRef, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get configmap %s/%s: %w", namespace, configRef, err)
	}
	clientID := strings.TrimSpace(cfgCM.Data["client_id"])
	audience := strings.TrimSpace(cfgCM.Data["audience"])
	scopes := SplitCSV(cfgCM.Data["scopes"])
	if clientID == "" {
		return nil, fmt.Errorf("configmap %s/%s missing data.client_id", namespace, configRef)
	}
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "groups"}
	}

	app := &App{
		Namespace: namespace,
		Name:      name,
		ClientID:  clientID,
		Audience:  audience,
		Scopes:    scopes,
	}

	if v := anns[r.ann("allowed-groups")]; v != "" {
		app.DefaultGroups = SplitCSV(v)
	}
	if v := anns[r.ann("allowed-subs")]; v != "" {
		app.AllowedSubs = SplitCSV(v)
	}

	if polRef := anns[r.ann("policy-ref")]; polRef != "" {
		polCM, err := r.Kube.CoreV1().ConfigMaps(namespace).Get(ctx, polRef, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get policy configmap %s/%s: %w", namespace, polRef, err)
		}
		raw, ok := polCM.Data["rules.yaml"]
		if !ok {
			return nil, fmt.Errorf("policy configmap %s/%s missing data.rules.yaml", namespace, polRef)
		}
		var pf policyFile
		if err := yaml.Unmarshal([]byte(raw), &pf); err != nil {
			return nil, fmt.Errorf("parse policy configmap %s/%s: %w", namespace, polRef, err)
		}
		if len(pf.DefaultAllowedGroups) > 0 {
			app.DefaultGroups = pf.DefaultAllowedGroups
		}
		if len(pf.AllowedSubs) > 0 {
			app.AllowedSubs = pf.AllowedSubs
		}
		app.Rules = pf.Rules
	}

	r.mu.Lock()
	r.cache[cacheKey] = cachedApp{app: app, expires: time.Now().Add(r.CacheTTL)}
	r.mu.Unlock()
	return app, nil
}

func SplitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (a *App) Permit(path string, subject string, groups []string) bool {
	for _, s := range a.AllowedSubs {
		if s == subject {
			return true
		}
	}
	required := a.DefaultGroups
	for _, rule := range a.Rules {
		if rule.PathPrefix == "" {
			continue
		}
		if strings.HasPrefix(path, rule.PathPrefix) {
			required = rule.AllowedGroups
			break
		}
	}
	if len(required) == 0 {
		return true
	}
	for _, g := range required {
		for _, sg := range groups {
			if g == sg {
				return true
			}
		}
	}
	return false
}
