package tokens

import (
	"context"
	"fmt"
	"sync"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Minter struct {
	Clientset      kubernetes.Interface
	Namespace      string
	ServiceAccount string
	TTL            time.Duration

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	token  string
	expiry time.Time
}

func New(cs kubernetes.Interface, namespace, sa string) *Minter {
	return &Minter{
		Clientset:      cs,
		Namespace:      namespace,
		ServiceAccount: sa,
		TTL:            10 * time.Minute,
		cache:          map[string]cached{},
	}
}

func (m *Minter) Token(ctx context.Context, audience string) (string, error) {
	m.mu.Lock()
	if c, ok := m.cache[audience]; ok && time.Until(c.expiry) > m.TTL/4 {
		tok := c.token
		m.mu.Unlock()
		return tok, nil
	}
	m.mu.Unlock()

	ttlSecs := int64(m.TTL.Seconds())
	req := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &ttlSecs,
		},
	}
	resp, err := m.Clientset.CoreV1().
		ServiceAccounts(m.Namespace).
		CreateToken(ctx, m.ServiceAccount, req, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create SA token (ns=%s sa=%s aud=%s): %w", m.Namespace, m.ServiceAccount, audience, err)
	}

	m.mu.Lock()
	m.cache[audience] = cached{token: resp.Status.Token, expiry: resp.Status.ExpirationTimestamp.Time}
	m.mu.Unlock()
	return resp.Status.Token, nil
}
