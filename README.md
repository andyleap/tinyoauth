# tinyoauth

A tiny, Kubernetes-native OIDC **forward-auth** service for [Traefik](https://traefik.io/).

tinyoauth sits behind Traefik's `forwardAuth` middleware and gates HTTP traffic
to your apps behind an OIDC login. It authenticates users against an OIDC
provider (e.g. [Pocket ID](https://pocket-id.org/), Keycloak, Dex), stores the
session in a signed cookie, and applies per-app, per-path access policy — all
configured through ordinary Kubernetes resources (Traefik `Middleware`s +
`ConfigMap`s), with no per-app config baked into tinyoauth itself.

## Features

- **OIDC login** via any compliant provider (`coreos/go-oidc`).
- **Forward-auth** integration with Traefik — one tinyoauth deployment guards
  every app in the cluster.
- **Per-app, per-path policy** driven by Kubernetes `ConfigMap`s referenced from
  each Traefik `Middleware` — group- and subject-based rules.
- **Stateless sessions** in an AES-encrypted, signed cookie shared across the
  cookie domain. No session store to run.
- **Identity headers** passed to upstreams (`X-Auth-Request-User`,
  `-Email`, `-Groups`, …) for apps that consume them.
- **Least-privilege RBAC**: read-only access to Middlewares/ConfigMaps, and the
  ability to mint a token only for its own service account.
- **Tiny, distroless image** — static Go binary on `gcr.io/distroless/static`.

## How it works

```
                ┌─────────────┐   forwardAuth    ┌────────────┐
  browser ─────▶│   Traefik   │ ───/check/...──▶ │  tinyoauth │ ──▶ OIDC provider
                └─────────────┘                  └────────────┘
                       │  2xx + identity headers / 302 to /start
                       ▼
                 protected app
```

1. Traefik's `forwardAuth` middleware sends each request to
   `/check/<namespace>/<middleware-name>`.
2. tinyoauth reads the session cookie. If valid and the policy allows the
   request, it returns `202` with `X-Auth-Request-*` identity headers that
   Traefik copies onto the upstream request.
3. If there's no valid session, it returns a redirect to `/start`, which kicks
   off the OIDC authorization-code flow; `/callback` completes it and sets the
   cookie.
4. `/sign_out` clears the session.

Per-app configuration lives entirely in Kubernetes: a Traefik `Middleware`
annotated with references to a config `ConfigMap` (OIDC `client_id`, `audience`)
and an optional policy `ConfigMap` (the access-rules table). See
[examples/k8s/traefik-middleware.yaml](examples/k8s/traefik-middleware.yaml) for
a complete, commented example.

## Endpoints

| Path | Purpose |
|------|---------|
| `/check/<ns>/<name>` | forward-auth decision endpoint (called by Traefik) |
| `/start` | begin the OIDC login flow |
| `/callback` | OIDC redirect/callback |
| `/sign_out` | clear the session |
| `/healthz` | liveness/readiness probe (returns `204`) |

## Configuration

tinyoauth reads a single global YAML config (per-app data lives in Kubernetes
resources, not here). Path resolution order: `-config` flag →
`TINYOAUTH_CONFIG` env → `/etc/tinyoauth/config.yaml`.

```yaml
listen: ":4180"                          # default
auth_host: "auth.example.com"            # required — public host for /start, /callback
issuer: "https://id.example.com"         # required — OIDC issuer URL
cookie_name: "_tinyoauth"                # default
cookie_domain: ".example.com"            # shared across protected apps
cookie_secret: "<64 hex chars>"          # required — 32 bytes; `openssl rand -hex 32`
session_ttl: "12h"                       # default
annotation_prefix: "tinyoauth.example.com"
# namespace / service_account default to the POD_NAMESPACE / POD_SERVICE_ACCOUNT
# env vars (wired via the downward API in the Deployment).
```

See [examples/config.yaml](examples/config.yaml).

## Deploying to Kubernetes

A complete, ready-to-adapt manifest (Namespace, ServiceAccount, least-privilege
RBAC, ConfigMap, Deployment, Service) is in
[examples/k8s/deployment.yaml](examples/k8s/deployment.yaml):

```bash
# 1. Generate a cookie secret and drop it into the config.
openssl rand -hex 32

# 2. Edit examples/k8s/deployment.yaml (auth_host, issuer, cookie_*).
kubectl apply -f examples/k8s/deployment.yaml

# 3. Wire up an app — see examples/k8s/traefik-middleware.yaml.
kubectl apply -f examples/k8s/traefik-middleware.yaml
```

tinyoauth must run **in-cluster** (it uses the in-cluster Kubernetes config to
read Middlewares/ConfigMaps and mint its own service-account token).

## Container images

Multi-arch (`linux/amd64`, `linux/arm64`) images are published to GitHub
Container Registry on every release:

```
ghcr.io/andyleap/tinyoauth:latest
ghcr.io/andyleap/tinyoauth:<version>      # e.g. 1.2.3
ghcr.io/andyleap/tinyoauth:<major>.<minor>
```

## Building from source

Requires Go (see [go.mod](go.mod) for the version).

```bash
# Binary
go build -o tinyoauth ./cmd/tinyoauth
./tinyoauth -version

# Local container image
docker build -t tinyoauth .
```

## Releases

Releases are automated with [GoReleaser](https://goreleaser.com/) via GitHub
Actions ([.github/workflows/release.yml](.github/workflows/release.yml)).
Pushing a `vX.Y.Z` tag builds cross-platform binaries + archives, multi-arch
container images, and a GitHub Release with generated notes:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Version, commit, and build date are injected into the binary at release time and
reported by `tinyoauth -version`.
