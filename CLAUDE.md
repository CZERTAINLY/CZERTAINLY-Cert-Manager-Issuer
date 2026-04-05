# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kubernetes operator implementing a cert-manager Issuer for the CZERTAINLY PKI platform. It bridges cert-manager's `CertificateRequest` workflow with CZERTAINLY's certificate lifecycle API (issue, renew, rekey). Built with Go using controller-runtime and cert-manager's issuer-lib abstraction.

## Build & Development Commands

```bash
make build              # Build manager binary (bin/manager)
make test               # Run unit tests (uses envtest, excludes e2e)
make lint               # Run golangci-lint (config in .golangci.yml)
make lint-fix           # Auto-fix lint issues
make fmt                # go fmt
make vet                # go vet
make manifests          # Regenerate CRDs and RBAC from Go types
make generate           # Regenerate DeepCopy methods
make run                # Run controller locally (needs --cluster-resource-namespace or in-cluster)
```

Run a single test:
```bash
KUBEBUILDER_ASSETS="$(bin/setup-envtest-* use 1.29.0 --bin-dir bin -p path)" go test ./internal/signer/ -run TestFunctionName -v
```

E2E testing (requires Kind cluster):
```bash
make kind-cluster deploy-cert-manager install install-rbac   # Setup
make docker-build && make kind-load && make deploy           # Deploy controller
make test-e2e                                                 # Run e2e tests
make prune-kind-cluster                                       # Cleanup
```

## OpenAPI Client Generation

The `internal/signer/czertainly/` directory is **entirely generated** from the CZERTAINLY OpenAPI spec. Do not edit files there manually.

```bash
make openapi-generate                         # Generate from default API version (2.17.0)
make openapi-generate API_VERSION=X.Y.Z       # Generate from specific version
make openapi-clean                            # Remove all generated files
```

Requires `openapi-generator` CLI installed. Config is in `openapi-generator-config.yaml`. Post-generation patches live in `openapi-patch/`.

## Architecture

### Control Flow

```
CertificateRequest → issuer-lib CombinedController → Issuer.Check() → Issuer.Sign()
                                                          ↓                  ↓
                                                    HealthChecker      czertainlySigner
                                                    (GetInfo+Profile)  (issue/renew/rekey → poll)
```

The operator does NOT use traditional Kubernetes reconcilers directly. Instead, `issuer-lib`'s `CombinedController` handles reconciliation and calls two methods:
- **Check**: Validates CZERTAINLY connectivity (calls `/info` and `/profile` endpoints)
- **Sign**: Orchestrates certificate issuance through CZERTAINLY API

### Key Source Files

- `main.go` - Entry point, flag parsing, manager setup
- `internal/controllers/signer.go` - Issuer controller wiring Check/Sign to issuer-lib
- `internal/signer/signer.go` - Core signing logic: HTTP client setup, auth, issue/renew/rekey/poll
- `internal/signer/helpers.go` - K8s helpers: owner refs, annotations, secret lookups
- `internal/signer/x509util.go` - CSR/cert parsing, public key matching
- `internal/signer/constants.go` - HTTP timeout defaults, annotation keys
- `api/v1alpha1/` - CRD type definitions (CzertainlyIssuer, CzertainlyClusterIssuer)

### CRDs

Two custom resources with identical specs (namespaced vs cluster-scoped):
- `CzertainlyIssuer` (namespaced)
- `CzertainlyClusterIssuer` (cluster-scoped)

Key spec fields: `apiUrl`, `authSecretName`, `raProfileUuid`, `caBundleSecretName`, `httpTransport`

### Authentication

Determined by Kubernetes Secret type:
- `kubernetes.io/tls` - mTLS client certificate auth (fields: `tls.crt`, `tls.key`)
- `Opaque` - OAuth2 client credentials flow (fields: `client_id`, `client_secret`, `token_url`, `scopes`)

### Certificate Lifecycle

- **New issuance**: No `certificate-uuid` annotation → calls `IssueCertificate`
- **Renewal**: Has annotation + secret has `tls.crt` + no key rotation → calls `RenewCertificate`
- **Rekey**: Has annotation + secret has `tls.crt` + key rotation=Always → calls `RekeyCertificate`
- **Polling**: After any request, polls every 10s until ISSUED, FAILED, or REJECTED
- **Annotation**: `czertainly-issuer.czertainly.com/certificate-uuid` tracks cert UUID on the owning Certificate object

### Error Handling

- `signer.PermanentError` - No retry (validation failures, rejected certs)
- `signer.IssuerError` - Marks the Issuer itself as failed
- Regular errors - Retried up to `MaxRetryDuration` (1 minute)

## Linting

golangci-lint with 20 linters enabled. Notable exclusions:
- `api/*` paths: `lll` (line length) excluded
- `internal/*` paths: `dupl` and `lll` excluded
