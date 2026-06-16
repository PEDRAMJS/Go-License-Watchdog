# Go-License-Watchdog

A cryptographic license enforcement library for Go applications. Embed it in your binary — it gates all HTTP traffic behind a signed license token that you issue. When the license expires, requests get a `402`. Send a revoke token to lock a deployment instantly without destroying anything (reversible), or a terminate token to make the binary self-destruct.

Zero external dependencies. Pure stdlib.

---

## How it works

1. You generate an ECDSA keypair. The **public key** is baked into every binary you ship. The **private key** never leaves your machine.
2. Your binary runs a small side-car HTTP server (default `127.0.0.1:18443`). This is separate from your application's server.
3. A customer installs your app. It starts **unlicensed** — the middleware blocks all requests with `402` until a token is submitted.
4. The customer fetches their `instance_id` from `GET {SecretPath}/instance` and shares it with you.
5. You generate a signed JWT token bound to that instance and valid for up to 7 days.
6. The customer submits the token to `POST {SecretPath}/token`. The license activates immediately.
7. Repeat before expiry to keep the service running. Stop issuing tokens to lock the customer out.

---

## Security model

| Layer | Protection |
|-------|-----------|
| ES256 ECDSA signature | Only the private key holder can create valid tokens |
| Absolute token expiry | `exp` is a fixed timestamp; replaying the same token is harmless |
| Instance ID binding | Each token is tied to a specific machine's fingerprint |
| One-time JTI | Each token ID is accepted only once — no same-machine replay |
| Clock rewind detection | Wall clock is compared across enforcement ticks; a backwards jump invalidates the license |
| AES-256-GCM state | Persisted state is encrypted and stored in 3 independent locations with anti-rollback revision counters |

---

## Installation

```bash
go get github.com/PEDRAMJS/Go-License-Watchdog
```

---

## Quick start

### Step 1 — Generate your keypair (once)

```bash
go run github.com/PEDRAMJS/Go-License-Watchdog/cmd/keygen
```

This writes two files:

| File | Purpose |
|------|---------|
| `watchdog_private.pem` | Signs tokens — **never commit, never ship** |
| `watchdog_public.pem` | Baked into your binary — safe to commit |

### Step 2 — Embed the public key and start the watchdog

```go
package main

import (
    _ "embed"
    "log"
    "net/http"

    watchdog "github.com/PEDRAMJS/Go-License-Watchdog"
)

//go:embed watchdog_public.pem
var publicKeyPEM string

func main() {
    wd, err := watchdog.Start(watchdog.Config{
        SecretPath:   "/xK9mP2qR7sL3vN8w", // long, random — this is your admin path
        PublicKeyPEM: publicKeyPEM,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer wd.Stop()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("hello"))
    })

    // All routes behind this middleware require a valid license
    http.ListenAndServe(":8080", wd.Middleware()(mux))
}
```

---

## Adding the middleware

`wd.Middleware()` returns a standard `func(http.Handler) http.Handler` compatible with any `net/http`-based router.

### stdlib `net/http`

```go
http.ListenAndServe(":8080", wd.Middleware()(yourMux))
```

### [chi](https://github.com/go-chi/chi)

```go
r := chi.NewRouter()
r.Use(wd.Middleware())
r.Get("/", yourHandler)
```

### [gorilla/mux](https://github.com/gorilla/mux)

```go
r := mux.NewRouter()
r.Use(wd.Middleware())
r.HandleFunc("/", yourHandler)
```

### [echo](https://echo.labstack.com/)

```go
e := echo.New()
e.Use(echo.WrapMiddleware(wd.Middleware()))
```

### [gin](https://gin-gonic.com/)

Gin uses its own middleware signature, so wrap it manually:

```go
r := gin.New()
r.Use(func(c *gin.Context) {
    if !wd.IsValid() {
        c.AbortWithStatusJSON(http.StatusPaymentRequired, gin.H{
            "error": "license expired or not activated",
        })
        return
    }
    c.Next()
})
```

### Apply selectively to a route group

You can apply the middleware to only a subset of routes:

```go
// chi example — public routes are unaffected
r := chi.NewRouter()

r.Get("/health", healthHandler)  // always reachable

r.Group(func(r chi.Router) {
    r.Use(wd.Middleware())
    r.Get("/api/data", dataHandler)
    r.Post("/api/submit", submitHandler)
})
```

### Custom response when license is expired

Override `OnUnauthorized` in the config to return whatever shape your API uses:

```go
wd, _ := watchdog.Start(watchdog.Config{
    SecretPath:   "/xK9mP2qR7sL3vN8w",
    PublicKeyPEM: publicKeyPEM,
    OnUnauthorized: func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusPaymentRequired)
        w.Write([]byte(`{"code":402,"message":"license required","contact":"support@yourcompany.com"}`))
    },
})
```

---

## Watchdog server routes

The watchdog runs its **own** HTTP server on `127.0.0.1:18443` (configurable via `Config.ListenAddr`). These routes are **separate** from your application's server and are never exposed through your app's router or middleware.

### `GET {SecretPath}/instance`

Returns the instance ID of the running deployment and current license status.

**Response**

```json
{
  "instance_id": "a3f9b2c1d4e5f607...",
  "valid_until":  "2026-06-23T12:00:00Z"
}
```

If no license has been activated yet, `valid_until` is `"not activated"`.

**Use this to get the `instance_id` you need to generate a bound token.**

---

### `POST {SecretPath}/token`

Submits a signed license, revoke, or terminate token.

**Request body**

```json
{
  "token": "<es256_jwt>"
}
```

**License response** `200 OK`

```json
{
  "status":      "ok",
  "valid_until": "2026-06-23T12:00:00Z"
}
```

**Revoke response** `200 OK`

```json
{
  "status": "revoked"
}
```

The current license is invalidated immediately — the next request gets a `402`. The process keeps
running and **nothing is deleted**; submitting a fresh license token re-activates the instance.
This is the user-friendly counterpart to terminate.

**Terminate response** `200 OK`

```json
{
  "status": "terminating"
}
```

The process self-destructs 200ms after this response is sent. Only the binary and the watchdog's own
state files are removed — application data (databases, uploads, configs) is never touched.

**Error response** `401 Unauthorized`

```json
{
  "error": "unauthorized"
}
```

The error message is always vague — which check failed is never revealed to the caller.

> **Note:** All other paths on the watchdog server return `404`. This gives no information about whether you found the right base path.

---

## Vendor workflow

### 1. Generate a license token

Once you have a customer's `instance_id`:

```bash
go run github.com/PEDRAMJS/Go-License-Watchdog/cmd/tokengen \
    -key      watchdog_private.pem \
    -instance a3f9b2c1d4e5f607... \
    -days     7 \
    -customer acme-corp
```

The token is printed to stdout. Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-key` | `watchdog_private.pem` | Path to your EC private key |
| `-instance` | required | Instance ID to bind this token to |
| `-days` | `7` | License duration, 1–7 |
| `-customer` | — | Optional customer reference (for your records) |
| `-action` | `license` | `license`, `revoke`, or `terminate` |

### 2. Customer submits the token

```bash
curl -s -X POST http://127.0.0.1:18443/xK9mP2qR7sL3vN8w/token \
     -H "Content-Type: application/json" \
     -d '{"token": "eyJhbGci..."}'
```

Or in Postman: `POST` → body `raw / JSON` → `{"token": "eyJhbGci..."}`.

### 3. Generate a revoke token (recommended for cutting access)

To remotely lock a deployment **without destroying anything** — the process keeps running, every
request gets a `402`, and a future license token brings it straight back:

```bash
go run github.com/PEDRAMJS/Go-License-Watchdog/cmd/tokengen \
    -key      watchdog_private.pem \
    -instance a3f9b2c1d4e5f607... \
    -action   revoke
```

A revoke token is valid for 1 hour. Submit it the same way as a license token. Prefer this over
terminate for routine access control (non-payment, suspended account, etc.) — it's reversible.

### 4. Generate a terminate token (destructive, irreversible)

To remotely destroy a deployment — removes the binary and the watchdog's state files (application
data is never touched):

```bash
go run github.com/PEDRAMJS/Go-License-Watchdog/cmd/tokengen \
    -key      watchdog_private.pem \
    -instance a3f9b2c1d4e5f607... \
    -action   terminate
```

A terminate token is valid for 1 hour. Submit it the same way as a license token.

---

## Configuration reference

```go
watchdog.Config{
    // Required
    SecretPath:   "/xK9mP2qR7sL3vN8w",  // min 8 chars, random, keep private
    PublicKeyPEM: publicKeyPEM,           // from cmd/keygen

    // Optional
    ListenAddr:    "127.0.0.1:18443",    // watchdog side-car listen address
    CheckInterval: 1 * time.Hour,        // how often enforcement loop runs
    StateFile:     "",                   // default: $HOME/.cache/.wdstate
    InstanceID:    "",                   // default: auto-derived from machine fingerprint
    AllowedCIDRs:  []string{"10.0.0.0/8"}, // whitelist token submission sources; nil = any

    // Callbacks
    OnExpired: func() {
        // called each enforcement tick while license is expired
        // default: prints a banner to stderr
    },
    OnKill: func() {
        // called immediately on terminate token — must not return
        // default: removes state files, zeros + deletes binary, os.Exit(1)
        db.Close()
        flushLogs()
        os.Exit(1)
    },
    OnUnauthorized: func(w http.ResponseWriter, r *http.Request) {
        // called by Middleware when license is invalid
        // default: 402 JSON {"error":"license expired or not activated"}
    },
}
```

---

## Self-destruct scope

The default `OnKill` removes exactly:

- The watchdog's own state files (`$HOME/.cache/.wdstate` and two hidden backups)
- The running binary (zeroed then unlinked)

**User data, databases, configs, and application files are never touched.**

---

## Token format

Tokens are standard ES256 JWTs. You can inspect them at [jwt.io](https://jwt.io).

| Claim | Type | Description |
|-------|------|-------------|
| `jti` | string | Unique token ID (one-time use) |
| `iss` | string | `"watchdog-vendor"` |
| `nbf` | unix ts | Valid from |
| `exp` | unix ts | Valid until (absolute) |
| `act` | string | `"license"`, `"revoke"`, or `"terminate"` |
| `iid` | string | Bound instance ID |
| `cid` | string | Customer reference (optional) |

---

## State files

Three encrypted copies are maintained automatically:

| Location | Purpose |
|----------|---------|
| `$HOME/.cache/.wdstate` | Primary (configurable via `Config.StateFile`) |
| `$HOME/.local/share/.<hash>` | Hidden backup |
| `$TMPDIR/<hash>` | Hidden backup |

The highest-revision copy wins on startup, preventing rollback attacks via file deletion. All three are removed on self-destruct.
