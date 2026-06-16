// Package watchdog implements a cryptographic license enforcement system for Go applications.
//
// The vendor signs license tokens with a private ECDSA key. The binary contains only
// the matching public key and verifies tokens submitted over HTTP. While a valid license
// is active the Middleware passes requests through; once it expires all requests receive
// a 402 response until a new token is submitted. An explicit terminate token causes
// immediate self-destruction of the binary.
//
// Security model (4 independent layers):
//
//  1. ES256 ECDSA signature   — only the holder of the private key can create valid tokens
//  2. Absolute token expiry   — tokens carry a fixed valid_until timestamp; replay is harmless
//  3. Instance ID binding     — tokens are bound to a specific deployment's machine fingerprint
//  4. One-time JTI            — each token ID can only be accepted once (no same-machine replay)
//
// Additionally, clock manipulation is detected by comparing consecutive wall clock readings
// across enforcement ticks; a detected rewind invalidates the license immediately.
//
// State is encrypted with AES-256-GCM and persisted to 3 independent locations with
// monotonic revision counters, defeating state-deletion and rollback attacks.
//
// Zero external dependencies — pure stdlib.
//
// # Quick start
//
//	wd, err := watchdog.Start(watchdog.Config{
//	    SecretPath:   "/xK9mP2qR7sL3vN8w", // long, random, keep secret
//	    PublicKeyPEM: publicKeyPEM,          // from: go run ./cmd/keygen
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer wd.Stop()
//
//	// Apply license gate to your router (works with any net/http-compatible mux):
//	router.Use(wd.Middleware())
//
// # Vendor workflow
//
//  1. go run ./cmd/keygen                      — generate keypair once, keep private key secret
//  2. GET  {SecretPath}/instance               — customer shares their instance_id with you
//  3. go run ./cmd/tokengen -instance <id> ... — you generate a bound license token
//  4. POST {SecretPath}/token {"token":"..."}  — customer activates the license
package watchdog

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Watchdog is the running license enforcement engine.
// Obtain one via Start(). It manages its own goroutines.
type Watchdog struct {
	cfg    Config
	state  *State
	server *heartbeatServer
	pubKey *ecdsa.PublicKey
	stopCh chan struct{}
	logger *log.Logger
}

// Start initializes the watchdog and runs it in background goroutines. Non-blocking.
//
// On first run the service starts in an unlicensed state — the Middleware will block
// all requests until a valid license token is submitted via POST {SecretPath}/token.
func Start(cfg Config) (*Watchdog, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	pubKey, err := ParseECDSAPublicKey(cfg.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("watchdog: invalid public key: %w", err)
	}

	w := &Watchdog{
		cfg:    cfg,
		pubKey: pubKey,
		stopCh: make(chan struct{}),
		logger: log.New(os.Stderr, "[watchdog] ", log.LstdFlags),
	}

	// Default OnKill is set as a method so it can access state file paths for cleanup.
	if w.cfg.OnKill == nil {
		w.cfg.OnKill = w.defaultKill
	}

	state, err := loadOrInitState(cfg)
	if err != nil {
		return nil, fmt.Errorf("watchdog: state init: %w", err)
	}
	w.state = state

	w.server = newHeartbeatServer(w)
	go w.server.run()
	go w.enforcementLoop()

	w.logger.Printf("started | instance=%s | listen=%s | licensed=%v",
		cfg.InstanceID, cfg.ListenAddr, w.IsValid())

	return w, nil
}

// Stop gracefully shuts down the watchdog. Does not trigger the kill sequence.
// Call this in your application's shutdown path.
func (w *Watchdog) Stop() {
	close(w.stopCh)
	w.server.shutdown()
}

// InstanceID returns the machine fingerprint for this deployment.
// Share this with the license issuer to generate a bound token.
func (w *Watchdog) InstanceID() string {
	return w.cfg.InstanceID
}

// IsValid reports whether a license is currently active and not expired.
func (w *Watchdog) IsValid() bool {
	state := w.state.Get()
	if state.ValidUntil.IsZero() {
		return false // never licensed
	}
	return time.Now().Before(state.ValidUntil)
}

// ValidUntil returns the expiry time of the active license.
// Returns a zero time if no license has been activated yet.
func (w *Watchdog) ValidUntil() time.Time {
	return w.state.Get().ValidUntil
}

// Middleware returns a standard Go HTTP middleware that gates requests behind the
// license check. When the license is invalid or expired it calls Config.OnUnauthorized
// (default: 402 JSON) instead of passing the request to the next handler.
//
// Compatible with any net/http-based mux (chi, gorilla/mux, echo, stdlib, etc.):
//
//	router.Use(wd.Middleware())
func (w *Watchdog) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if !w.IsValid() {
				w.cfg.OnUnauthorized(rw, r)
				return
			}
			next.ServeHTTP(rw, r)
		})
	}
}

func (w *Watchdog) enforcementLoop() {
	w.enforceOnce() // immediate check on startup

	ticker := time.NewTicker(w.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.enforceOnce()
		case <-w.stopCh:
			return
		}
	}
}
