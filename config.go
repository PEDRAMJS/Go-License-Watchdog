package watchdog

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultCheckInterval = 1 * time.Hour
	defaultListenAddr    = "127.0.0.1:18443"
)

// Config configures the watchdog license enforcement engine.
type Config struct {
	// SecretPath is the URL prefix for watchdog endpoints. Make it long and random.
	// Endpoints:
	//   GET  {SecretPath}/instance  → returns this instance's ID
	//   POST {SecretPath}/token     → submit a signed license or terminate token
	SecretPath string

	// ListenAddr is the watchdog HTTP server address.
	// Default: "127.0.0.1:18443"
	ListenAddr string

	// PublicKeyPEM is your ECDSA P-256 public key in PEM format.
	// Generate with: go run ./cmd/keygen
	// Bake into the binary with go:embed or ldflags. Never the private key.
	PublicKeyPEM string

	// InstanceID uniquely identifies this deployment.
	// Auto-derived from machine fingerprint if empty.
	InstanceID string

	// CheckInterval is how often the enforcement loop runs.
	// Default: 1 hour
	CheckInterval time.Duration

	// StateFile is the primary encrypted state file path.
	// Two backup locations are maintained automatically.
	// Default: $HOME/.cache/.wdstate
	StateFile string

	// AllowedCIDRs optionally whitelists source IPs for token submission.
	// nil = accept from anywhere.
	AllowedCIDRs []string

	// OnExpired is called each enforcement tick when the license is expired.
	// Default: prints a notice to stderr.
	OnExpired func()

	// OnKill is called immediately when a terminate token is received.
	// Default: removes state files, overwrites and deletes the binary, then exits.
	// Override to run cleanup before the process dies.
	// Must not return; call os.Exit if your implementation doesn't already exit.
	OnKill func()

	// OnUnauthorized is the HTTP handler invoked by Middleware when the license
	// is invalid or expired. Default: 402 JSON response.
	OnUnauthorized func(http.ResponseWriter, *http.Request)
}

func (c *Config) setDefaults() {
	if c.CheckInterval == 0 {
		c.CheckInterval = defaultCheckInterval
	}
	if c.ListenAddr == "" {
		c.ListenAddr = defaultListenAddr
	}
	if c.InstanceID == "" {
		c.InstanceID = generateFingerprint()
	}
	if c.StateFile == "" {
		home, _ := os.UserHomeDir()
		c.StateFile = filepath.Join(home, ".cache", ".wdstate")
	}
	if c.OnExpired == nil {
		c.OnExpired = defaultOnExpired
	}
	if c.OnUnauthorized == nil {
		c.OnUnauthorized = defaultOnUnauthorized
	}
	// OnKill default is set in Start() after the Watchdog is created,
	// so the default implementation can access state file paths for cleanup.
}

func (c *Config) validate() error {
	if c.SecretPath == "" {
		return errors.New("watchdog: SecretPath required")
	}
	if len(c.SecretPath) < 8 {
		return errors.New("watchdog: SecretPath must be at least 8 chars — use something random")
	}
	if c.PublicKeyPEM == "" {
		return errors.New("watchdog: PublicKeyPEM required")
	}
	return nil
}

func defaultOnExpired() {
	fmt.Fprintf(os.Stderr,
		"\n╔══════════════════════════════════════════════════════╗\n"+
			"║              LICENSE EXPIRED                         ║\n"+
			"╠══════════════════════════════════════════════════════╣\n"+
			"║  This software's license has expired.                ║\n"+
			"║  Contact the vendor to obtain a new license token.   ║\n"+
			"╚══════════════════════════════════════════════════════╝\n\n")
}

func defaultOnUnauthorized(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	w.Write([]byte(`{"error":"license expired or not activated"}`))
}
