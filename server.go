package watchdog

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type heartbeatServer struct {
	w   *Watchdog
	srv *http.Server

	// Lightweight rate limit — prevents log spam from accidental hammering.
	// Not a security gate: signed tokens cannot be brute-forced.
	rateMu      sync.Mutex
	lastAttempt time.Time
}

func newHeartbeatServer(w *Watchdog) *heartbeatServer {
	hs := &heartbeatServer{w: w}

	mux := http.NewServeMux()
	mux.HandleFunc(w.cfg.SecretPath+"/instance", hs.handleInstance)
	mux.HandleFunc(w.cfg.SecretPath+"/token", hs.handleToken)
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		http.NotFound(rw, r)
	})

	hs.srv = &http.Server{
		Addr:         w.cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return hs
}

func (hs *heartbeatServer) run() {
	if err := hs.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		hs.w.logger.Printf("server error: %v", err)
	}
}

func (hs *heartbeatServer) shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.srv.Shutdown(ctx)
}

// GET {SecretPath}/instance
//
// Returns this instance's ID and current license status.
// The customer shares the instance_id with the vendor so a bound token can be issued.
//
// Response: {"instance_id":"...","valid_until":"RFC3339|not activated"}
func (hs *heartbeatServer) handleInstance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	if !hs.checkCIDR(r) {
		http.Error(w, "403", http.StatusForbidden)
		return
	}

	state := hs.w.state.Get()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"instance_id": state.InstanceID,
		"valid_until": formatValidUntil(state.ValidUntil),
	})
}

// POST {SecretPath}/token
//
// Accepts a signed license or terminate JWT.
// Body: {"token":"<es256_jwt>"}
//
// License response:   {"status":"ok","valid_until":"RFC3339"}
// Terminate response: {"status":"terminating"} — process exits after response is flushed
// Failure response:   {"error":"unauthorized"} — always vague, never reveals which check failed
func (hs *heartbeatServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	if !hs.checkCIDR(r) {
		http.Error(w, "403", http.StatusForbidden)
		return
	}

	hs.rateMu.Lock()
	if time.Since(hs.lastAttempt) < 2*time.Second {
		hs.rateMu.Unlock()
		w.Header().Set("Retry-After", "2")
		jsonError(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	hs.lastAttempt = time.Now()
	hs.rateMu.Unlock()

	body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Token == "" {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}

	state := hs.w.state.Get()

	claims, err := verifyLicenseToken(req.Token, hs.w.pubKey, state.InstanceID)
	if err != nil {
		hs.w.logger.Printf("token rejected from %s: %v", r.RemoteAddr, err)
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Replay check: each JTI may only be accepted once.
	if claims.JTI == state.LastAcceptedJTI {
		hs.w.logger.Printf("token replay detected from %s (jti=%s)", r.RemoteAddr, claims.JTI)
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch claims.Action {
	case actionLicense:
		hs.w.state.UpdateLicense(claims)
		hs.w.logger.Printf("license accepted from %s | valid until %s | customer=%s",
			r.RemoteAddr, claims.ValidUntil().Format(time.RFC3339), claims.CustomerID)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "ok",
			"valid_until": claims.ValidUntil().Format(time.RFC3339),
		})

	case actionTerminate:
		hs.w.logger.Printf("terminate token accepted from %s — initiating self-destruct", r.RemoteAddr)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "terminating"})

		// Flush the response before exiting so the caller receives confirmation.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		go func() {
			time.Sleep(200 * time.Millisecond)
			hs.w.cfg.OnKill()
			os.Exit(1) // safety net if OnKill returns without exiting
		}()
	}
}

func (hs *heartbeatServer) checkCIDR(r *http.Request) bool {
	if len(hs.w.cfg.AllowedCIDRs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range hs.w.cfg.AllowedCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func formatValidUntil(t time.Time) string {
	if t.IsZero() {
		return "not activated"
	}
	return t.Format(time.RFC3339)
}
