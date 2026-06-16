package watchdog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// watchdogState is the persisted enforcement state.
// Encrypted on disk with AES-256-GCM; key is derived from instance ID + public key,
// making the state file non-portable between machines or vendor key rotations.
type watchdogState struct {
	InstanceID        string    `json:"iid"`
	ValidUntil        time.Time `json:"vu"`   // zero = unlicensed
	LastAcceptedJTI   string    `json:"jti"`  // JTI of the last accepted token (replay prevention)
	LastSeenWallClock time.Time `json:"lswc"` // wall clock at last enforcement tick (rewind detection)
	Revision          int64     `json:"rev"`  // monotonically increasing; prevents state rollback attacks
}

// State manages encrypted persistent state with:
//   - AES-256-GCM encryption (key is machine- and vendor-bound)
//   - 3 independent storage locations (primary + 2 hidden backups)
//   - Anti-rollback: always loads the copy with the highest Revision
//   - Thread-safe via RWMutex
type State struct {
	mu     sync.RWMutex
	data   watchdogState
	encKey []byte
	paths  []string
}

func loadOrInitState(cfg Config) (*State, error) {
	key := deriveStateKey(cfg)
	paths := statePaths(cfg)

	s := &State{
		encKey: key,
		paths:  paths,
	}

	// Load from all locations; take the one with the highest Revision.
	// Prevents an attacker from deleting/replacing state files to reset the countdown.
	var best *watchdogState
	for _, p := range paths {
		data, err := s.loadFrom(p)
		if err != nil {
			continue
		}
		if data.InstanceID != cfg.InstanceID {
			continue // reject state files from a different instance
		}
		if best == nil || data.Revision > best.Revision {
			best = data
		}
	}

	if best == nil {
		// Fresh install — service starts unlicensed until a token is submitted.
		s.data = watchdogState{
			InstanceID:        cfg.InstanceID,
			LastSeenWallClock: time.Now(),
			Revision:          1,
		}
	} else {
		s.data = *best
	}

	s.saveAll()
	return s, nil
}

// Get returns a snapshot of the current state. Safe for concurrent use.
func (s *State) Get() watchdogState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

// UpdateLicense records an accepted license token.
func (s *State) UpdateLicense(claims *LicenseClaims) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ValidUntil = claims.ValidUntil()
	s.data.LastAcceptedJTI = claims.JTI
	s.data.LastSeenWallClock = time.Now()
	s.data.Revision++
	s.saveAll()
}

// UpdateWallClock advances the wall clock anchor used for rewind detection.
func (s *State) UpdateWallClock(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.LastSeenWallClock = now
	s.data.Revision++
	s.saveAll()
}

// InvalidateLicense sets ValidUntil to zero, forcing the middleware to block all requests.
func (s *State) InvalidateLicense() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data.ValidUntil = time.Time{}
	s.data.Revision++
	s.saveAll()
}

func (s *State) saveAll() {
	for _, p := range s.paths {
		_ = s.saveTo(p)
	}
}

func (s *State) saveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	plaintext, err := json.Marshal(s.data)
	if err != nil {
		return err
	}
	encrypted, err := encryptAESGCM(s.encKey, plaintext)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0600)
}

func (s *State) loadFrom(path string) (*watchdogState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptAESGCM(s.encKey, raw)
	if err != nil {
		return nil, err
	}
	var data watchdogState
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// deriveStateKey derives the AES-256 key from the instance ID and the embedded public key.
// The state file is unreadable on a different machine (different fingerprint) or
// after a vendor key rotation.
func deriveStateKey(cfg Config) []byte {
	h := sha256.New()
	h.Write([]byte("watchdog-state-v2:"))
	h.Write([]byte(cfg.InstanceID))
	h.Write([]byte(":"))
	h.Write([]byte(cfg.PublicKeyPEM))
	return h.Sum(nil) // 32 bytes → AES-256
}

// statePaths returns 3 storage locations for the state file.
// Backup paths are hidden and named by a hash of the instance ID.
func statePaths(cfg Config) []string {
	home, _ := os.UserHomeDir()
	h := sha256.Sum256([]byte(cfg.InstanceID))
	hiddenName := fmt.Sprintf(".%x", h[:8])

	return []string{
		cfg.StateFile,
		filepath.Join(home, ".local", "share", hiddenName),
		filepath.Join(os.TempDir(), hiddenName),
	}
}

// --- AES-256-GCM helpers ---

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}
