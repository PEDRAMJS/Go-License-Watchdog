package watchdog

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	actionLicense   = "license"
	actionRevoke    = "revoke"
	actionTerminate = "terminate"
)

// LicenseClaims are the JWT payload claims in a valid license, revoke, or terminate token.
type LicenseClaims struct {
	JTI        string `json:"jti"`           // unique token ID — replay prevention
	Issuer     string `json:"iss,omitempty"`
	NotBefore  int64  `json:"nbf"`           // valid from (Unix timestamp)
	ExpiresAt  int64  `json:"exp"`           // valid until (Unix timestamp)
	Action     string `json:"act"`           // "license", "revoke", or "terminate"
	InstanceID string `json:"iid"`           // bound to this specific deployment
	CustomerID string `json:"cid,omitempty"` // vendor-defined customer reference
}

// ValidUntil returns the token's expiry as a time.Time.
func (c *LicenseClaims) ValidUntil() time.Time {
	return time.Unix(c.ExpiresAt, 0)
}

// verifyLicenseToken parses and fully validates a signed license JWT.
// All four checks must pass: ES256 signature, time bounds, instance binding, action validity.
func verifyLicenseToken(tokenStr string, pubKey *ecdsa.PublicKey, expectedInstanceID string) (*LicenseClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed jwt: expected 3 dot-separated parts")
	}

	// --- Check 1: ES256 signature ---
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "ES256" {
		return nil, errors.New("unsupported algorithm (expected ES256)")
	}

	message := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(message))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature decode: %w", err)
	}
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("invalid ES256 signature length: %d (expected 64)", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return nil, errors.New("signature verification failed")
	}

	// --- Decode payload ---
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("payload parse: %w", err)
	}

	// --- Check 2: Time bounds ---
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}
	if claims.NotBefore > 0 && now < claims.NotBefore-300 { // 5-min clock skew tolerance
		return nil, errors.New("token not yet valid (clock skew?)")
	}

	// --- Check 3: Action validity ---
	if claims.Action != actionLicense && claims.Action != actionRevoke && claims.Action != actionTerminate {
		return nil, fmt.Errorf("unknown action %q", claims.Action)
	}

	// --- Check 4: Instance binding ---
	if claims.JTI == "" {
		return nil, errors.New("missing jti claim")
	}
	if !strings.EqualFold(claims.InstanceID, expectedInstanceID) {
		return nil, fmt.Errorf("instance_id mismatch: token bound to %q, this instance is %q",
			claims.InstanceID, expectedInstanceID)
	}

	return &claims, nil
}

// ParseECDSAPublicKey parses a PEM-encoded ECDSA P-256 public key (PKIX format).
func ParseECDSAPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}
	ecKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not ECDSA")
	}
	return ecKey, nil
}
