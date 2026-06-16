// tokengen generates a signed watchdog license or terminate token.
//
// Usage:
//
//	go run ./cmd/tokengen \
//	    -key      watchdog_private.pem \
//	    -instance <instance_id>         \
//	    -days     7                     \
//	    [-customer acme-corp]           \
//	    [-action  license]
//
// The instance_id is obtained from the running binary:
//
//	GET {SecretPath}/instance
//
// To generate a terminate token (triggers immediate self-destruct on the target):
//
//	go run ./cmd/tokengen -key watchdog_private.pem -instance <id> -action terminate
//
// The token is printed to stdout. Submit it via:
//
//	POST {SecretPath}/token
//	{"token": "<output>"}
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

func main() {
	keyFile    := flag.String("key", "watchdog_private.pem", "Path to EC private key PEM")
	instanceID := flag.String("instance", "", "Instance ID to bind this token to (required)")
	days       := flag.Int("days", 7, "License duration in days (1–7 for license action)")
	customer   := flag.String("customer", "", "Customer identifier (optional, for your records)")
	action     := flag.String("action", "license", "Token action: license or terminate")
	flag.Parse()

	if *instanceID == "" {
		die("-instance is required (get it from GET {SecretPath}/instance)")
	}
	if *action != "license" && *action != "terminate" {
		die("-action must be 'license' or 'terminate'")
	}
	if *action == "license" && (*days < 1 || *days > 7) {
		die("-days must be between 1 and 7")
	}

	privKey, err := loadPrivateKey(*keyFile)
	if err != nil {
		die("load private key: %v", err)
	}

	jti, err := randomHex(16)
	if err != nil {
		die("generate jti: %v", err)
	}

	now := time.Now()
	var exp time.Time
	if *action == "terminate" {
		exp = now.Add(1 * time.Hour) // terminate tokens are short-lived
	} else {
		exp = now.Add(time.Duration(*days) * 24 * time.Hour)
	}

	claims := map[string]interface{}{
		"jti": jti,
		"iss": "watchdog-vendor",
		"nbf": now.Unix(),
		"exp": exp.Unix(),
		"act": *action,
		"iid": *instanceID,
	}
	if *customer != "" {
		claims["cid"] = *customer
	}

	token, err := buildJWT(privKey, claims)
	if err != nil {
		die("build jwt: %v", err)
	}

	fmt.Println(token)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Action    : %s\n", *action)
	fmt.Fprintf(os.Stderr, "Instance  : %s\n", *instanceID)
	if *action == "license" {
		fmt.Fprintf(os.Stderr, "Valid until: %s\n", exp.Format(time.RFC3339))
	}
	fmt.Fprintf(os.Stderr, "JTI       : %s\n", jti)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Submit via:")
	fmt.Fprintln(os.Stderr, `  POST {SecretPath}/token`)
	fmt.Fprintf(os.Stderr, "  {\"token\": \"%s...\"}\n", token[:32])
}

func buildJWT(privKey *ecdsa.PrivateKey, claims map[string]interface{}) (string, error) {
	header := map[string]string{"alg": "ES256", "typ": "JWT"}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	message := headerB64 + "." + claimsB64

	hash := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("ecdsa sign: %w", err)
	}

	// ES256 signature: r || s, each zero-padded to exactly 32 bytes
	sig := make([]byte, 64)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[32-len(rb):32], rb)
	copy(sig[64-len(sb):64], sb)

	return message + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

// keep math/big referenced for ES256 signature arithmetic awareness
var _ = new(big.Int)

// keep strings referenced
var _ = strings.EqualFold

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
