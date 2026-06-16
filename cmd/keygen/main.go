// keygen generates the ECDSA keypair needed by the watchdog package.
//
// Run once and store the outputs safely:
//
//	go run ./cmd/keygen
//
// Outputs:
//
//	watchdog_private.pem  → used by tokengen to sign license tokens  [KEEP SECRET]
//	watchdog_public.pem   → embed in your binary (go:embed or ldflags) [safe to commit]
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	fmt.Println("╔═══════════════════════════════════╗")
	fmt.Println("║     Watchdog Key Generator        ║")
	fmt.Println("╚═══════════════════════════════════╝")
	fmt.Println()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("generate key: %v", err)
	}

	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		fatal("marshal private key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		fatal("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	mustWrite("watchdog_private.pem", privPEM, 0600)
	mustWrite("watchdog_public.pem", pubPEM, 0644)

	fmt.Println("Generated files:")
	fmt.Println("  watchdog_private.pem  ← tokengen signs license tokens with this  [KEEP SECRET]")
	fmt.Println("  watchdog_public.pem   ← embed in your binary                     [safe to commit]")
	fmt.Println()
	fmt.Println("Public Key PEM (put in Config.PublicKeyPEM):")
	fmt.Print(string(pubPEM))
	fmt.Println()
	fmt.Println("⚠  Never commit watchdog_private.pem.")
	fmt.Println("⚠  Store it in a password manager or secrets vault.")
}

func mustWrite(path string, data []byte, mode os.FileMode) {
	if err := os.WriteFile(path, data, mode); err != nil {
		fatal("write %s: %v", path, err)
	}
	fmt.Printf("  ✓ %s\n", path)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
