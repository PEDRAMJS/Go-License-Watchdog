package watchdog

import (
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

// generateFingerprint creates a stable machine-specific identifier by hashing
// several hardware/OS characteristics together. Single-factor spoofing
// (e.g. changing just the hostname) won't be enough.
func generateFingerprint() string {
	parts := []string{
		getHostname(),
		getMACAddresses(),
		runtime.GOOS,
		runtime.GOARCH,
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars — compact but unique enough
}

func getHostname() string {
	h, _ := os.Hostname()
	return h
}

func getMACAddresses() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	var macs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback
		}
		if len(iface.HardwareAddr) > 0 {
			macs = append(macs, iface.HardwareAddr.String())
		}
	}
	sort.Strings(macs) // deterministic regardless of interface ordering
	return strings.Join(macs, ",")
}
