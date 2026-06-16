package watchdog

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// clockRewindTolerance is the maximum backwards clock movement that is tolerated
// without invalidating the license. Covers NTP micro-corrections and measurement noise.
const clockRewindTolerance = 5 * time.Second

// enforceOnce is called every CheckInterval.
func (w *Watchdog) enforceOnce() {
	now := time.Now()
	state := w.state.Get()

	// Clock rewind detection: if the wall clock moved backwards beyond the tolerance
	// window, the license is invalidated and a fresh token must be submitted.
	// Uses time.Now() wall component, which is manipulable by settimeofday — that is
	// exactly the attack we want to detect. The monotonic component (used by time.Since)
	// ensures the enforcement ticker itself fires at real-time intervals regardless.
	if !state.LastSeenWallClock.IsZero() &&
		now.Before(state.LastSeenWallClock.Add(-clockRewindTolerance)) {
		w.logger.Printf("WARN: clock rewind detected (now=%s last_seen=%s) — invalidating license",
			now.Format(time.RFC3339), state.LastSeenWallClock.Format(time.RFC3339))
		w.state.InvalidateLicense()
		w.cfg.OnExpired()
		return
	}

	w.state.UpdateWallClock(now)

	// License expiry check — only fires if the service was previously licensed.
	if !state.ValidUntil.IsZero() && now.After(state.ValidUntil) {
		w.logger.Printf("INFO: license expired at %s", state.ValidUntil.Format(time.RFC3339))
		w.cfg.OnExpired()
	}
}

// defaultKill is the default OnKill implementation: removes watchdog state files,
// then destroys the binary. Only the binary and watchdog's own operational files
// are touched — user data is never affected.
func (w *Watchdog) defaultKill() {
	for _, p := range w.state.paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			w.logger.Printf("kill: remove state file %s: %v", p, err)
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Printf("[watchdog] kill: could not resolve executable: %v — exiting anyway", err)
		os.Exit(1)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}

	log.Printf("[watchdog] self-destructing: %s", exePath)

	switch runtime.GOOS {
	case "windows":
		selfDestructWindows(exePath)
	default:
		selfDestructUnix(exePath)
	}
}

// selfDestructUnix overwrites the binary with zeros before unlinking it.
// On Linux/macOS you can write to a running executable's file — the OS keeps
// the inode alive until the process exits, but the directory entry is removed
// immediately and the on-disk data is zeroed, making recovery much harder.
func selfDestructUnix(exePath string) {
	if f, err := os.OpenFile(exePath, os.O_WRONLY, 0); err == nil {
		info, _ := f.Stat()
		if info != nil {
			size := info.Size()
			if size > 1<<20 {
				size = 1 << 20 // cap at 1 MB of zeros — good enough deterrent
			}
			f.Write(make([]byte, int(size)))
		}
		f.Close()
	}
	if err := os.Remove(exePath); err != nil {
		log.Printf("[watchdog] kill: remove binary failed: %v", err)
	}
	os.Exit(1)
}

// selfDestructWindows schedules binary deletion via a detached cmd.exe process,
// then exits immediately. Windows cannot delete or overwrite a running exe directly.
func selfDestructWindows(exePath string) {
	// "ping -n 2" = ~1 second delay, giving our process time to exit first.
	script := fmt.Sprintf(`ping -n 2 127.0.0.1 > nul & del /F /Q "%s"`, exePath)
	cmd := exec.Command("cmd", "/C", script)
	cmd.Start() //nolint:errcheck — fire and forget
	os.Exit(1)
}
