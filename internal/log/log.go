package log

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"
)

// Logger provides simple logging capabilities that can be enabled or disabled.
type Logger struct {
	enabled bool
	output  io.Writer
	mu      sync.Mutex
}

var (
	globalLogger = &Logger{
		enabled: false,
		output:  os.Stderr,
	}
)

// SetEnabled controls whether logging is enabled globally.
func SetEnabled(enabled bool) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	globalLogger.enabled = enabled
}

// SetOutput sets the output writer for the global logger.
func SetOutput(w io.Writer) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	if w == nil {
		w = io.Discard
	}
	globalLogger.output = w
}

// Printf writes a formatted log message if logging is enabled.
func Printf(format string, args ...interface{}) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	if globalLogger.enabled {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(globalLogger.output, "[%s] %s\n", timestamp, fmt.Sprintf(format, args...))
	}
}

// Println writes a log message if logging is enabled.
func Println(args ...interface{}) {
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()
	if globalLogger.enabled {
		timestamp := time.Now().Format("2006-01-02 15:04:05.000")
		fmt.Fprintf(globalLogger.output, "[%s] %s\n", timestamp, fmt.Sprint(args...))
	}
}

// SanitizeURL removes credentials from a URL string for safe logging.
// If the URL cannot be parsed, it returns "[invalid URL]".
func SanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	// Try to parse as a URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[invalid URL]"
	}

	// If there's user info, redact it
	if u.User != nil {
		u.User = url.User("[redacted]")
	}

	return u.String()
}
