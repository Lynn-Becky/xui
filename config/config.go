package config

import (
	_ "embed"
	"fmt"
	"os"
	"strings"
)

//go:embed version
var version string

//go:embed name
var name string

type LogLevel string

const (
	Debug LogLevel = "debug"
	Info  LogLevel = "info"
	Warn  LogLevel = "warn"
	Error LogLevel = "error"
)

func GetVersion() string {
	return strings.TrimSpace(version)
}

func GetName() string {
	return strings.TrimSpace(name)
}

func GetLogLevel() LogLevel {
	if IsDebug() {
		return Debug
	}
	logLevel := os.Getenv("XUI_LOG_LEVEL")
	if logLevel == "" {
		return Info
	}
	return LogLevel(logLevel)
}

func IsDebug() bool {
	return os.Getenv("XUI_DEBUG") == "true"
}

func GetDBPath() string {
	return fmt.Sprintf("/etc/%s/%s.db", GetName(), GetName())
}

// GetTrustedProxies returns the CIDRs whose X-Forwarded-For header the panel is
// willing to believe, read from XUI_TRUSTED_PROXIES as a comma-separated list.
//
// The default is to trust none. Honouring X-Forwarded-For from any peer lets a
// client pick its own apparent source address, which forges the login audit log
// and defeats per-IP login throttling. Operators running the panel behind a
// reverse proxy should set this to the proxy's address.
func GetTrustedProxies() []string {
	raw := os.Getenv("XUI_TRUSTED_PROXIES")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	proxies := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			proxies = append(proxies, part)
		}
	}
	if len(proxies) == 0 {
		return nil
	}
	return proxies
}
