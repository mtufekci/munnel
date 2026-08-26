package client

import (
	"fmt"
	"strings"
)

// Config holds client settings.
type Config struct {
	LocalPort   int    // local service port, e.g. 3000
	LocalHost   string // default "127.0.0.1"
	ServerAddr  string // control server "host:port", e.g. "tunnels.example.com:7001"
	Subdomain   string // requested subdomain; "" = server picks
	Token       string // auth token for protected servers
	Inspect     bool   // run the web inspector
	InspectAddr string // inspector listen addr, default ":4040"
	MaxBody     int64  // per-request body cap in bytes (matches server side)
}

// Validate checks the config and fills defaults.
func (c *Config) Validate() error {
	if c.LocalPort <= 0 || c.LocalPort > 65535 {
		return fmt.Errorf("invalid local port %d", c.LocalPort)
	}
	if c.LocalHost == "" {
		c.LocalHost = "127.0.0.1"
	}
	if c.ServerAddr == "" {
		return fmt.Errorf("no server address (use --server host:7001)")
	}
	if !strings.Contains(c.ServerAddr, ":") {
		c.ServerAddr += ":7001"
	}
	if c.InspectAddr == "" {
		c.InspectAddr = ":4040"
	}
	if c.MaxBody <= 0 {
		c.MaxBody = 32 << 20
	}
	return nil
}
