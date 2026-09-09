package divert

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// Config selects executables and bounds the local TCP relay. Zero numeric fields
// use defaults (port 34010, connect timeout 10 seconds, 4096 connections).
// Targets optionally restricts original destinations in the kernel before PID lookup.
// SOCKS5 is required unless Options.Handler supplies the forwarding implementation.
type Config struct {
	Apps                  []string     `json:"apps"`
	Targets               []TargetRule `json:"targets,omitempty"`
	targets               targetSet
	routes                []compiledRoute
	SOCKS5                string `json:"socks5"`
	RelayPort             uint16 `json:"relay_port"`
	ConnectTimeoutSeconds int    `json:"connect_timeout_seconds"`
	MaxConnections        int    `json:"max_connections"`
}

// LoadConfig reads a strict standalone CLI JSON configuration, including SOCKS5.
// Embedded hosts can instead construct Config and pass it directly to New.
func LoadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("config must contain one JSON object")
	}
	return c.normalized(false)
}

func (c Config) normalized(customHandler bool) (Config, error) {
	c.Apps = append([]string(nil), c.Apps...)
	c.Targets = append([]TargetRule(nil), c.Targets...)
	for i := range c.Targets {
		c.Targets[i].IPs = append([]string(nil), c.Targets[i].IPs...)
		c.Targets[i].Ports = append([]string(nil), c.Targets[i].Ports...)
	}
	var err error
	c.targets, err = compileTargets(c.Targets)
	if err != nil {
		return c, err
	}
	if c.RelayPort == 0 {
		c.RelayPort = 34010
	}
	if c.ConnectTimeoutSeconds == 0 {
		c.ConnectTimeoutSeconds = 10
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 4096
	}
	if len(c.Apps) == 0 {
		return c, errors.New("apps must not be empty")
	}
	for _, app := range c.Apps {
		if strings.TrimSpace(app) == "" || strings.ContainsAny(app, "*?\x00") {
			return c, errors.New("apps must contain executable names or full paths, without wildcards")
		}
	}
	if !customHandler {
		a, err := netip.ParseAddrPort(c.SOCKS5)
		if err != nil || !a.Addr().IsLoopback() || a.Port() == 0 {
			return c, errors.New("socks5 must be a numeric loopback IP:port")
		}
		if a.Port() == c.RelayPort {
			return c, errors.New("socks5 and relay_port must differ")
		}
	}
	if c.ConnectTimeoutSeconds < 1 || c.ConnectTimeoutSeconds > 120 || c.MaxConnections < 1 || c.MaxConnections > 16000 {
		return c, fmt.Errorf("invalid timeout (1..120) or max_connections (1..16000)")
	}
	return c, nil
}

func (c Config) matches(path string) bool {
	path = strings.ReplaceAll(path, "/", "\\")
	base := path
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		base = path[i+1:]
	}
	for _, app := range c.Apps {
		app = strings.ReplaceAll(app, "/", "\\")
		candidate := base
		if strings.Contains(app, "\\") {
			candidate = path
		}
		if strings.EqualFold(app, candidate) {
			return true
		}
	}
	return false
}
