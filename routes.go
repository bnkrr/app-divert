package divert

import (
	"fmt"
	"net/netip"
	"strings"
)

// Route selects applications and destinations for one forwarding handler.
// Names must be unique. Application selectors must not overlap across routes.
// Routes are supplied through Options, not the standalone CLI configuration.
type Route struct {
	Name    string
	Apps    []string
	Targets []TargetRule
	Handler TCPHandler
}

type compiledRoute struct {
	name    string
	apps    Config
	targets targetSet
	handler TCPHandler
}

func appSelector(s string) string { return strings.ToLower(strings.ReplaceAll(s, "/", "\\")) }
func appBase(s string) string     { return s[strings.LastIndexByte(s, '\\')+1:] }

func compileRoutes(routes []Route) ([]compiledRoute, []string, []TargetRule, error) {
	if len(routes) > 32 {
		return nil, nil, nil, fmt.Errorf("at most 32 routes are supported")
	}
	var compiled []compiledRoute
	var apps []string
	var targets []TargetRule
	names := map[string]bool{}
	selectors := map[string]string{}
	for _, r := range routes {
		if strings.TrimSpace(r.Name) == "" || names[r.Name] || r.Handler == nil {
			return nil, nil, nil, fmt.Errorf("routes require unique nonempty names and nonnil handlers")
		}
		names[r.Name] = true
		cfg, err := (Config{Apps: r.Apps, Targets: r.Targets}).normalized(true)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("route %q: %w", r.Name, err)
		}
		for _, app := range cfg.Apps {
			key := appSelector(app)
			for previous, name := range selectors {
				if name != r.Name && (strings.EqualFold(key, previous) || (strings.EqualFold(appBase(key), appBase(previous)) && (!strings.Contains(key, "\\") || !strings.Contains(previous, "\\")))) {
					return nil, nil, nil, fmt.Errorf("app %q overlaps routes %q and %q", app, name, r.Name)
				}
			}
			selectors[key] = r.Name
		}
		apps = append(apps, cfg.Apps...)
		if len(cfg.Targets) == 0 {
			targets = append(targets, TargetRule{})
		} else {
			targets = append(targets, cfg.Targets...)
		}
		compiled = append(compiled, compiledRoute{r.Name, cfg, cfg.targets, r.Handler})
	}
	// Apply the same total filter complexity budget as the single-handler API.
	if _, err := compileTargets(targets); err != nil {
		return nil, nil, nil, err
	}
	return compiled, apps, targets, nil
}

func (c Config) selectRoute(path string, target netip.AddrPort) string {
	if len(c.routes) == 0 {
		if c.matches(path) && c.targets.matches(target) {
			return "default"
		}
		return ""
	}
	for _, r := range c.routes {
		if r.apps.matches(path) && r.targets.matches(target) {
			return r.name
		}
	}
	return ""
}
