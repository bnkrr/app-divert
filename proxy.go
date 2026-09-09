// Package divert intercepts new TCP connections from selected Windows executables.
// It requires Windows x64, administrator privileges and the official WinDivert
// DLL/driver. It does not intercept DNS or UDP.
package divert

import (
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// ErrUnsupportedPlatform means interception is unavailable on this platform.
var ErrUnsupportedPlatform = errors.New("app-divert requires Windows x64")

// ErrAlreadyRun means Run has already been called on this Proxy.
var ErrAlreadyRun = errors.New("app-divert Proxy can only run once")

// TCPHandler handles one intercepted connection and its original destination IP
// and port. Calls are concurrent. The handler must honor cancellation, finish all
// use of conn before returning, and preserve TCP half-close when forwarding.
// Return nil for normal completion or an error to reset the connection.
// The proxy closes conn after return and resets it on shutdown. It waits for all
// handlers before Run returns; a handler ignoring ctx can prevent shutdown.
type TCPHandler func(ctx context.Context, conn *net.TCPConn, target netip.AddrPort) error

// Logger must support concurrent calls. A standard *log.Logger implements it.
type Logger interface {
	Printf(format string, args ...any)
}

// Options configures host integration; these settings are not read from JSON.
type Options struct {
	// Routes binds disjoint application groups to independent TCP handlers.
	// When used, Config.Apps, Config.Targets, Config.SOCKS5 and Handler must be empty.
	Routes []Route
	// DLLDir is the trusted directory containing official WinDivert.dll and
	// WinDivert64.sys. Empty uses the host executable's directory.
	DLLDir string
	// Handler replaces SOCKS5 forwarding. Config.SOCKS5 must be empty when set;
	// ConnectTimeoutSeconds then has no effect on the handler.
	Handler TCPHandler
	// Logger defaults to log.Default(). It must not block indefinitely.
	Logger Logger
}

// Proxy is a single-use interception instance. Create another after stopping.
// Create it with New; the zero value is not usable. Do not copy a Proxy.
// Only one active instance per machine is supported.
type Proxy struct {
	cfg     Config
	opts    Options
	ready   chan struct{}
	started atomic.Bool
}

// New validates configuration and copies Apps and Targets. It does not open sockets or load
// the driver. The caller must not mutate their slices concurrently with New.
func New(cfg Config, opts Options) (*Proxy, error) {
	if len(opts.Routes) > 0 {
		if len(cfg.Apps) > 0 || len(cfg.Targets) > 0 || cfg.SOCKS5 != "" || opts.Handler != nil {
			return nil, errors.New("Routes cannot be combined with Apps, Targets, SOCKS5 or Handler")
		}
		var err error
		cfg.routes, cfg.Apps, cfg.Targets, err = compileRoutes(opts.Routes)
		if err != nil {
			return nil, err
		}
		opts.Routes = nil // All selectors have been copied into the compiled configuration.
	}
	if opts.Handler != nil && cfg.SOCKS5 != "" {
		return nil, errors.New("specify either SOCKS5 or Handler, not both")
	}
	cfg, err := cfg.normalized(opts.Handler != nil || len(cfg.routes) > 0)
	if err != nil {
		return nil, err
	}
	if opts.DLLDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		opts.DLLDir = filepath.Dir(exe)
	}
	opts.DLLDir, err = filepath.Abs(opts.DLLDir)
	if err != nil {
		return nil, err
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.Handler == nil && len(cfg.routes) == 0 {
		opts.Handler = func(ctx context.Context, conn *net.TCPConn, target netip.AddrPort) error {
			upstream, err := dialSOCKS(ctx, cfg.SOCKS5, target, time.Duration(cfg.ConnectTimeoutSeconds)*time.Second)
			if err != nil {
				return err
			}
			return relayTCP(ctx, conn, upstream)
		}
	}
	return &Proxy{cfg: cfg, opts: opts, ready: make(chan struct{})}, nil
}

// Ready closes once both TCP listeners and the driver processing loops are
// started. Also observe Run's result: startup failure does not close Ready, and
// Ready remaining closed does not mean the proxy is still running.
func (p *Proxy) Ready() <-chan struct{} { return p.ready }

// Run blocks until cancellation or a fatal error, then waits for handlers and
// driver cleanup. Normal cancellation returns nil. Startup/runtime errors are
// returned to the host; the library never exits the process or installs signals.
// A canceled context before startup does not open sockets or load the driver.
func (p *Proxy) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("context must not be nil")
	}
	if !p.started.CompareAndSwap(false, true) {
		return ErrAlreadyRun
	}
	if ctx.Err() != nil {
		return nil
	}
	return p.run(ctx)
}

func (p *Proxy) handle(ctx context.Context, conn *net.TCPConn, target netip.AddrPort) error {
	return p.handleRoute(ctx, conn, target, "default")
}

func (p *Proxy) handleRoute(ctx context.Context, conn *net.TCPConn, target netip.AddrPort, route string) error {
	defer conn.Close()
	handler := p.opts.Handler
	if len(p.cfg.routes) > 0 {
		for _, r := range p.cfg.routes {
			if r.name == route {
				handler = r.handler
				break
			}
		}
	}
	if handler == nil {
		resetTCP(conn)
		return errors.New("unknown connection route")
	}
	if err := handler(ctx, conn, target); err != nil {
		resetTCP(conn)
		return err
	}
	return nil
}
