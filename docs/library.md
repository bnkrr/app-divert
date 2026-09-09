# Go library guide

The module is `github.com/bnkrr/app-divert`; its package name is `divert`.
The root package contains the core implementation. Driver access, packet
parsing, address rewriting, and process table types are internal.
`cmd/app-divert` handles configuration, command-line flags, signals, and
error reporting.

Once you have access to the module, add it to your host project with Go modules:

```sh
go get github.com/bnkrr/app-divert@latest
```

No adjacent source directory or local `replace` directive is required.

## Lifecycle

- `New(Config, Options)` validates configuration, fills defaults, and deeply copies
  `Apps` and `Targets`. It does not load the driver or open listeners.
- `Run(ctx)` blocks until shutdown and returns startup or runtime errors to
  the host. Normal cancellation returns nil.
- `Ready()` returns a channel that closes after both TCP listeners and the
  driver processing loop have started. Startup failure leaves it open, so
  always observe the result of `Run` while waiting for readiness.
- Cancel the context and wait for `Run` to return to close diverted
  connections, wait for handlers, and release driver resources. Existing
  connections cannot switch seamlessly to a direct route. New connections
  after shutdown follow their original network path.

Each instance can run once; a second `Run` returns `ErrAlreadyRun`. Only one
active instance per machine is supported. Outside Windows x64, `Run` returns
`ErrUnsupportedPlatform`; construction, configuration validation, and a
`Run` with an already-canceled context can be used in cross-platform tests.
Create a new instance to restart diversion.

This function shows how a host waits for readiness and shutdown. The host is
responsible for canceling the supplied context:

```go
func runDivert(ctx context.Context, logger *log.Logger) error {
    proxy, err := divert.New(divert.Config{
        Apps: []string{`C:\Games\WoW\Wow.exe`},
        SOCKS5: "127.0.0.1:1080",
        Targets: []divert.TargetRule{{Ports: []string{"3724", "8085"}}},
    }, divert.Options{Logger: logger})
    if err != nil {
        return err
    }
    done := make(chan error, 1)
    go func() { done <- proxy.Run(ctx) }()
    select {
    case err := <-done:
        return err
    case <-proxy.Ready():
        logger.Print("TCP interception started")
    }
    return <-done
}
```

`Ready` is a one-time startup notification, not an ongoing health check.
Runtime errors can still occur after readiness. The library does not install
signal handlers, exit the process, change system DNS, or elevate privileges.

`Options.DLLDir` defaults to the host executable's directory. If overridden,
point it only to a trusted directory containing the WinDivert DLL/SYS.
`Options.Logger` defaults to `log.Default()`; a custom implementation must
support concurrent calls and must not block indefinitely.

## Forwarding

By default, `Config.SOCKS5` specifies a numeric loopback IP:port for IPv4/IPv6
NOAUTH CONNECT. Application destinations are always resolved IP addresses;
the library does not recover or re-resolve domain names.

The host can instead provide a forwarding function:

```go
proxy, err := divert.New(divert.Config{
    Apps: []string{"Wow.exe"},
}, divert.Options{
    Handler: func(ctx context.Context, conn *net.TCPConn, target netip.AddrPort) error {
        return forwardTCP(ctx, conn, target) // Complete forwarding implementation supplied by the host.
    },
})
```

When `Handler` is set, `SOCKS5` must be empty.
`ConnectTimeoutSeconds` applies only to the default SOCKS5 dial and handshake.
A custom handler must enforce its own upstream connection establishment
timeout. That timeout should not limit the lifetime of the entire game
connection.

Handler contract:

- The handler is called once per matched connection, with concurrent calls
  across connections. `target` is the original remote IPv4 or IPv6 address and
  port. `conn` is the locally reflected connection; do not substitute
  `conn.RemoteAddr()` for `target`.
- Finish all use of `conn` before returning. Do not hand it to a background
  goroutine and return immediately.
- Return nil on normal completion; the library closes the connection after
  return. Return an error on failure; the library resets the connection and
  logs the error.
- Preserve TCP half-close during bidirectional forwarding: EOF from one side
  should close only the other side's write direction while remaining responses
  continue to flow. Return upstream failures as errors; do not silently fall
  back to a direct connection or treat RST as normal EOF.
- On shutdown, the context is canceled and the library resets diverted TCP
  sockets. The handler must still cancel its own upstream connection attempts,
  tunnel waits, and background work. `Run` waits for handlers to finish;
  an uncooperative handler will block shutdown.
- Ordinary TCP connections created by a custom handler belong to the host
  process. The host process is excluded from matching to prevent loops.

Implement `forwardTCP` to connect your forwarding engine without a local
SOCKS5 listener or handshake. Verify half-close, error handling, and
cancellation in your custom implementation.

## Limits

Only new TCP connections are diverted. `Config.Targets` selects eligible
original destination IPs/CIDRs and ports before process matching; see the
[README](../README.md#destination-filters) for rule semantics and limits.
Omitting it leaves destinations unrestricted. Relay return packets are also
captured to maintain existing mappings.

Owner lookup failure, overload, or timeout allows a new connection to continue
directly. The library records this decision before releasing the SYN; late
lookup results cannot change it. Existing proxied connections retain their
mapping and never fall back to direct midstream. Direct decisions expire after
ten minutes idle; new initial sequence numbers distinguish tuple reuse.
If the bounded decision cache fills, all new connections stay direct until a
new proxy instance is started. This library provides best-effort forwarding,
not mandatory-proxy enforcement.

Packets outside the configured target scope bypass this WinDivert handle in
the kernel, except for the relay return path. In-scope direct packets still
pass through user-mode capture/injection. Process scheduling and driver queues
can affect them under load, even with the direct fast path.

The library does not provide statistics subscriptions, dynamic rule updates,
or hot switching. It does not intercept DNS or UDP.

## Multiple application routes

Use one proxy with `Options.Routes` to bind independent application groups to
handlers. Leave `Config.Apps`, `Config.Targets`, `Config.SOCKS5` and
`Options.Handler` empty in this mode. Existing single-handler integrations and
standalone CLI configurations continue to work unchanged.

```go
p, err := divert.New(divert.Config{}, divert.Options{
    Routes: []divert.Route{
        {
            Name: "game-a",
            Apps: []string{`C:\Games\A\Game.exe`},
            Targets: []divert.TargetRule{{Ports: []string{"3724"}}},
            Handler: forwardToUpstreamA,
        },
        {
            Name: "game-b",
            Apps: []string{`C:\Games\B\Game.exe`},
            Targets: []divert.TargetRule{{Ports: []string{"8085"}}},
            Handler: forwardToUpstreamB,
        },
    },
})
```

The two forwarding functions have the existing `TCPHandler` signature and the
same cancellation, half-close and connection ownership contract. They can close
over different upstream settings. The library remains unaware of KCP, PSKs or
any other upstream protocol. Route names must be unique and handlers nonnil.

Executable selectors cannot overlap across routes: names are case-insensitive,
slash direction is normalized, and a basename conflicts with any full-path
selector for that basename. Different full paths to identically named binaries
are allowed. Routes do not inherit or automatically include child processes.

The kernel prefilter uses the union of target rules. After ownership lookup,
the application's own targets are checked before modifying the SYN. Traffic
excluded by that application's targets stays direct even if another route
includes that destination. The selected route is retained with the connection;
PID lookup is not repeated later to choose its handler. Process-handle caching
retains the executable path, not a destination-specific routing decision.

Application/target slices are copied at construction. At most 32 routes,
32 aggregate target rules and 64 aggregate IP/port selectors are supported.
An unrestricted route consumes one wildcard target rule. All routes share the
relay listeners, connection limit and fail-open decision cache of one instance.
