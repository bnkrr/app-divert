# app-divert

Per-application TCP diversion for Windows x64: official WinDivert → local TCP
relay → SOCKS5. The root package is an embeddable Go library; `cmd/app-divert`
is a thin CLI for configuration and shutdown handling.

Use any local SOCKS5 service that supports NOAUTH CONNECT, or supply a custom
forwarding callback when embedding the library. Supports IPv4 and IPv6 TCP
without parsing application protocols or modifying the target application.
DNS and UDP are outside its scope.

## Embed in a Go application

Import `github.com/bnkrr/app-divert`; the package name is `divert`. The library
compiles into the host executable. It does not produce a separate C ABI `.lib`
or DLL. Runtime operation requires the official WinDivert DLL/SYS and
administrator privileges.

See the [Go library guide](docs/library.md) for the API, startup and shutdown
examples, and the custom TCP handler contract. The CLI uses local SOCKS5;
embedded applications can provide their own forwarding implementation.

```go
proxy, err := divert.New(divert.Config{
    Apps:   []string{"Wow.exe", "Wow-64.exe"},
    SOCKS5: "127.0.0.1:1080",
}, divert.Options{})
// Check err, then call proxy.Run(ctx).
// To shut down, cancel ctx and wait for Run to return.
```

To connect another forwarding engine, set `Options.Handler` and omit `SOCKS5`.
The callback receives a `context.Context`, a `*net.TCPConn`, and the original
destination as a `netip.AddrPort`. It receives no domain name and does not
intercept DNS.

## Run the portable client

The runtime files are listed below. Start a local SOCKS5 service before running
the client. Keep the license files and third-party notices when distributing
the package.

```text
app-divert.exe          Per-application TCP interception; requires administrator privileges
WinDivert.dll           Official 2.2.2 x64 DLL
WinDivert64.sys         Official signed driver; keep unmodified
config.json            Target applications and local SOCKS5 address
start-client.cmd        Validates configuration and requests elevation
```

Copy `config.example.json` to `config.json` if needed, then set the executable
names or full paths and the local SOCKS5 address. Adjust all example paths,
application names, and addresses for your environment. In the source tree,
the example configuration is under `configs/`.

1. Start your local SOCKS5 service.
2. Double-click `start-client.cmd`, or run
   `app-divert.exe -config config.json` in an administrator terminal.
3. Wait for app-divert to report ready, then start the game. If Windows Firewall
   prompts for relay listener access, allow it. Verify firewall behavior on the
   target Windows installation.
4. To stop diversion, press Ctrl+C in the app-divert window before stopping the
   upstream proxy. Diverted connections will close and the game must reconnect.
   An existing TCP connection cannot switch seamlessly back to a direct route.

The first `WinDivertOpen` call automatically registers and loads the driver from
the same directory. No separate MSI, manual certificate installation, test
signing mode, or custom signing is required. Windows must still allow the
official driver to load. Run the game with its usual, non-administrator
privileges. Only one app-divert instance may be active at a time.

## Configuration and scope

`apps` matches EXE filenames or full Windows paths, case-insensitively and
exactly; wildcards are not supported. A filename matches every executable with
that name. Use a full path to restrict matching to a particular installation.
Child processes are matched by their own executable names, so list both the
launcher and game if their names differ and both need diversion.

`socks5` must be a numeric loopback IP:port and supports IPv4/IPv6 NOAUTH CONNECT.
`relay_port` defaults to 34010 and listens on both address families; failure to
open either listener stops startup. Incoming relay connections without an
internal mapping are immediately reset; the relay port is not a general proxy
endpoint. `connect_timeout_seconds` defaults to 10 (range 1..120).
`max_connections` defaults to 4096 (range 1..16000), including mappings retained
after closure. Unknown configuration keys are rejected at startup.

### Destination filters

`targets` limits destinations in the kernel before packets reach the process
lookup workers. Each rule accepts `ips` (literal IPv4/IPv6 or CIDR) and `ports`
(decimal port strings or inclusive ranges). IP and port conditions within a
rule are ANDed; rules are ORed. An omitted or empty field matches any value.
Omitting `targets` or using `[]` keeps the unrestricted destination scope.
Hostnames, zone IDs, IPv4-mapped IPv6 addresses, and wildcard strings are not
accepted. Use at most 32 rules and 64 IP/port selectors in total.

For example, restrict all destination IPs to selected game ports:

```json
"targets": [
  { "ports": ["3724", "8085"] }
]
```

To restrict addresses as well:

```json
"targets": [
  { "ips": ["192.0.2.0/24", "2001:db8::/32"], "ports": ["3724", "8000-8100"] }
]
```

The shipped example uses ports 3724 and 8085; adjust them for your server.
Packets outside the destination filter bypass this WinDivert handle in the
kernel. Relay return packets are also captured so translated connections can
be restored, even though their ports no longer match the original rule.
Only destinations matching `targets` are eligible for process lookup.

Current behavior and limits:

- Only new TCP connections created after startup by matching applications are
  diverted, and only to non-local global unicast addresses, including private
  IPv4 addresses. Existing connections, UDP, DNS, loopback, local and link-local
  destinations, fragments, and nonstandard TCP/IP packets are outside the
  interception scope. This is a TCP forwarding tool, not a traffic isolation
  boundary.
- Windows resolves domain names through its existing DNS path. app-divert sends
  the resolved IP to SOCKS5; it does not intercept DNS or select a new target
  address based on a domain name.
- Each eligible new SYN is associated with a PID using its complete TCP tuple
  from `GetExtendedTcpTable`, then matched by executable path. Four workers
  perform lookups without blocking the receive loop. Process decisions are
  cached for up to one minute using retained process handles; exited process
  instances are invalidated before reuse. At most 256 handles are cached.
- Unknown ownership, a full lookup queue, expired lookup budget, or failure to
  allocate a new proxy mapping **releases the original SYN for direct routing**.
  There are no deliberate lookup retry sleeps. Pending lookups have a 50 ms
  budget, checked on completion and by a 10 ms timer. This is a scheduling
  budget, not a hard real-time latency guarantee. Late results cannot redirect
  an already-released connection. A duplicate pending SYN is coalesced until
  the original is released or mapped. Shutdown releases pending SYNs too.
- Direct decisions use full connection tuples and initial sequence numbers,
  with a ten-minute idle timeout. Retransmissions reuse the decision; a new
  initial sequence triggers a new lookup. Unchanged packets are injected
  without checksum recalculation, process lookup, or per-packet logging.
  Fallback counts are logged at most once per second. DNS and UDP are unchanged.
- Direct and pending decisions share a bounded 65,536-entry cache. If it fills,
  new connections remain direct until restart, preserving existing proxy maps.
  This avoids evicting a live direct decision and later redirecting its SYN
  retransmission. Target connections may therefore bypass acceleration on
  lookup failure or overload. This tool does not enforce mandatory proxy use.
- Diversion rewrites addresses and ports in both directions. It does not change
  system SOCKS settings. Full connection tuples and separate translated ports
  in 49152..65535 prevent connections sharing a local source port from being
  confused with each other.
- FIN preserves half-close behavior; RST or upstream connection failure
  terminates the connection. A mapping enters a two-minute retention period
  only after the relay finishes, continuing to handle FIN/RST retransmissions.
  A new SYN reusing that exact tuple is rejected until retention expires.
  Ctrl+C briefly keeps interception running to send RSTs before shutdown and
  draining. Forced termination, system failure, or driver failure cannot
  guarantee immediate notification to the game; TCP and upstream protocol
  timeouts determine cleanup in those cases.

## Build and package

Requires Go 1.25 or newer. No cgo, WDK, or custom driver build is needed.

On Windows, run:

```powershell
./scripts/package.ps1
```

The script builds app-divert, downloads official WinDivert 2.2.2-A, verifies its
pinned SHA-256 and Windows driver signature, and writes `dist/windows-amd64`.
It preserves an existing user configuration; compare it with the example when
upgrading. Downloads and extraction use the system temporary directory and
are cleaned up in `finally`. Go uses its default temporary directory and build
cache. No project-local temporary directory is required.

The build depends only on this repository, its declared Go modules, and the
official WinDivert download. It does not read adjacent repositories. To create
a distributable archive, use a fresh, empty `-Output` directory. Do not archive
a directory used for normal operation: the script preserves its real user
configuration and other files.

Run tests and cross-compile from a POSIX shell without overriding temporary
directory settings:

```sh
go test -race ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o dist/windows-amd64/app-divert.exe ./cmd/app-divert
```

Tests cover IPv4/IPv6 tuple isolation, bidirectional address rewriting, source
port reuse and retention, PID table parsing, SOCKS5 requests and rejections,
responses after half-close, cancellation cleanup, configuration validation and
snapshots, cancellation before startup, single-use instances, and custom
handler target delivery and FIN/RST behavior. The packet parser also has a
fuzzing entry point. Tests also cover target rules, direct-decision caching,
lookup timeouts, late results, queue/cache exhaustion, and shutdown with pending
lookups.

Optional Windows tests use `APP_DIVERT_TEST_DLL_DIR` to validate generated
filters with the official DLL without loading the driver. The opt-in
`TestWindowsDiversionE2E` and `TestWindowsFailOpenE2E` additionally require administrator privileges and
`APP_DIVERT_E2E_TARGETS`: comma-separated controlled endpoint pairs (eligible
port, excluded port) for each address family. Its endpoint protocol is described
in the test source. Never point that test at game or other uncontrolled servers.

## References and licensing

The implementation uses WinDivert's network-layer API and Microsoft's process
and TCP table APIs. It references the official
[streamdump TCP reflection approach](https://github.com/basil00/WinDivert/blob/v2.2.2/examples/streamdump/streamdump.c)
with independently implemented tuple mapping and SOCKS5 relay code. No
ProxyBridge source code is reused. API references include the
[WinDivert 2.2.2 header](https://github.com/basil00/WinDivert/blob/v2.2.2/include/windivert.h)
and Microsoft's
[GetExtendedTcpTable documentation](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable).

The project's own code uses the [MIT license](LICENSE). WinDivert is used under
its LGPLv3 option; Go dependencies retain their BSD licenses. Third-party
components are not relicensed under MIT. See the
[third-party notices](THIRD_PARTY_NOTICES.md). The portable package includes
the official WinDivert LICENSE/README and third-party notices.

Embedded hosts can use `Options.Routes` to assign disjoint application groups
and destination rules to separate TCP handlers within one interceptor. See
[the library guide](docs/library.md#multiple-application-routes).
