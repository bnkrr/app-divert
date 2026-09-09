package divert

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const retainClosed = 2 * time.Minute

type flow struct {
	route      string
	original   tuple
	translated uint16
	seq        uint32
	expires    time.Time // zero while a relay owns the connection
	claimed    bool
	conn       *net.TCPConn
}
type flowTable struct {
	mu       sync.Mutex
	forward  map[tuple]*flow
	reverse  map[tuple]*flow
	used     map[uint16]bool
	next     uint16
	relay    uint16
	limit    int
	stopping bool
}

func newFlowTable(port uint16, limit int) *flowTable {
	return &flowTable{forward: make(map[tuple]*flow), reverse: make(map[tuple]*flow), used: make(map[uint16]bool), next: 49152, relay: port, limit: limit}
}
func (t *flowTable) reverseKey(f *flow) tuple {
	return tuple{netip.AddrPortFrom(f.original.local.Addr(), t.relay), netip.AddrPortFrom(f.original.remote.Addr(), f.translated)}
}
func (t *flowTable) expire(now time.Time) {
	for k, f := range t.forward {
		if !f.expires.IsZero() && !now.Before(f.expires) {
			delete(t.forward, k)
			delete(t.reverse, t.reverseKey(f))
			delete(t.used, f.translated)
		}
	}
}
func (t *flowTable) add(p packet) (*flow, error) {
	return t.addRoute(p, "default")
}

func (t *flowTable) addRoute(p packet, route string) (*flow, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopping {
		return nil, errors.New("interception is stopping")
	}
	t.expire(time.Now())
	if f := t.forward[p.key]; f != nil {
		if f.seq == p.seq {
			return f, nil
		}
		return nil, errors.New("previous tuple still draining; reconnect with a fresh source port")
	}
	if len(t.forward) >= t.limit {
		return nil, errors.New("connection limit reached (includes TCP close retention)")
	}
	for i := 0; i < 16384; i++ {
		port := t.next
		t.next++
		if t.next == 0 {
			t.next = 49152
		}
		if port == t.relay || t.used[port] {
			continue
		}
		f := &flow{route: route, original: p.key, translated: port, seq: p.seq, expires: time.Now().Add(retainClosed)}
		t.forward[p.key] = f
		t.reverse[t.reverseKey(f)] = f
		t.used[port] = true
		return f, nil
	}
	return nil, errors.New("translated port pool exhausted")
}

// Returns mapped=true even for a conflicting SYN: an old translated TCP
// connection must never be spliced into a new connection with the same tuple.
func (t *flowTable) rewrite(p packet) (mapped, drop bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.reverse[p.key]; f != nil {
		p.reflect(f.original.remote, f.original.local)
		return true, false
	}
	if f := t.forward[p.key]; f != nil {
		if p.syn && !p.ack && p.seq != f.seq {
			return true, true
		}
		p.reflect(netip.AddrPortFrom(f.original.remote.Addr(), f.translated), netip.AddrPortFrom(f.original.local.Addr(), t.relay))
		return true, false
	}
	return false, false
}
func (t *flowTable) claim(c *net.TCPConn) *flow {
	local := c.LocalAddr().(*net.TCPAddr).AddrPort()
	remote := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.reverse[tuple{local, remote}]
	if t.stopping || f == nil || f.claimed {
		return nil
	}
	f.claimed = true
	f.conn = c
	f.expires = time.Time{}
	return f
}
func (t *flowTable) release(f *flow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f.conn = nil
	f.expires = time.Now().Add(retainClosed)
}
func (t *flowTable) stop() {
	t.mu.Lock()
	t.stopping = true
	var conns []*net.TCPConn
	for _, f := range t.forward {
		if f.conn != nil {
			conns = append(conns, f.conn)
		}
	}
	t.mu.Unlock()
	for _, c := range conns {
		resetTCP(c)
	}
}
