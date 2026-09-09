package divert

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type packetSink struct {
	mu       sync.Mutex
	raw      [][]byte
	modified []bool
}

func (s *packetSink) inject(raw []byte, _ *address, modified bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = append(s.raw, append([]byte(nil), raw...))
	s.modified = append(s.modified, modified)
}
func newTestRouter(t *testing.T, owner func(tuple) (string, error)) (*packetRouter, *packetSink) {
	t.Helper()
	cfg, err := (Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080", Targets: []TargetRule{{Ports: []string{"3724"}}}}).normalized(false)
	if err != nil {
		t.Fatal(err)
	}
	sink := &packetSink{}
	r := newPacketRouter(cfg, newFlowTable(cfg.RelayPort, cfg.MaxConnections), owner, sink.inject)
	t.Cleanup(r.stop)
	return r, sink
}

func TestDirectDecisionsAndTupleReuse(t *testing.T) {
	for _, failed := range []bool{false, true} {
		var calls int
		r, sink := newTestRouter(t, func(tuple) (string, error) {
			calls++
			if failed {
				return "", errors.New("owner unavailable")
			}
			return "", nil
		})
		p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
		original := append([]byte(nil), p.raw...)
		r.process(p.raw, &address{})
		r.resolve(<-r.jobs)
		for i := 0; i < 10; i++ {
			r.process(p.raw, &address{})
		}
		if calls != 1 || len(sink.raw) != 11 {
			t.Fatalf("calls=%d packets=%d", calls, len(sink.raw))
		}
		for i, raw := range sink.raw {
			if sink.modified[i] || !bytes.Equal(raw, original) {
				t.Fatal("direct packet changed")
			}
		}
		// An unrelated destination sharing a source port gets its own decision.
		q := testPacket(t, "192.0.2.1:50000", "198.51.100.2:3724", 1)
		r.process(q.raw, &address{})
		r.resolve(<-r.jobs)
		// A new initial sequence on the original tuple is a new connection.
		q = testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 2)
		r.process(q.raw, &address{})
		r.resolve(<-r.jobs)
		if calls != 3 {
			t.Fatal("tuple/sequence isolation failed")
		}
	}
}

func TestQueueFullAndMappingFailurePassDirect(t *testing.T) {
	for _, queueFull := range []bool{false, true} {
		r, sink := newTestRouter(t, func(tuple) (string, error) { return "default", nil })
		if queueFull {
			r.jobs = make(chan *ownerJob)
		} else {
			r.table.limit = 0
		}
		p := testPacket(t, "[2001:db8::1]:50000", "[2001:db8::2]:3724", 1)
		r.process(p.raw, &address{})
		if !queueFull {
			r.resolve(<-r.jobs)
		}
		r.process(p.raw, &address{})
		if len(sink.raw) != 2 || sink.modified[0] || sink.modified[1] || len(r.pending) != 0 || len(r.direct) != 1 {
			t.Fatal("fallback lost or modified SYN")
		}
	}
}

func TestLookupDeadlineIgnoresLateProxyResult(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	r, sink := newTestRouter(t, func(tuple) (string, error) { close(entered); <-release; return "default", nil })
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	r.process(p.raw, &address{})
	job := <-r.jobs
	done := make(chan struct{})
	go func() { r.resolve(job); close(done) }()
	<-entered
	r.process(p.raw, &address{}) // duplicate SYN remains pending
	r.expire(job.deadline.Add(time.Millisecond))
	close(release)
	<-done
	r.process(p.raw, &address{})
	if len(sink.raw) != 2 || sink.modified[0] || sink.modified[1] || len(r.table.forward) != 0 {
		t.Fatal("late result changed a released connection")
	}
}

func TestScopeAndExistingPacketsSkipOwner(t *testing.T) {
	r, sink := newTestRouter(t, func(tuple) (string, error) { t.Error("unexpected owner lookup"); return "", nil })
	for _, target := range []string{"198.51.100.1:443", "127.0.0.1:3724", "[fe80::1]:3724"} {
		local := "192.0.2.1:50000"
		if target[0] == '[' {
			local = "[2001:db8::1]:50000"
		}
		p := testPacket(t, local, target, 1)
		r.process(p.raw, &address{})
	}
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	p.raw[p.tcp+13] = 16
	r.process(p.raw, &address{})
	if len(r.jobs) != 0 || len(sink.raw) != 4 {
		t.Fatal("out-of-scope packet queued")
	}
}

func TestProxyAndReverseRelayStayMapped(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		r, sink := newTestRouter(t, func(tuple) (string, error) { return "default", nil })
		local, target := "192.0.2.1:50000", "198.51.100.1:3724"
		if v6 {
			local, target = "[2001:db8::1]:50000", "[2001:db8::2]:3724"
		}
		p := testPacket(t, local, target, 1)
		key := p.key
		r.process(p.raw, &address{})
		r.resolve(<-r.jobs)
		reflected, _ := parsePacket(sink.raw[0])
		reply := testPacket(t, reflected.key.remote.String(), reflected.key.local.String(), 90)
		reply.raw[reply.tcp+13] = 18
		r.process(reply.raw, &address{})
		restored, _ := parsePacket(sink.raw[1])
		if restored.key.local != key.remote || restored.key.remote != key.local || !sink.modified[0] || !sink.modified[1] {
			t.Fatal("lost NAT direction")
		}
		r.stop()
		r.process(p.raw, &address{}) // shutdown must retain maps for resets/retransmissions
		if !sink.modified[2] {
			t.Fatal("mapped connection switched direct")
		}
	}
}

func TestDecisionCapacityBypassesUntilRestart(t *testing.T) {
	r, sink := newTestRouter(t, func(tuple) (string, error) { return "", nil })
	r.limit = 1
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	r.process(p.raw, &address{})
	r.resolve(<-r.jobs)
	q := testPacket(t, "192.0.2.1:50001", "198.51.100.1:3724", 1)
	r.process(q.raw, &address{})
	r.expire(time.Now().Add(directIdleTimeout + time.Minute))
	r.process(q.raw, &address{})
	if !r.bypass || len(r.jobs) != 0 || len(sink.raw) != 3 {
		t.Fatal("cache exhaustion could reclassify a direct connection")
	}
}

func TestStopFlushesPendingAndRejectsLateDecisions(t *testing.T) {
	r, sink := newTestRouter(t, func(tuple) (string, error) { t.Error("lookup after stop"); return "default", nil })
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	r.process(p.raw, &address{})
	job := <-r.jobs
	r.stop()
	r.resolve(job)
	r.process(p.raw, &address{})
	if len(sink.raw) != 2 || sink.modified[0] || len(r.pending) != 0 {
		t.Fatal("shutdown stranded SYN")
	}
}

func TestPendingPacketPinsDirectBeforeLateResult(t *testing.T) {
	r, sink := newTestRouter(t, func(tuple) (string, error) { return "default", nil })
	p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	r.process(p.raw, &address{})
	job := <-r.jobs
	p.raw[p.tcp+13] = 4 // application canceled while owner lookup was pending
	r.process(p.raw, &address{})
	r.resolve(job)
	if len(sink.raw) != 2 || sink.modified[0] || sink.modified[1] || len(r.table.forward) != 0 {
		t.Fatal("late mapping after reset")
	}
}

func TestConcurrentOwnerResultsAndShutdown(t *testing.T) {
	var calls atomic.Int32
	r, _ := newTestRouter(t, func(tuple) (string, error) { calls.Add(1); return "", nil })
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range r.jobs {
				r.resolve(job)
			}
		}()
	}
	for i := 0; i < 100; i++ {
		p := testPacket(t, "192.0.2.1:50000", "198.51.100.1:3724", uint32(i))
		r.process(p.raw, &address{})
	}
	r.stop()
	workers.Wait()
	if len(r.pending) != 0 {
		t.Fatal("pending lookups leaked")
	}
}

// Measures the in-memory direct decision path; excludes actual driver/syscall
// overhead and is not a claim about end-to-end networking performance.
func BenchmarkDirectPacketPath(b *testing.B) {
	cfg, _ := (Config{Apps: []string{"game.exe"}, SOCKS5: "127.0.0.1:1080"}).normalized(false)
	calls := 0
	r := newPacketRouter(cfg, newFlowTable(cfg.RelayPort, cfg.MaxConnections), func(tuple) (string, error) { calls++; return "", nil }, func([]byte, *address, bool) {})
	p := testPacket(b, "192.0.2.1:50000", "198.51.100.1:3724", 1)
	addr := address{}
	r.process(p.raw, &addr)
	r.resolve(<-r.jobs)
	p.raw[p.tcp+13] = 16
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		r.process(p.raw, &addr)
	}
	b.StopTimer()
	r.stop()
	if calls != 1 {
		b.Fatal("repeated owner lookup")
	}
}
