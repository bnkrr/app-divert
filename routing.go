package divert

import (
	"sync"
	"time"
)

const (
	ownerLookupTimeout = 50 * time.Millisecond
	directIdleTimeout  = 10 * time.Minute
	decisionLimit      = 65536
)

type directDecision struct {
	seq     uint32
	expires time.Time
}
type ownerJob struct {
	p        packet
	addr     address
	deadline time.Time
}

// packetRouter makes each first-SYN decision atomic with its publication and
// injection. Late owner results cannot redirect a connection already released.
// The receive loop borrows packet buffers; only pending lookups retain a copy.
type packetRouter struct {
	mu               sync.Mutex
	cfg              Config
	table            *flowTable
	owner            func(tuple) (string, error)
	inject           func([]byte, *address, bool)
	direct           map[tuple]directDecision
	pending          map[tuple]*ownerJob
	jobs             chan *ownerJob
	limit            int
	stopping, bypass bool
	nextSweep        time.Time
	// owner failure, queue full, deadline, mapping failure, cache exhaustion.
	fallbacks [5]uint64
}

func newPacketRouter(cfg Config, table *flowTable, owner func(tuple) (string, error), inject func([]byte, *address, bool)) *packetRouter {
	return &packetRouter{cfg: cfg, table: table, owner: owner, inject: inject, direct: make(map[tuple]directDecision), pending: make(map[tuple]*ownerJob), jobs: make(chan *ownerJob, 256), limit: decisionLimit}
}

func (r *packetRouter) process(raw []byte, addr *address) {
	p, err := parsePacket(raw)
	if err != nil {
		r.inject(raw, addr, false)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Always honor existing NAT maps, including while new connections bypass.
	if mapped, drop := r.table.rewrite(p); mapped {
		if !drop {
			r.inject(raw, addr, true)
		}
		return
	}
	now := time.Now()
	if r.stopping || r.bypass {
		r.inject(raw, addr, false)
		return
	}
	syn := p.syn && !p.ack
	if d, ok := r.direct[p.key]; ok {
		if now.Before(d.expires) && (!syn || d.seq == p.seq) {
			d.expires = now.Add(directIdleTimeout)
			r.direct[p.key] = d
			r.inject(raw, addr, false)
			return
		}
		delete(r.direct, p.key)
	}
	if job := r.pending[p.key]; job != nil {
		if syn && p.seq == job.p.seq {
			return
		} // retain one SYN until decision/deadline
		if !syn {
			// A reset, data, or ACK arrived before lookup completed. Release the held
			// SYN first and pin direct, so a late lookup cannot splice the connection.
			r.release(job, now)
			r.inject(raw, addr, false)
			return
		}
		// A different initial sequence identifies tuple reuse, not retransmission.
		delete(r.pending, p.key)
	}
	if !syn || !p.key.remote.Addr().IsGlobalUnicast() || p.key.remote.Addr().IsLoopback() || p.key.remote.Addr().IsLinkLocalUnicast() || !r.cfg.targets.matches(p.key.remote) {
		r.inject(raw, addr, false)
		return
	}
	if len(r.direct)+len(r.pending) >= r.limit {
		// Never evict a live direct decision to proxy its retransmission later.
		// With no room to remember additional decisions, bypass new connections
		// until restart. Existing proxies retain their mappings.
		r.bypass = true
		r.fallbacks[4]++
		for _, job := range r.pending {
			r.release(job, now)
		}
		r.inject(raw, addr, false)
		return
	}
	if addr.Flags&impostorFlag != 0 {
		// A reinjected SYN cannot create a new proxy mapping. Remember its direct
		// decision so an ordinary retransmission cannot splice it later. Packets
		// belonging to our existing mappings have already been handled above.
		r.direct[p.key] = directDecision{p.seq, now.Add(directIdleTimeout)}
		r.inject(raw, addr, false)
		return
	}
	copyPacket, _ := parsePacket(append([]byte(nil), raw...))
	job := &ownerJob{p: copyPacket, addr: *addr, deadline: now.Add(ownerLookupTimeout)}
	r.pending[p.key] = job
	select {
	case r.jobs <- job:
	default:
		r.fallbacks[1]++
		r.release(job, now)
	}
}

// release requires mu. Record the direct decision before injecting the SYN.
func (r *packetRouter) release(job *ownerJob, now time.Time) {
	delete(r.pending, job.p.key)
	if !r.bypass && !r.stopping {
		r.direct[job.p.key] = directDecision{job.p.seq, now.Add(directIdleTimeout)}
	}
	r.inject(job.p.raw, &job.addr, false)
}

func (r *packetRouter) resolve(job *ownerJob) {
	r.mu.Lock()
	active := r.pending[job.p.key] == job
	r.mu.Unlock()
	if !active {
		return
	}
	route, err := r.owner(job.p.key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[job.p.key] != job {
		return
	}
	now := time.Now()
	if err != nil {
		r.fallbacks[0]++
		r.release(job, now)
		return
	}
	if !now.Before(job.deadline) {
		r.fallbacks[2]++
		r.release(job, now)
		return
	}
	if route == "" {
		r.release(job, now)
		return
	}
	if _, err = r.table.addRoute(job.p, route); err != nil {
		r.fallbacks[3]++
		r.release(job, now)
		return
	}
	delete(r.pending, job.p.key)
	modified, drop := r.table.rewrite(job.p)
	if !drop {
		r.inject(job.p.raw, &job.addr, modified)
	}
}

func (r *packetRouter) expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, job := range r.pending {
		if !now.Before(job.deadline) {
			r.fallbacks[2]++
			r.release(job, now)
		}
	}
	if !now.Before(r.nextSweep) {
		for key, d := range r.direct {
			if !now.Before(d.expires) {
				delete(r.direct, key)
			}
		}
		r.nextSweep = now.Add(time.Minute)
	}
}

func (r *packetRouter) takeFallbacks() [5]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	counts := r.fallbacks
	r.fallbacks = [5]uint64{}
	return counts
}

func (r *packetRouter) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping {
		return
	}
	r.stopping = true
	for _, job := range r.pending {
		r.release(job, time.Now())
	}
	close(r.jobs)
}
