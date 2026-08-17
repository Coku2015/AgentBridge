package httpserver

import (
	"sync"

	"github.com/Coku2015/agentbridge/internal/job"
)

// Event is a single per-host progress event streamed over SSE (AB-NFR-006,
// FR-038). All fields are non-secret; the producer MUST redact any error before
// publishing (Message is already expected to be redacted).
type Event struct {
	Type     string `json:"type"` // "host" | "batch"
	BatchID  string `json:"batchId,omitempty"`
	HostID   string `json:"hostId,omitempty"`
	State    string `json:"state,omitempty"`    // job.HostState / BatchState
	Progress int    `json:"progress,omitempty"` // 0..100
	Message  string `json:"message,omitempty"`
}

// Bus is an in-memory pub/sub for progress events with a bounded replay buffer
// so a browser refresh can re-read recent state without losing progress
// (FR-038). It is safe for concurrent use.
type Bus struct {
	mu      sync.Mutex
	subs    map[int]chan Event
	nextID  int
	recent  []Event
	replayN int
}

// NewBus returns a Bus with the given replay-buffer length.
func NewBus(replay int) *Bus {
	if replay < 0 {
		replay = 0
	}
	return &Bus{subs: map[int]chan Event{}, replayN: replay}
}

// Publish broadcasts e to all subscribers and records it in the replay buffer.
func (b *Bus) Publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.recent = append(b.recent, e)
	if len(b.recent) > b.replayN {
		b.recent = b.recent[len(b.recent)-b.replayN:]
	}
	for _, ch := range b.subs {
		// Non-blocking: a slow client must not stall the pipeline.
		select {
		case ch <- e:
		default:
		}
	}
}

// Recent returns a copy of the replay buffer (oldest first).
func (b *Bus) Recent() []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, len(b.recent))
	copy(out, b.recent)
	return out
}

// Subscribe returns a buffered live channel plus a cancel func. The caller
// should first drain Recent() (for refresh-safe replay) then range over ch.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	b.mu.Lock()
	id := b.nextID
	b.nextID++
	b.subs[id] = ch
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		if c, ok := b.subs[id]; ok {
			delete(b.subs, id)
			close(c)
		}
		b.mu.Unlock()
	}
	return ch, cancel
}

// PublishHost is a convenience that builds and publishes a host event from a
// job.HostState, keeping the SSE layer decoupled from internal state literals.
func (b *Bus) PublishHost(batchID, hostID string, state job.HostState, progress int, msg string) {
	b.Publish(Event{
		Type: "host", BatchID: batchID, HostID: hostID,
		State: string(state), Progress: progress, Message: msg,
	})
}
