package evidence

import "sync"

// TODO[jpower432]: This should be a queue. Once processed should be removed.

type Store struct {
	mu     sync.RWMutex
	events map[string]EvidenceEvent
}

func NewStore() *Store {
	return &Store{
		events: make(map[string]EvidenceEvent),
	}
}

func (s *Store) Add(event EvidenceEvent) {
	s.mu.Lock()
	s.events[event.Evidence.ID] = event
	s.mu.Unlock()
}

func (s *Store) Events() []EvidenceEvent {
	events := make([]EvidenceEvent, 0, len(s.events))
	for _, claim := range s.events {
		events = append(events, claim)
	}
	return events
}
