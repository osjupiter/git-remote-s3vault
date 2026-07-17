package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Memory is an in-memory Storage, used by tests and available for tooling.
type Memory struct {
	mu      sync.Mutex
	objects map[string][]byte
	mtimes  map[string]time.Time
	clock   time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		objects: map[string][]byte{},
		mtimes:  map[string]time.Time{},
		clock:   time.Unix(1_700_000_000, 0),
	}
}

func (m *Memory) List(_ context.Context, prefix string) ([]Object, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Object
	for k, v := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, Object{Key: k, Size: int64(len(v)), LastModified: m.mtimes[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (m *Memory) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("no such key %s", key)
	}
	return io.NopCloser(bytes.NewReader(v)), nil
}

func (m *Memory) Put(_ context.Context, key string, body io.Reader, _ int64) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = data
	m.clock = m.clock.Add(time.Second)
	m.mtimes[key] = m.clock
	return nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	delete(m.mtimes, key)
	return nil
}

func (m *Memory) Exists(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[key]
	return ok, nil
}

// Bytes returns a stored object's raw content (test convenience).
func (m *Memory) Bytes(key string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.objects[key]
	return v, ok
}
