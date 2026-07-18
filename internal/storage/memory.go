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
	etags   map[string]string
	rev     int
	clock   time.Time
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		objects: map[string][]byte{},
		mtimes:  map[string]time.Time{},
		etags:   map[string]string{},
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
	m.store(key, data)
	return nil
}

// store writes an object and bumps its etag; callers hold the lock.
func (m *Memory) store(key string, data []byte) {
	m.objects[key] = data
	m.clock = m.clock.Add(time.Second)
	m.mtimes[key] = m.clock
	m.rev++
	m.etags[key] = fmt.Sprintf("\"rev-%d\"", m.rev)
}

func (m *Memory) PutIf(_ context.Context, key string, body io.Reader, _ int64, ifMatch string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, exists := m.etags[key]
	if ifMatch == "" {
		if exists {
			return fmt.Errorf("putting %s: %w", key, ErrPreconditionFailed)
		}
	} else if !exists || cur != ifMatch {
		return fmt.Errorf("putting %s: %w", key, ErrPreconditionFailed)
	}
	m.store(key, data)
	return nil
}

func (m *Memory) ETag(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.etags[key], nil
}

func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	delete(m.mtimes, key)
	delete(m.etags, key)
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
