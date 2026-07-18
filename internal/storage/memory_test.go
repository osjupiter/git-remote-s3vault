package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMemoryPutIfSemantics(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	// Create-only succeeds once.
	if err := m.PutIf(ctx, "k", strings.NewReader("v1"), 2, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIf(ctx, "k", strings.NewReader("v2"), 2, ""); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("second create-only write must fail, got %v", err)
	}

	// CAS with the right etag succeeds; a stale etag fails.
	etag, err := m.ETag(ctx, "k")
	if err != nil || etag == "" {
		t.Fatalf("etag = %q, %v", etag, err)
	}
	if err := m.PutIf(ctx, "k", strings.NewReader("v2"), 2, etag); err != nil {
		t.Fatal(err)
	}
	if err := m.PutIf(ctx, "k", strings.NewReader("v3"), 2, etag); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale-etag write must fail, got %v", err)
	}

	// Content reflects the successful CAS.
	rc, _ := m.Get(ctx, "k")
	buf := make([]byte, 2)
	rc.Read(buf)
	rc.Close()
	if string(buf) != "v2" {
		t.Fatalf("content = %q", buf)
	}

	// CAS against a missing key fails; etag of missing key is empty.
	if err := m.PutIf(ctx, "absent", strings.NewReader("x"), 1, etag); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("CAS on missing key must fail, got %v", err)
	}
	if etag, _ := m.ETag(ctx, "absent"); etag != "" {
		t.Fatalf("missing key etag = %q", etag)
	}
}
