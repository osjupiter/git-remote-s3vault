package snapshot

import (
	"context"
	"errors"
	"testing"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

func testState() *State {
	return &State{
		Refs:   map[string]string{"refs/heads/main": "aaaa", "refs/tags/v1": "bbbb"},
		Head:   "refs/heads/main",
		Bundle: "obj123",
	}
}

func TestMissingStateIsNilNotError(t *testing.T) {
	st, etag, err := Load(context.Background(), storage.NewMemory(), "repo", "data", nil)
	if err != nil || st != nil || etag != "" {
		t.Fatalf("missing state: got %+v %q %v", st, etag, err)
	}
}

func TestEncryptedRoundtrip(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	dek, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}

	if err := Save(ctx, mem, "repo", "data", testState(), dek.Recipient(), ""); err != nil {
		t.Fatal(err)
	}
	got, etag, err := Load(ctx, mem, "repo", "data", dek)
	if err != nil {
		t.Fatal(err)
	}
	if etag == "" {
		t.Fatal("expected a CAS token")
	}
	if got.Refs["refs/heads/main"] != "aaaa" || got.Head != "refs/heads/main" || got.Bundle != "obj123" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// The stored bytes are not the JSON (encrypted), and a stranger's key
	// cannot read them.
	stranger, _ := age.GenerateX25519Identity()
	if _, _, err := Load(ctx, mem, "repo", "data", stranger); err == nil {
		t.Fatal("stranger's key must not decrypt the state")
	}
}

func TestPlaintextRoundtrip(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	if err := Save(ctx, mem, "repo", "data", testState(), nil, ""); err != nil {
		t.Fatal(err)
	}
	got, _, err := Load(ctx, mem, "repo", "data", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Refs["refs/tags/v1"] != "bbbb" {
		t.Fatalf("plaintext roundtrip mismatch: %+v", got)
	}
}

func TestSaveIsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()

	// Create-only: a second blind create loses.
	if err := Save(ctx, mem, "repo", "data", testState(), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, mem, "repo", "data", testState(), nil, ""); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("blind create over existing state: got %v", err)
	}

	// Update with the current token wins; reusing the stale token loses.
	_, etag, err := Load(ctx, mem, "repo", "data", nil)
	if err != nil {
		t.Fatal(err)
	}
	s2 := testState()
	s2.Bundle = "obj456"
	if err := Save(ctx, mem, "repo", "data", s2, nil, etag); err != nil {
		t.Fatal(err)
	}
	if err := Save(ctx, mem, "repo", "data", testState(), nil, etag); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("stale-token update: got %v", err)
	}
	got, _, _ := Load(ctx, mem, "repo", "data", nil)
	if got.Bundle != "obj456" {
		t.Fatalf("winning update lost: %+v", got)
	}
}

func TestDeleteRemovesState(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	if err := Save(ctx, mem, "repo", "data", testState(), nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := Delete(ctx, mem, "repo", "data"); err != nil {
		t.Fatal(err)
	}
	st, _, err := Load(ctx, mem, "repo", "data", nil)
	if err != nil || st != nil {
		t.Fatalf("state should be gone: %+v %v", st, err)
	}
}
