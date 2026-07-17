package keyring

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-r2/internal/storage"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestInitUnwrapRoundtrip(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	kr := New(mem, "proj")
	alice := newIdentity(t)

	if _, ok, _ := kr.RepoRecipient(ctx); ok {
		t.Fatal("keyring should not exist yet")
	}
	dek, err := kr.Init(ctx, []string{alice.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}

	// repo.pub is published and matches the DEK.
	pub, ok, err := kr.RepoRecipient(ctx)
	if err != nil || !ok {
		t.Fatalf("repo recipient missing: %v", err)
	}
	if pub.(*age.X25519Recipient).String() != dek.Recipient().String() {
		t.Fatal("published repo.pub does not match the DEK")
	}

	// The wrapped slot never contains the DEK secret in plaintext.
	label := DefaultLabel(alice.Recipient().String())
	raw, ok := mem.Bytes("proj/.keys/dek/" + label + ".age")
	if !ok {
		t.Fatalf("wrapped slot missing at proj/.keys/dek/%s.age", label)
	}
	if bytes.Contains(raw, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("wrapped slot leaks the DEK secret")
	}

	// Alice unwraps; a stranger cannot.
	got, ok, err := kr.Unwrap(ctx, []age.Identity{alice})
	if err != nil || !ok {
		t.Fatalf("alice cannot unwrap: %v", err)
	}
	if got.String() != dek.String() {
		t.Fatal("unwrapped DEK mismatch")
	}
	if _, ok, _ := kr.Unwrap(ctx, []age.Identity{newIdentity(t)}); ok {
		t.Fatal("a stranger should not unwrap the DEK")
	}
}

func TestInitRefusesSecondKeyring(t *testing.T) {
	ctx := context.Background()
	kr := New(storage.NewMemory(), "proj")
	if _, err := kr.Init(ctx, []string{newIdentity(t).Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Init(ctx, []string{newIdentity(t).Recipient().String()}); err == nil {
		t.Fatal("second Init must fail")
	}
	if _, err := New(storage.NewMemory(), "p").Init(ctx, nil); err == nil {
		t.Fatal("Init without recipients must fail")
	}
}

func TestGrantListRevoke(t *testing.T) {
	ctx := context.Background()
	kr := New(storage.NewMemory(), "proj")
	alice, bob := newIdentity(t), newIdentity(t)

	dek, err := kr.Init(ctx, []string{alice.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Grant(ctx, dek, bob.Recipient().String(), "bob"); err != nil {
		t.Fatal(err)
	}

	slots, err := kr.Slots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 {
		t.Fatalf("slots = %+v", slots)
	}
	byLabel := map[string]string{}
	for _, s := range slots {
		byLabel[s.Label] = s.Recipient
	}
	if byLabel["bob"] != bob.Recipient().String() {
		t.Fatalf("bob's slot wrong: %+v", slots)
	}

	// Bob can now unwrap without any history rewrite.
	if _, ok, err := kr.Unwrap(ctx, []age.Identity{bob}); err != nil || !ok {
		t.Fatalf("bob cannot unwrap after grant: %v", err)
	}

	// Revoke by label, then bob is locked out of future unwraps.
	if _, err := kr.Revoke(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := kr.Unwrap(ctx, []age.Identity{bob}); ok {
		t.Fatal("bob should not unwrap after revoke")
	}
	if _, ok, err := kr.Unwrap(ctx, []age.Identity{alice}); err != nil || !ok {
		t.Fatal("alice must keep access after bob's revocation")
	}

	// Revoke by recipient string too.
	if err := kr.Grant(ctx, dek, bob.Recipient().String(), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Revoke(ctx, bob.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Revoke(ctx, "nobody"); err == nil {
		t.Fatal("revoking an unknown slot must fail")
	}
}

func TestGrantRejectsBadLabelAndKey(t *testing.T) {
	ctx := context.Background()
	kr := New(storage.NewMemory(), "proj")
	dek, err := kr.Init(ctx, []string{newIdentity(t).Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := kr.Grant(ctx, dek, "not-a-key", ""); err == nil {
		t.Fatal("garbage recipient must be rejected")
	}
	if err := kr.Grant(ctx, dek, newIdentity(t).Recipient().String(), "bad/label"); err == nil {
		t.Fatal("label with slash must be rejected")
	}
	if !strings.HasPrefix(DefaultLabel("age1abc"), DefaultLabel("age1abc")) || len(DefaultLabel("x")) != 12 {
		t.Fatal("DefaultLabel should be a stable 12-char fingerprint")
	}
}
