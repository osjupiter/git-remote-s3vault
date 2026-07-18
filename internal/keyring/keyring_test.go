package keyring

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/storage"
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

// blindStore simulates the init race window: Get pretends repo.pub does
// not exist (as the loser saw it before the winner's write landed), while
// the conditional write still sees the truth.
type blindStore struct {
	storage.Storage
	hidden string
}

func (b *blindStore) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if key == b.hidden {
		return nil, errors.New("no such key (simulated race window)")
	}
	return b.Storage.Get(ctx, key)
}

func TestInitRaceLoserGetsAlreadyInitialized(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()

	// Winner initializes for alice.
	if _, err := New(mem, "proj").Init(ctx, []string{newIdentity(t).Recipient().String()}); err != nil {
		t.Fatal(err)
	}

	// Loser raced: its existence check saw nothing, but its conditional
	// write must be rejected — and mapped to ErrAlreadyInitialized.
	loser := New(&blindStore{Storage: mem, hidden: "proj/.keys/repo.pub"}, "proj")
	_, err := loser.Init(ctx, []string{newIdentity(t).Recipient().String()})
	if !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("race loser must get ErrAlreadyInitialized, got %v", err)
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
	if _, err := kr.Revoke(ctx, dek, "bob"); err != nil {
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
	if _, err := kr.Revoke(ctx, dek, bob.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Revoke(ctx, dek, "nobody"); err == nil {
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

// TestSealDetectsPlantedSlot: someone with bucket write access (but no
// DEK) plants a slot .pub — the seal must flag it, and revoking the rogue
// slot must repair it.
func TestSealDetectsPlantedSlot(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	kr := New(mem, "proj")
	alice := newIdentity(t)
	dek, err := kr.Init(ctx, []string{alice.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}

	// Init seals the keyring.
	if st, err := kr.VerifySeal(ctx, dek); err != nil || st != SealValid {
		t.Fatalf("fresh keyring should be sealed: %v %v", st, err)
	}

	// Attacker plants a .pub without the DEK (cannot re-seal).
	evil := newIdentity(t)
	pub := evil.Recipient().String() + "\n"
	if err := mem.Put(ctx, "proj/.keys/dek/evil.pub", strings.NewReader(pub), int64(len(pub))); err != nil {
		t.Fatal(err)
	}
	if st, _ := kr.VerifySeal(ctx, dek); st != SealInvalid {
		t.Fatalf("planted slot must invalidate the seal, got %v", st)
	}

	// Replacing an existing slot's .pub is caught too.
	slots, _ := kr.Slots(ctx)
	if err := mem.Put(ctx, "proj/.keys/dek/"+slots[0].Label+".pub", strings.NewReader(pub), int64(len(pub))); err != nil {
		t.Fatal(err)
	}
	if st, _ := kr.VerifySeal(ctx, dek); st != SealInvalid {
		t.Fatalf("swapped slot pub must invalidate the seal, got %v", st)
	}

	// Deleting the seal downgrades to "missing", never "valid".
	if err := mem.Delete(ctx, "proj/.keys/seal"); err != nil {
		t.Fatal(err)
	}
	if st, _ := kr.VerifySeal(ctx, dek); st != SealMissing {
		t.Fatalf("deleted seal should report missing, got %v", st)
	}

	// A member repairs: revoke the rogue slot (restore alice's pub first).
	alicePub := alice.Recipient().String() + "\n"
	if err := mem.Put(ctx, "proj/.keys/dek/"+slots[0].Label+".pub", strings.NewReader(alicePub), int64(len(alicePub))); err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Revoke(ctx, dek, "evil"); err != nil {
		t.Fatal(err)
	}
	if st, _ := kr.VerifySeal(ctx, dek); st != SealValid {
		t.Fatalf("revoke must repair the seal, got %v", st)
	}
}

// TestSealCoversRepoPub: swapping the repository public key without the
// DEK is detected.
func TestSealCoversRepoPub(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemory()
	kr := New(mem, "proj")
	alice := newIdentity(t)
	dek, err := kr.Init(ctx, []string{alice.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	evil := newIdentity(t)
	pub := evil.Recipient().String() + "\n"
	if err := mem.Put(ctx, "proj/.keys/repo.pub", strings.NewReader(pub), int64(len(pub))); err != nil {
		t.Fatal(err)
	}
	if st, _ := kr.VerifySeal(ctx, dek); st != SealInvalid {
		t.Fatalf("swapped repo.pub must invalidate the seal, got %v", st)
	}
}
