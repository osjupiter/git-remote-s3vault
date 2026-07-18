package rotation

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/filesystem"

	"github.com/osjupiter/git-remote-s3ee/internal/config"
	"github.com/osjupiter/git-remote-s3ee/internal/keyring"
	"github.com/osjupiter/git-remote-s3ee/internal/kopiax"
	"github.com/osjupiter/git-remote-s3ee/internal/storage"
)

const (
	shaMain  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaTopic = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type env struct {
	cfg    *config.Config
	store  *storage.Memory
	alice  *age.X25519Identity
	dekOld *age.X25519Identity
}

// newEnv seeds a remote: keyring with alice granted, generation "data"
// holding two refs and HEAD.
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	blobDir := t.TempDir()
	orig := kopiax.NewBlobStorage
	kopiax.NewBlobStorage = func(ctx context.Context, _ *config.Config, gen string) (blob.Storage, error) {
		dir := filepath.Join(blobDir, gen)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		return filesystem.New(ctx, &filesystem.Options{Path: dir}, true)
	}
	t.Cleanup(func() { kopiax.NewBlobStorage = orig })

	alice, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		cfg:   &config.Config{Bucket: "b", Prefix: "repo", Encryption: config.EncryptionAge},
		store: storage.NewMemory(),
		alice: alice,
	}
	kr := keyring.New(e.store, "repo")
	dek, err := kr.Init(ctx, []string{alice.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	e.dekOld = dek

	rep, err := kopiax.Open(ctx, e.cfg, dek.String(), kopiax.FirstGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	defer rep.Close(ctx)
	mustPush(t, rep, "refs/heads/main", shaMain, "bundle-main-payload")
	mustPush(t, rep, "refs/heads/topic", shaTopic, "bundle-topic-payload")
	if err := rep.SetHead(ctx, "refs/heads/main"); err != nil {
		t.Fatal(err)
	}
	return e
}

func mustPush(t *testing.T, rep *kopiax.Repo, name, sha, payload string) {
	t.Helper()
	if _, err := rep.PushRef(context.Background(), name, sha, strings.NewReader(payload), false); err != nil {
		t.Fatal(err)
	}
}

// verifyGeneration opens gen with password and checks the seeded state.
func (e *env) verifyGeneration(t *testing.T, gen, password string) {
	t.Helper()
	ctx := context.Background()
	rep, err := kopiax.Open(ctx, e.cfg, password, gen, false)
	if err != nil {
		t.Fatalf("opening %s: %v", gen, err)
	}
	defer rep.Close(ctx)
	refs, err := rep.Refs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if refs["refs/heads/main"].SHA != shaMain || refs["refs/heads/topic"].SHA != shaTopic {
		t.Fatalf("refs wrong in %s: %+v", gen, refs)
	}
	rc, _, err := rep.OpenBundle(ctx, refs["refs/heads/main"].Object)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != "bundle-main-payload" {
		t.Fatalf("bundle content wrong in %s: %q", gen, data)
	}
	if head, _ := rep.Head(ctx); head != "refs/heads/main" {
		t.Fatalf("HEAD wrong in %s: %q", gen, head)
	}
}

func (e *env) newDEK(t *testing.T) *age.X25519Identity {
	t.Helper()
	dek, ok, err := keyring.New(e.store, "repo").Unwrap(context.Background(), []age.Identity{e.alice})
	if err != nil || !ok {
		t.Fatalf("alice cannot unwrap after rotation: %v", err)
	}
	return dek
}

func TestRotateHappyPath(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Run(ctx); err != nil {
		t.Fatal(err)
	}

	if gen := kopiax.CurrentGeneration(ctx, e.store, "repo"); gen != "data2" {
		t.Fatalf("generation = %q", gen)
	}
	dekNew := e.newDEK(t)
	if dekNew.String() == e.dekOld.String() {
		t.Fatal("DEK did not change")
	}
	// repo.pub now advertises the new DEK.
	kr := keyring.New(e.store, "repo")
	if r, _, _ := kr.RepoRecipient(ctx); r.(*age.X25519Recipient).String() != dekNew.Recipient().String() {
		t.Fatal("repo.pub not updated")
	}
	// Everything is readable in the new generation under the new DEK...
	e.verifyGeneration(t, "data2", dekNew.String())
	// ...and the old DEK does not open it.
	if _, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), "data2", false); err == nil {
		t.Fatal("old DEK must not open the new generation")
	}
	// The staged rotation key is gone.
	if _, err := e.store.Get(ctx, "repo/.keys/rotation-next.age"); err == nil {
		t.Fatal("staged DEK should be removed after rotation")
	}
}

func TestRotateResumesAfterBuildCrash(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	// First attempt: build only, then "crash".
	r1, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := r1.Build(ctx); err != nil {
		t.Fatal(err)
	}
	// The remote is untouched: still generation "data", old DEK works.
	if gen := kopiax.CurrentGeneration(ctx, e.store, "repo"); gen != "data" {
		t.Fatalf("generation flipped early: %q", gen)
	}
	e.verifyGeneration(t, "data", e.dekOld.String())

	// Second attempt resumes with the SAME staged DEK — if it generated a
	// fresh one, opening the half-built data2 would fail on password.
	r2, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := r2.Run(ctx); err != nil {
		t.Fatalf("resumed rotation failed: %v", err)
	}
	e.verifyGeneration(t, "data2", e.newDEK(t).String())
}

func TestRotatePostFlipCrashLeavesWorkingRemote(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Build(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rot.RewrapKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rot.Flip(ctx); err != nil {
		t.Fatal(err)
	}
	// "Crash" before Cleanup: the remote must already be fully working on
	// the new generation with the new key.
	if gen := kopiax.CurrentGeneration(ctx, e.store, "repo"); gen != "data2" {
		t.Fatalf("generation = %q", gen)
	}
	e.verifyGeneration(t, "data2", e.newDEK(t).String())
}

func TestSweepRemovesStaleGenerations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	// Debris from an old post-flip crash, visible through the store.
	e.store.Put(ctx, "repo/data9/p123", bytes.NewReader([]byte("junk")), 4)
	e.store.Put(ctx, "repo/data9/q456", bytes.NewReader([]byte("junk")), 4)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.SweepStaleGenerations(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Get(ctx, "repo/data9/p123"); err == nil {
		t.Fatal("stale generation debris should be swept")
	}
	// Keyring objects are untouched.
	if _, exists, _ := keyring.New(e.store, "repo").RepoRecipient(ctx); !exists {
		t.Fatal("sweep must not touch the keyring")
	}
}

func TestRefsChangedMidBuildAreResynced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Build(ctx); err != nil {
		t.Fatal(err)
	}

	// Someone pushes to the OLD generation after the first build pass.
	rep, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), "data", false)
	if err != nil {
		t.Fatal(err)
	}
	newSHA := "cccccccccccccccccccccccccccccccccccccccc"
	mustPush(t, rep, "refs/heads/main", newSHA, "bundle-main-v2")
	rep.Close(ctx)

	// A re-run of Build picks up the change before the flip.
	if err := rot.Build(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rot.RewrapKeys(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rot.Flip(ctx); err != nil {
		t.Fatal(err)
	}
	dekNew := e.newDEK(t)
	dst, err := kopiax.Open(ctx, e.cfg, dekNew.String(), "data2", false)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close(ctx)
	refs, err := dst.Refs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if refs["refs/heads/main"].SHA != newSHA {
		t.Fatalf("late push lost: %+v", refs["refs/heads/main"])
	}
}
