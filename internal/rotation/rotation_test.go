package rotation

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/kopia/kopia/repo/blob"
	"github.com/kopia/kopia/repo/blob/filesystem"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
	"github.com/osjupiter/git-remote-s3vault/internal/keyring"
	"github.com/osjupiter/git-remote-s3vault/internal/kopiax"
	"github.com/osjupiter/git-remote-s3vault/internal/snapshot"
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

const (
	shaMain      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaTopic     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	bundleV1     = "bundle-all-payload"
	bundleLater  = "bundle-all-v2"
	lateMainSHA  = "cccccccccccccccccccccccccccccccccccccccc"
)

type env struct {
	cfg    *config.Config
	store  *storage.Memory
	alice  *age.X25519Identity
	dekOld *age.X25519Identity
}

// newEnvBare wires the store, keyring, and filesystem-backed kopia blob
// storage but seeds no repository data.
func newEnvBare(t *testing.T) *env {
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
	return e
}

// newEnv seeds a v3 remote: keyring with alice granted, generation "data"
// holding a snapshot (two refs, HEAD, one all-refs bundle object).
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	e := newEnvBare(t)

	rep, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), kopiax.FirstGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := rep.WriteBundle(ctx, strings.NewReader(bundleV1))
	rep.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st := &snapshot.State{
		Refs:   map[string]string{"refs/heads/main": shaMain, "refs/heads/topic": shaTopic},
		Head:   "refs/heads/main",
		Bundle: oid,
	}
	if err := snapshot.Save(ctx, e.store, "repo", kopiax.FirstGeneration, st, e.dekOld.Recipient(), ""); err != nil {
		t.Fatal(err)
	}
	return e
}

// loadState decrypts gen's state record with the given DEK.
func (e *env) loadState(t *testing.T, gen string, dek *age.X25519Identity) *snapshot.State {
	t.Helper()
	st, _, err := snapshot.Load(context.Background(), e.store, "repo", gen, dek)
	if err != nil {
		t.Fatalf("loading state of %s: %v", gen, err)
	}
	if st == nil {
		t.Fatalf("no state record in %s", gen)
	}
	return st
}

// verifyGeneration checks that gen holds the seeded snapshot readable
// under password.
func (e *env) verifyGeneration(t *testing.T, gen, password string) {
	t.Helper()
	ctx := context.Background()
	dek, err := age.ParseX25519Identity(password)
	if err != nil {
		t.Fatal(err)
	}
	st := e.loadState(t, gen, dek)
	if st.Refs["refs/heads/main"] != shaMain || st.Refs["refs/heads/topic"] != shaTopic {
		t.Fatalf("refs wrong in %s: %+v", gen, st.Refs)
	}
	if st.Head != "refs/heads/main" {
		t.Fatalf("HEAD wrong in %s: %q", gen, st.Head)
	}
	rep, err := kopiax.Open(ctx, e.cfg, password, gen, false)
	if err != nil {
		t.Fatalf("opening %s: %v", gen, err)
	}
	defer rep.Close(ctx)
	rc, _, err := rep.OpenBundle(ctx, st.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != bundleV1 {
		t.Fatalf("bundle content wrong in %s: %q", gen, data)
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
	// ...and the old DEK does not open it (neither kopia nor the state).
	if _, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), "data2", false); err == nil {
		t.Fatal("old DEK must not open the new generation")
	}
	if _, _, err := snapshot.Load(ctx, e.store, "repo", "data2", e.dekOld); err == nil {
		t.Fatal("old DEK must not decrypt the new state record")
	}
	// The old generation's state record and the staged key are gone.
	if _, err := e.store.Get(ctx, "repo/state-data"); err == nil {
		t.Fatal("old state record should be removed after rotation")
	}
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

func TestFlipRefusesWhenGenerationChangedConcurrently(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Build(ctx); err != nil {
		t.Fatal(err)
	}

	// A concurrent rotation flips the pointer first.
	_, etag := kopiax.CurrentGenerationInfo(ctx, e.store, "repo")
	if err := kopiax.SetGeneration(ctx, e.store, "repo", "data5", etag); err != nil {
		t.Fatal(err)
	}

	// Our flip must fail loudly instead of clobbering it.
	err = rot.Flip(ctx)
	if err == nil || !strings.Contains(err.Error(), "another rotation") {
		t.Fatalf("expected a concurrent-rotation error, got %v", err)
	}
	if gen := kopiax.CurrentGeneration(ctx, e.store, "repo"); gen != "data5" {
		t.Fatalf("the concurrent flip must stand, got %q", gen)
	}
}

func TestSweepRemovesStaleGenerations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	// Debris from an old post-flip crash, visible through the store —
	// kopia blobs AND the generation's state record.
	e.store.Put(ctx, "repo/data9/p123", bytes.NewReader([]byte("junk")), 4)
	e.store.Put(ctx, "repo/data9/q456", bytes.NewReader([]byte("junk")), 4)
	e.store.Put(ctx, "repo/state-data9", bytes.NewReader([]byte("junk")), 4)

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
	if _, err := e.store.Get(ctx, "repo/state-data9"); err == nil {
		t.Fatal("stale state record should be swept")
	}
	// The active generation's state record and keyring are untouched.
	if _, err := e.store.Get(ctx, "repo/state-data"); err != nil {
		t.Fatal("sweep must not touch the active state record")
	}
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

	// Someone pushes to the OLD generation after the first build pass:
	// new bundle object, updated state record.
	rep, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), "data", false)
	if err != nil {
		t.Fatal(err)
	}
	oid, err := rep.WriteBundle(ctx, strings.NewReader(bundleLater))
	rep.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st, etag, err := snapshot.Load(ctx, e.store, "repo", "data", e.dekOld)
	if err != nil {
		t.Fatal(err)
	}
	st.Refs["refs/heads/main"] = lateMainSHA
	st.Bundle = oid
	if err := snapshot.Save(ctx, e.store, "repo", "data", st, e.dekOld.Recipient(), etag); err != nil {
		t.Fatal(err)
	}

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
	got := e.loadState(t, "data2", dekNew)
	if got.Refs["refs/heads/main"] != lateMainSHA {
		t.Fatalf("late push lost: %+v", got.Refs)
	}
	rep2, err := kopiax.Open(ctx, e.cfg, dekNew.String(), "data2", false)
	if err != nil {
		t.Fatal(err)
	}
	defer rep2.Close(ctx)
	rc, _, err := rep2.OpenBundle(ctx, got.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if string(data) != bundleLater {
		t.Fatalf("stale bundle copied: %q", data)
	}
}

// gitr runs git in dir with a fixed author for reproducibility.
func gitr(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestRotateMigratesPerRefRemote: a legacy v2 remote (one real bundle per
// ref, no state record) rotates into a v3 snapshot with all refs merged
// into one bundle.
func TestRotateMigratesPerRefRemote(t *testing.T) {
	ctx := context.Background()
	e := newEnvBare(t)

	// Build a real repository with two branches and per-ref bundles.
	work := t.TempDir()
	gitr(t, work, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(work, "f.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitr(t, work, "add", ".")
	gitr(t, work, "commit", "-q", "-m", "c1")
	mainSHA := gitr(t, work, "rev-parse", "main")
	gitr(t, work, "checkout", "-q", "-b", "topic")
	gitr(t, work, "commit", "-q", "--allow-empty", "-m", "c2")
	topicSHA := gitr(t, work, "rev-parse", "topic")

	mainBundle := filepath.Join(t.TempDir(), "main.bundle")
	topicBundle := filepath.Join(t.TempDir(), "topic.bundle")
	gitr(t, work, "bundle", "create", mainBundle, "refs/heads/main")
	gitr(t, work, "bundle", "create", topicBundle, "refs/heads/topic")

	rep, err := kopiax.Open(ctx, e.cfg, e.dekOld.String(), kopiax.FirstGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ name, sha, path string }{
		{"refs/heads/main", mainSHA, mainBundle},
		{"refs/heads/topic", topicSHA, topicBundle},
	} {
		f, err := os.Open(p.path)
		if err != nil {
			t.Fatal(err)
		}
		_, perr := rep.PushRef(ctx, p.name, p.sha, f, false)
		f.Close()
		if perr != nil {
			t.Fatal(perr)
		}
	}
	if err := rep.SetHead(ctx, "refs/heads/main"); err != nil {
		t.Fatal(err)
	}
	rep.Close(ctx)

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := rot.Run(ctx); err != nil {
		t.Fatal(err)
	}

	dekNew := e.newDEK(t)
	st := e.loadState(t, "data2", dekNew)
	if st.Refs["refs/heads/main"] != mainSHA || st.Refs["refs/heads/topic"] != topicSHA {
		t.Fatalf("migrated refs wrong: %+v", st.Refs)
	}
	if st.Head != "refs/heads/main" {
		t.Fatalf("migrated HEAD wrong: %q", st.Head)
	}

	// The merged bundle is a real git bundle advertising both refs under
	// their REAL names.
	rep2, err := kopiax.Open(ctx, e.cfg, dekNew.String(), "data2", false)
	if err != nil {
		t.Fatal(err)
	}
	defer rep2.Close(ctx)
	rc, _, err := rep2.OpenBundle(ctx, st.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	merged := filepath.Join(t.TempDir(), "merged.bundle")
	out, err := os.Create(merged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	out.Close()
	heads := gitr(t, work, "bundle", "list-heads", merged)
	for _, want := range []string{mainSHA + " refs/heads/main", topicSHA + " refs/heads/topic"} {
		if !strings.Contains(heads, want) {
			t.Fatalf("merged bundle missing %q:\n%s", want, heads)
		}
	}
}

// TestRotateRefusesTamperedKeyring: a slot planted with bucket write
// access (no DEK, so the seal cannot be re-computed) must abort rotation
// BEFORE any key is re-wrapped — rotation is the moment such a slot
// would be promoted to real access.
func TestRotateRefusesTamperedKeyring(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	evil, _ := age.GenerateX25519Identity()
	pub := evil.Recipient().String() + "\n"
	if err := e.store.Put(ctx, "repo/.keys/dek/evil.pub", strings.NewReader(pub), int64(len(pub))); err != nil {
		t.Fatal(err)
	}

	rot, err := New(ctx, e.cfg, e.store, e.dekOld, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	err = rot.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "integrity seal") {
		t.Fatalf("rotation over a tampered keyring must abort, got %v", err)
	}
	// The rogue slot must NOT have received a wrapped key.
	if _, err := e.store.Get(ctx, "repo/.keys/dek/evil.age"); err == nil {
		t.Fatal("rogue slot was re-wrapped despite the broken seal")
	}
	// The generation pointer must be untouched (abort happened pre-flip).
	if gen := kopiax.CurrentGeneration(ctx, e.store, "repo"); gen != "data" {
		t.Fatalf("generation must not flip on abort, got %q", gen)
	}
}
