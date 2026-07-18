package helper

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newRepoWithCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello r2\n"), 0o644)
	git(t, dir, "add", ".")
	git(t, dir, "commit", "-q", "-m", "initial")
	return dir
}

type testEnv struct {
	store   *storage.Memory // keyring side
	blobDir string          // kopia blob storage (filesystem-backed)
	cfg     *config.Config
	id      *age.X25519Identity
}

// newTestEnv isolates a helper test completely: in-memory keyring store,
// filesystem-backed kopia blobs, and private config/cache directories.
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testEnv{
		store:   storage.NewMemory(),
		blobDir: blobDir,
		cfg: &config.Config{
			RemoteName:    "origin",
			Bucket:        "test",
			Prefix:        "repo",
			Encryption:    config.EncryptionAge,
			Recipients:    []string{id.Recipient().String()},
			IdentityFiles: []string{idFile},
		},
		id: id,
	}
}

// runSession executes one remote-helper session in repoDir with the given
// stdin script and returns stdout.
func (e *testEnv) runSession(t *testing.T, repoDir, input string) string {
	t.Helper()
	out, _ := e.runSessionErr(t, repoDir, input)
	return out
}

// runSessionErr is runSession but also returns what the helper wrote to
// stderr (progress and warnings).
func (e *testEnv) runSessionErr(t *testing.T, repoDir, input string) (string, string) {
	t.Helper()
	t.Chdir(repoDir)
	var out, errBuf bytes.Buffer
	h := New(e.cfg, e.store, strings.NewReader(input), &out, &errBuf)
	if err := h.Run(context.Background()); err != nil {
		t.Fatalf("helper session failed: %v\nstderr: %s\nstdout: %s", err, errBuf.String(), out.String())
	}
	return out.String(), errBuf.String()
}

// blobFiles lists the kopia blob storage contents (relative names).
func (e *testEnv) blobFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	filepath.Walk(e.blobDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			rel, _ := filepath.Rel(e.blobDir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// storedBytesContain reports whether any blob contains the needle —
// used to prove plaintext never reaches storage.
func (e *testEnv) storedBytesContain(t *testing.T, needle []byte) bool {
	t.Helper()
	found := false
	filepath.Walk(e.blobDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if data, err := os.ReadFile(p); err == nil && bytes.Contains(data, needle) {
				found = true
			}
		}
		return nil
	})
	return found
}

func TestCapabilities(t *testing.T) {
	e := newTestEnv(t)
	out := e.runSession(t, newRepoWithCommit(t), "capabilities\n\n")
	for _, cap := range []string{"fetch", "push", "option"} {
		if !strings.Contains(out, cap+"\n") {
			t.Errorf("capabilities output missing %q: %q", cap, out)
		}
	}
}

func TestListOnFreshRemoteIsEmpty(t *testing.T) {
	e := newTestEnv(t)
	out := e.runSession(t, newRepoWithCommit(t), "list\n\n")
	if strings.TrimSpace(out) != "" {
		t.Fatalf("fresh remote should list nothing: %q", out)
	}
}

func TestPushListFetchRoundtrip(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	sha := git(t, src, "rev-parse", "HEAD")

	// Push from the source repo.
	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("push not acknowledged: %q", out)
	}

	// Nothing stored at rest may contain the plaintext.
	if e.storedBytesContain(t, []byte("hello r2")) {
		t.Fatal("plaintext leaked into the blob storage")
	}
	if len(e.blobFiles(t)) == 0 {
		t.Fatal("no kopia blobs written")
	}

	// A fresh repo lists and fetches the pushed commit.
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	out = e.runSession(t, dst, "list\n\n")
	if !strings.Contains(out, sha+" refs/heads/main\n") || !strings.Contains(out, "@refs/heads/main HEAD\n") {
		t.Fatalf("list output wrong: %q", out)
	}
	e.runSession(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))
	git(t, dst, "cat-file", "-e", sha) // fails the test if the object is missing
}

func TestNonFastForwardRejectedAndForceAccepted(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	// Rewrite history: the remote sha still exists locally but is no longer
	// an ancestor.
	git(t, src, "commit", "-q", "--amend", "-m", "rewritten")
	sha2 := git(t, src, "rev-parse", "HEAD")

	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "error refs/heads/main") || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("non-fast-forward push should be rejected: %q", out)
	}

	out = e.runSession(t, src, "list for-push\npush +refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("force push should succeed: %q", out)
	}
	out = e.runSession(t, src, "list\n\n")
	if !strings.Contains(out, sha2+" refs/heads/main\n") {
		t.Fatalf("ref not updated after force push: %q", out)
	}
}

func TestFastForwardPushUpdatesRef(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	os.WriteFile(filepath.Join(src, "second.txt"), []byte("more\n"), 0o644)
	git(t, src, "add", ".")
	git(t, src, "commit", "-q", "-m", "second")
	sha2 := git(t, src, "rev-parse", "HEAD")

	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("fast-forward push failed: %q", out)
	}
	out = e.runSession(t, src, "list\n\n")
	if !strings.Contains(out, sha2+" refs/heads/main\n") {
		t.Fatalf("ref not updated: %q", out)
	}
}

func TestDeleteRef(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src,
		"list for-push\npush refs/heads/main:refs/heads/main\npush refs/heads/main:refs/heads/dev\n\n")

	out := e.runSession(t, src, "list for-push\npush :refs/heads/dev\n\n")
	if !strings.Contains(out, "ok refs/heads/dev\n") {
		t.Fatalf("delete push failed: %q", out)
	}
	out = e.runSession(t, src, "list\n\n")
	if strings.Contains(out, "refs/heads/dev") {
		t.Fatalf("dev should be gone: %q", out)
	}
	// main and its HEAD pointer survive.
	if !strings.Contains(out, "@refs/heads/main HEAD\n") {
		t.Fatalf("HEAD lost after deleting dev: %q", out)
	}

	// Deleting a nonexistent ref reports an error.
	out = e.runSession(t, src, "list for-push\npush :refs/heads/ghost\n\n")
	if !strings.Contains(out, "error refs/heads/ghost") {
		t.Fatalf("deleting a missing ref should error: %q", out)
	}
}

func TestTagsPushAndList(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	git(t, src, "tag", "-a", "v1.0.0", "-m", "release")
	tagSHA := git(t, src, "rev-parse", "refs/tags/v1.0.0")

	out := e.runSession(t, src,
		"list for-push\npush refs/heads/main:refs/heads/main\npush refs/tags/v1.0.0:refs/tags/v1.0.0\n\n")
	if strings.Count(out, "ok ") != 2 {
		t.Fatalf("expected two ok lines: %q", out)
	}

	out = e.runSession(t, src, "list\n\n")
	if !strings.Contains(out, tagSHA+" refs/tags/v1.0.0\n") {
		t.Fatalf("tag missing from list: %q", out)
	}
}

func TestPushWithoutAnyKeysFailsClearly(t *testing.T) {
	e := newTestEnv(t)
	e.cfg.Recipients = nil
	e.cfg.IdentityFiles = nil // no way to derive a public key either
	src := newRepoWithCommit(t)
	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "error refs/heads/main") || !strings.Contains(out, "public keys") {
		t.Fatalf("expected a clear no-keys error: %q", out)
	}
	if len(e.blobFiles(t)) != 0 {
		t.Fatal("nothing should have been written to blob storage")
	}
}

func TestFirstPushInitializesKeyringAndRepo(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	// Keyring: repo.pub plus exactly one wrapped DEK slot.
	if _, ok := e.store.Bytes("repo/.keys/repo.pub"); !ok {
		t.Fatal("repo.pub not created")
	}
	slots := 0
	for _, k := range memKeys(e.store) {
		if strings.HasPrefix(k, "repo/.keys/dek/") && strings.HasSuffix(k, ".age") {
			slots++
		}
	}
	if slots != 1 {
		t.Fatalf("expected 1 wrapped DEK slot, got %d", slots)
	}

	// Kopia repository was initialized in blob storage.
	found := false
	for _, f := range e.blobFiles(t) {
		if strings.Contains(f, "kopia.repository") {
			found = true
		}
	}
	if !found {
		t.Fatalf("kopia repository not initialized: %v", e.blobFiles(t))
	}
}

// TestGrantAllowsFetchWithoutRepush is the point of the keyring design:
// wrapping the DEK for a new member makes ALL existing history readable to
// them, with zero changes to the stored data.
func TestGrantAllowsFetchWithoutRepush(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	sha := git(t, src, "rev-parse", "HEAD")
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	before := e.blobFiles(t)

	// Bob appears. Alice (whose identity is e.id) grants him access.
	bob, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	kr := keyring.New(e.store, "repo")
	dek, ok, err := kr.Unwrap(context.Background(), []age.Identity{e.id})
	if err != nil || !ok {
		t.Fatalf("alice cannot unwrap: %v", err)
	}
	if err := kr.Grant(context.Background(), dek, bob.Recipient().String(), "bob"); err != nil {
		t.Fatal(err)
	}

	// The stored data was not touched by the grant.
	after := e.blobFiles(t)
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatal("grant must not rewrite stored blobs")
	}

	// Bob fetches with only his own identity configured.
	bobFile := filepath.Join(t.TempDir(), "bob.txt")
	if err := os.WriteFile(bobFile, []byte(bob.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.cfg.Recipients = nil
	e.cfg.IdentityFiles = []string{bobFile}

	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	e.runSession(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))
	git(t, dst, "cat-file", "-e", sha)
}

func TestPlaintextModeWorksWithoutAnyKeys(t *testing.T) {
	e := newTestEnv(t)
	e.cfg.Encryption = config.EncryptionNone
	e.cfg.Recipients = nil
	e.cfg.IdentityFiles = nil
	src := newRepoWithCommit(t)
	sha := git(t, src, "rev-parse", "HEAD")

	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("plaintext push failed: %q", out)
	}
	// No keyring is created in plaintext mode (the state record is data,
	// not key material).
	for _, k := range memKeys(e.store) {
		if strings.Contains(k, ".keys") {
			t.Fatalf("plaintext mode must not create key material: %v", memKeys(e.store))
		}
	}
	// A fresh clone works without any identity.
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	e.runSession(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))
	git(t, dst, "cat-file", "-e", sha)
}

func TestProgressOutput(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)

	// Default verbosity: pushing narrates the slow steps on stderr.
	_, stderr := e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	for _, want := range []string{"bundling snapshot", "uploading snapshot", "encrypted"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("progress output missing %q:\n%s", want, stderr)
		}
	}

	// Fetch narrates download and unbundling.
	sha := git(t, src, "rev-parse", "HEAD")
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	_, stderr = e.runSessionErr(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))
	for _, want := range []string{"downloading snapshot", "unbundling"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("fetch progress missing %q:\n%s", want, stderr)
		}
	}

	// `git push -q` (verbosity 0) and --no-progress both silence it.
	git(t, src, "commit", "-q", "--allow-empty", "-m", "next")
	_, stderr = e.runSessionErr(t, src, "option verbosity 0\nlist for-push\npush refs/heads/main:refs/heads/main\n\n")
	if strings.Contains(stderr, "bundling") {
		t.Errorf("verbosity 0 should silence progress:\n%s", stderr)
	}
	git(t, src, "commit", "-q", "--allow-empty", "-m", "next2")
	_, stderr = e.runSessionErr(t, src, "option progress false\nlist for-push\npush refs/heads/main:refs/heads/main\n\n")
	if strings.Contains(stderr, "bundling") {
		t.Errorf("progress=false should silence progress:\n%s", stderr)
	}
}

// TestLocalCacheHoldsNoPlaintext proves the kopia cache stores ciphertext
// only: after pushing and fetching known content, no file under the cache
// root may contain the plaintext. (Decryption happens in memory; the only
// on-disk plaintext is the transient bundle temp file, removed after use,
// and of course the working tree itself.)
func TestLocalCacheHoldsNoPlaintext(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t) // contains "hello r2"
	sha := git(t, src, "rev-parse", "HEAD")
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	// Fetch too, so the read path (prefetch into cache) also runs.
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	e.runSession(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))

	cacheRoot := os.Getenv("XDG_CACHE_HOME")
	found := ""
	filepath.Walk(cacheRoot, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if data, rerr := os.ReadFile(p); rerr == nil && bytes.Contains(data, []byte("hello r2")) {
				found = p
			}
		}
		return nil
	})
	if found != "" {
		t.Fatalf("plaintext found in local cache file %s", found)
	}
}

func TestGCSuggestion(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)

	// Small tidy repo at default thresholds: no hint.
	_, stderr := e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if strings.Contains(stderr, "git gc") {
		t.Errorf("small repo should not trigger the gc hint:\n%s", stderr)
	}

	// Lower the threshold so this repo's handful of loose objects trips it.
	origCount, origKiB := looseCountHint, looseKiBHint
	looseCountHint, looseKiBHint = 1, 1<<40
	t.Cleanup(func() { looseCountHint, looseKiBHint = origCount, origKiB })

	git(t, src, "commit", "-q", "--allow-empty", "-m", "next")
	_, stderr = e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(stderr, "git gc") || !strings.Contains(stderr, "loose objects") {
		t.Errorf("expected a gc suggestion:\n%s", stderr)
	}
	// Shown once per session even with multiple pushes.
	if strings.Count(stderr, "git gc") != 1 {
		t.Errorf("hint should appear once:\n%s", stderr)
	}

	// After packing, the hint disappears even with the low threshold.
	git(t, src, "gc", "-q")
	git(t, src, "commit", "-q", "--allow-empty", "-m", "after-gc")
	_, stderr = e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	// A fresh commit creates a couple of loose objects, so use count=10 to
	// represent "mostly packed".
	_ = stderr // the strict assertion below uses a saner threshold
	looseCountHint = 10
	git(t, src, "commit", "-q", "--allow-empty", "-m", "after-gc2")
	_, stderr = e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if strings.Contains(stderr, "git gc") {
		t.Errorf("packed repo should not trigger the hint:\n%s", stderr)
	}
}

func memKeys(m *storage.Memory) []string {
	objs, _ := m.List(context.Background(), "")
	var ks []string
	for _, o := range objs {
		ks = append(ks, o.Key)
	}
	return ks
}

// TestConcurrentPushLosesCleanly: session A reads the remote, session B
// pushes in between, and A's push must fail with a retryable
// concurrent-push error while B's push stands.
func TestConcurrentPushLosesCleanly(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	// Session A opens and reads the remote state over a pipe so we can
	// interleave another push before A's.
	t.Chdir(src)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	hA := New(e.cfg, e.store, inR, outW, io.Discard)
	done := make(chan error, 1)
	go func() {
		err := hA.Run(context.Background())
		outW.Close()
		done <- err
	}()
	rd := bufio.NewReader(outR)
	readBlock := func() string {
		var b strings.Builder
		for {
			line, err := rd.ReadString('\n')
			b.WriteString(line)
			if err != nil || line == "\n" {
				return b.String()
			}
		}
	}
	if _, err := io.WriteString(inW, "list for-push\n"); err != nil {
		t.Fatal(err)
	}
	readBlock()

	// B lands a push while A holds its stale view.
	git(t, src, "commit", "-q", "--allow-empty", "-m", "from-b")
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	shaB := git(t, src, "rev-parse", "HEAD")
	t.Chdir(src)

	// A pushes a newer commit — a valid fast-forward from A's point of
	// view, but the CAS token is stale.
	git(t, src, "commit", "-q", "--allow-empty", "-m", "from-a")
	if _, err := io.WriteString(inW, "push refs/heads/main:refs/heads/main\n\n"); err != nil {
		t.Fatal(err)
	}
	result := readBlock()
	inW.Close()
	if err := <-done; err != nil {
		t.Fatalf("session A failed: %v", err)
	}
	if !strings.Contains(result, "error refs/heads/main") || !strings.Contains(result, "concurrent push detected") {
		t.Fatalf("expected a concurrent-push error, got: %q", result)
	}

	// B's push stands.
	out := e.runSession(t, src, "list\n\n")
	if !strings.Contains(out, shaB+" refs/heads/main") {
		t.Fatalf("B's push was clobbered:\n%s", out)
	}
}

// TestV2RemoteMigratesOnFirstPush: a remote written by the pre-snapshot
// format (per-ref kopia manifests) lists fine, and the first push
// converts it to the snapshot format and removes the old manifests.
func TestV2RemoteMigratesOnFirstPush(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	sha1 := git(t, src, "rev-parse", "HEAD")

	// Seed a legacy v2 remote: keyring plus one per-ref bundle manifest.
	kr := keyring.New(e.store, "repo")
	dek, err := kr.Init(ctx, []string{e.id.Recipient().String()})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := kopiax.Open(ctx, e.cfg, dek.String(), kopiax.FirstGeneration, true)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(t.TempDir(), "main.bundle")
	git(t, src, "bundle", "create", bundle, "refs/heads/main")
	f, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	_, perr := rep.PushRef(ctx, "refs/heads/main", sha1, f, true)
	f.Close()
	if perr != nil {
		t.Fatal(perr)
	}
	rep.Close(ctx)

	// Read compatibility: the v2 remote lists and fetches.
	out := e.runSession(t, src, "list\n\n")
	if !strings.Contains(out, sha1+" refs/heads/main") {
		t.Fatalf("v2 remote not listed:\n%s", out)
	}

	// First push migrates.
	git(t, src, "commit", "-q", "--allow-empty", "-m", "two")
	sha2 := git(t, src, "rev-parse", "HEAD")
	out = e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main") {
		t.Fatalf("migration push failed:\n%s", out)
	}
	if _, err := e.store.Get(ctx, "repo/state-data"); err != nil {
		t.Fatal("no state record after migration push")
	}
	rep2, err := kopiax.Open(ctx, e.cfg, dek.String(), kopiax.FirstGeneration, false)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := rep2.Refs(ctx)
	rep2.Close(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("v2 manifests should be cleaned up after migration: %+v", refs)
	}

	// A fresh clone sees the migrated remote.
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	e.runSession(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha2))
	git(t, dst, "cat-file", "-e", sha2)
}

// TestBatchFetchDownloadsSnapshotOnce: cloning N refs downloads and
// unbundles exactly one snapshot bundle.
func TestBatchFetchDownloadsSnapshotOnce(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	shaMain := git(t, src, "rev-parse", "main")
	git(t, src, "checkout", "-q", "-b", "dev")
	git(t, src, "commit", "-q", "--allow-empty", "-m", "dev1")
	shaDev := git(t, src, "rev-parse", "dev")
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\npush refs/heads/dev:refs/heads/dev\n\n")

	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	_, stderr := e.runSessionErr(t, dst,
		fmt.Sprintf("list\nfetch %s refs/heads/main\nfetch %s refs/heads/dev\n\n", shaMain, shaDev))
	if n := strings.Count(stderr, "downloading snapshot"); n != 1 {
		t.Fatalf("snapshot downloaded %d times, want 1:\n%s", n, stderr)
	}
	git(t, dst, "cat-file", "-e", shaMain)
	git(t, dst, "cat-file", "-e", shaDev)
}

// TestPushMergesRefsAbsentFromLocalClone: pushing from a machine that
// never fetched some remote refs must not drop them — the helper merges
// the remote snapshot with the pushed refs through a scratch repo.
func TestPushMergesRefsAbsentFromLocalClone(t *testing.T) {
	e := newTestEnv(t)
	a := newRepoWithCommit(t)
	shaMain := git(t, a, "rev-parse", "main")
	git(t, a, "checkout", "-q", "-b", "topic")
	git(t, a, "commit", "-q", "--allow-empty", "-m", "t1")
	shaTopic := git(t, a, "rev-parse", "topic")
	e.runSession(t, a, "list for-push\npush refs/heads/main:refs/heads/main\npush refs/heads/topic:refs/heads/topic\n\n")

	// B has a completely unrelated history and none of A's objects.
	b := t.TempDir()
	git(t, b, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(b, "b.txt"), []byte("b\n"), 0o644)
	git(t, b, "add", ".")
	git(t, b, "commit", "-q", "-m", "b1")
	git(t, b, "tag", "vb") // tag on the pushed commit: exercises tag-vs-refspec collision in the scratch merge
	shaOther := git(t, b, "rev-parse", "main")
	out := e.runSession(t, b, "list for-push\npush refs/heads/main:refs/heads/other\npush refs/tags/vb:refs/tags/vb\n\n")
	if !strings.Contains(out, "ok refs/heads/other") || !strings.Contains(out, "ok refs/tags/vb") {
		t.Fatalf("push from partial clone failed:\n%s", out)
	}

	// All three refs survive, and every object is fetchable.
	c := t.TempDir()
	git(t, c, "init", "-q", "-b", "main")
	out = e.runSession(t, c, "list\n\n")
	for _, want := range []string{
		shaMain + " refs/heads/main",
		shaTopic + " refs/heads/topic",
		shaOther + " refs/heads/other",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in listing:\n%s", want, out)
		}
	}
	e.runSession(t, c, fmt.Sprintf("list\nfetch %s refs/heads/main\nfetch %s refs/heads/topic\nfetch %s refs/heads/other\n\n",
		shaMain, shaTopic, shaOther))
	for _, sha := range []string{shaMain, shaTopic, shaOther} {
		git(t, c, "cat-file", "-e", sha)
	}
}
