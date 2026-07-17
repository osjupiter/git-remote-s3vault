package helper

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-r2/internal/config"
	"github.com/osjupiter/git-remote-r2/internal/keyring"
	"github.com/osjupiter/git-remote-r2/internal/storage"
)

// memStore is an in-memory storage.Storage for protocol-level tests.
type memStore struct {
	objects map[string][]byte
	mtimes  map[string]time.Time
	clock   time.Time
}

func newMemStore() *memStore {
	return &memStore{
		objects: map[string][]byte{},
		mtimes:  map[string]time.Time{},
		clock:   time.Unix(1_700_000_000, 0),
	}
}

func (m *memStore) List(_ context.Context, prefix string) ([]storage.Object, error) {
	var out []storage.Object
	for k, v := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, storage.Object{Key: k, Size: int64(len(v)), LastModified: m.mtimes[k]})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func (m *memStore) Get(_ context.Context, key string) (io.ReadCloser, error) {
	v, ok := m.objects[key]
	if !ok {
		return nil, fmt.Errorf("no such key %s", key)
	}
	return io.NopCloser(bytes.NewReader(v)), nil
}

func (m *memStore) Put(_ context.Context, key string, body io.Reader, _ int64) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.objects[key] = data
	m.clock = m.clock.Add(time.Second)
	m.mtimes[key] = m.clock
	return nil
}

func (m *memStore) Delete(_ context.Context, key string) error {
	delete(m.objects, key)
	delete(m.mtimes, key)
	return nil
}

func (m *memStore) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.objects[key]
	return ok, nil
}

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
	store *memStore
	cfg   *config.Config
	id    *age.X25519Identity
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// Isolate from the developer's real machine key and recipients file:
	// the helper's default-path fallbacks resolve via os.UserConfigDir.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &testEnv{
		store: newMemStore(),
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
	t.Chdir(repoDir)
	var out, errBuf bytes.Buffer
	h := New(e.cfg, e.store, strings.NewReader(input), &out, &errBuf)
	if err := h.Run(context.Background()); err != nil {
		t.Fatalf("helper session failed: %v\nstderr: %s\nstdout: %s", err, errBuf.String(), out.String())
	}
	return out.String()
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

func TestProgressOutput(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)

	// Default verbosity: pushing narrates the slow steps on stderr.
	_, stderr := e.runSessionErr(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	for _, want := range []string{"bundling refs/heads/main", "uploading refs/heads/main", "encrypted"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("progress output missing %q:\n%s", want, stderr)
		}
	}

	// Fetch narrates download and decryption.
	sha := git(t, src, "rev-parse", "HEAD")
	dst := t.TempDir()
	git(t, dst, "init", "-q", "-b", "main")
	_, stderr = e.runSessionErr(t, dst, fmt.Sprintf("list\nfetch %s refs/heads/main\n\n", sha))
	for _, want := range []string{"downloading refs/heads/main", "decrypting"} {
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

func TestCapabilities(t *testing.T) {
	e := newTestEnv(t)
	out := e.runSession(t, newRepoWithCommit(t), "capabilities\n\n")
	for _, cap := range []string{"fetch", "push", "option"} {
		if !strings.Contains(out, cap+"\n") {
			t.Errorf("capabilities output missing %q: %q", cap, out)
		}
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

	// The stored bundle must be encrypted and carry the .age suffix.
	wantKey := "repo/refs/heads/main/" + sha + ".bundle.age"
	data, ok := e.store.objects[wantKey]
	if !ok {
		t.Fatalf("bundle not stored at %s; have %v", wantKey, keys(e.store))
	}
	if !bytes.HasPrefix(data, []byte("age-encryption.org/")) {
		t.Fatalf("stored object is not an age ciphertext: %q...", data[:min(32, len(data))])
	}
	if head := string(e.store.objects["repo/HEAD"]); head != "refs/heads/main" {
		t.Fatalf("HEAD object = %q", head)
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

	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "error refs/heads/main") || !strings.Contains(out, "non-fast-forward") {
		t.Fatalf("non-fast-forward push should be rejected: %q", out)
	}

	out = e.runSession(t, src, "list for-push\npush +refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("force push should succeed: %q", out)
	}

	// Only one bundle remains after the force push replaced the old one.
	if n := countBundles(e.store, "repo/refs/heads/main/"); n != 1 {
		t.Fatalf("expected exactly 1 bundle after force push, got %d: %v", n, keys(e.store))
	}
}

func TestFastForwardPushReplacesOldBundle(t *testing.T) {
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
	if n := countBundles(e.store, "repo/refs/heads/main/"); n != 1 {
		t.Fatalf("stale bundle not cleaned up: %v", keys(e.store))
	}
	if _, ok := e.store.objects["repo/refs/heads/main/"+sha2+".bundle.age"]; !ok {
		t.Fatalf("new bundle missing: %v", keys(e.store))
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
	if n := countBundles(e.store, "repo/refs/heads/dev/"); n != 0 {
		t.Fatalf("ref dir not emptied: %v", keys(e.store))
	}
	// main and its HEAD pointer survive.
	if head := string(e.store.objects["repo/HEAD"]); head != "refs/heads/main" {
		t.Fatalf("HEAD = %q after deleting dev", head)
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
	if n := countBundles(e.store, "repo/"); n != 0 {
		t.Fatal("nothing should have been uploaded")
	}
}

func TestFirstPushInitializesKeyring(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	pub, ok := e.store.objects["repo/.keys/repo.pub"]
	if !ok {
		t.Fatalf("repo.pub not created: %v", keys(e.store))
	}
	if !strings.HasPrefix(strings.TrimSpace(string(pub)), "age1") {
		t.Fatalf("repo.pub is not an age public key: %q", pub)
	}
	// Exactly one wrapped DEK slot (for the pusher's own key) + its .pub.
	var slots int
	for k := range e.store.objects {
		if strings.HasPrefix(k, "repo/.keys/dek/") && strings.HasSuffix(k, ".age") {
			slots++
		}
	}
	if slots != 1 {
		t.Fatalf("expected 1 wrapped DEK slot, got %d: %v", slots, keys(e.store))
	}
}

// TestGrantAllowsFetchWithoutRepush is the point of envelope encryption:
// wrapping the DEK for a new member makes ALL existing history readable to
// them, with zero changes to the stored bundles.
func TestGrantAllowsFetchWithoutRepush(t *testing.T) {
	e := newTestEnv(t)
	src := newRepoWithCommit(t)
	sha := git(t, src, "rev-parse", "HEAD")
	e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")

	bundleKey := "repo/refs/heads/main/" + sha + ".bundle.age"
	before := append([]byte{}, e.store.objects[bundleKey]...)

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

	// The stored bundle was not touched by the grant.
	if !bytes.Equal(before, e.store.objects[bundleKey]) {
		t.Fatal("grant must not rewrite existing bundles")
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

func TestPlaintextModeWhenExplicitlyDisabled(t *testing.T) {
	e := newTestEnv(t)
	e.cfg.Encryption = config.EncryptionNone
	e.cfg.Recipients = nil
	src := newRepoWithCommit(t)
	sha := git(t, src, "rev-parse", "HEAD")

	out := e.runSession(t, src, "list for-push\npush refs/heads/main:refs/heads/main\n\n")
	if !strings.Contains(out, "ok refs/heads/main\n") {
		t.Fatalf("plaintext push failed: %q", out)
	}
	key := "repo/refs/heads/main/" + sha + ".bundle"
	if _, ok := e.store.objects[key]; !ok {
		t.Fatalf("plaintext bundle missing at %s: %v", key, keys(e.store))
	}
}

func keys(m *memStore) []string {
	var ks []string
	for k := range m.objects {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func countBundles(m *memStore, prefix string) int {
	n := 0
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) && strings.Contains(k, ".bundle") {
			n++
		}
	}
	return n
}
