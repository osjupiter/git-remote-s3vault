// Package e2e exercises the compiled git-remote-s3ee binary end-to-end
// against a real S3-compatible backend (MinIO in a testcontainer), driving
// it exactly the way users do: through git push / clone / pull.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/testcontainers/testcontainers-go"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

const bucket = "git-remotes"

type harness struct {
	binDir   string
	endpoint string
	username string
	password string
	s3c      *s3.Client
	baseEnv  []string
	identity *age.X25519Identity
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

	// Compile the helper binary that git will discover on PATH.
	binDir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(binDir, "git-remote-s3ee"), "../cmd/git-remote-s3ee")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building helper: %v\n%s", err, out)
	}

	minioC, err := tcminio.Run(ctx, "minio/minio:RELEASE.2024-01-16T16-07-38Z")
	if err != nil {
		t.Fatalf("starting minio: %v", err)
	}
	t.Cleanup(func() { testcontainers.TerminateContainer(minioC) })

	endpoint, err := minioC.ConnectionString(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpoint = "http://" + endpoint

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(minioC.Username, minioC.Password, "")),
	)
	if err != nil {
		t.Fatal(err)
	}
	s3c := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
	if _, err := s3c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("creating bucket: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	h := &harness{
		binDir: binDir, endpoint: endpoint, s3c: s3c, identity: id,
		username: minioC.Username, password: minioC.Password,
	}
	h.baseEnv = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"AWS_ENDPOINT_URL="+endpoint,
		"AWS_ACCESS_KEY_ID="+minioC.Username,
		"AWS_SECRET_ACCESS_KEY="+minioC.Password,
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS="+id.Recipient().String(),
		"GIT_REMOTE_S3EE_AGE_IDENTITY_FILE="+idFile,
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.com",
		// Isolate from the developer's real git config.
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"HOME="+t.TempDir(),
	)
	return h
}

func (h *harness) git(t *testing.T, dir string, extraEnv []string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(append([]string{}, h.baseEnv...), extraEnv...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func (h *harness) mustGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := h.git(t, dir, nil, args...)
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return out
}

func (h *harness) listKeys(t *testing.T, prefix string) []string {
	t.Helper()
	resp, err := h.s3c.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, o := range resp.Contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys
}

// storedBytesContain downloads every object under prefix and reports
// whether any contains needle (proves plaintext never reaches storage).
func (h *harness) storedBytesContain(t *testing.T, prefix string, needle []byte) bool {
	t.Helper()
	for _, k := range h.listKeys(t, prefix) {
		obj, err := h.s3c.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(k),
		})
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(obj.Body)
		obj.Body.Close()
		if bytes.Contains(data, needle) {
			return true
		}
	}
	return false
}

// bucketSize sums object sizes under prefix.
func (h *harness) bucketSize(t *testing.T, prefix string) int64 {
	t.Helper()
	var total int64
	resp, err := h.s3c.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket), Prefix: aws.String(prefix),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range resp.Contents {
		total += aws.ToInt64(o.Size)
	}
	return total
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/project"

	// --- push from a fresh repository ---
	alice := t.TempDir()
	h.mustGit(t, alice, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(alice, "README.md"), []byte("# hello via r2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, alice, "add", ".")
	h.mustGit(t, alice, "commit", "-q", "-m", "initial commit")
	h.mustGit(t, alice, "remote", "add", "origin", remoteURL)
	h.mustGit(t, alice, "push", "origin", "main")

	// --- everything at rest is opaque and never contains plaintext ---
	keys := h.listKeys(t, "project/data/")
	if len(keys) == 0 {
		t.Fatalf("no kopia blobs stored under project/data/: %v", h.listKeys(t, "project/"))
	}
	for _, k := range keys {
		if strings.Contains(k, "bundle") || strings.Contains(k, "refs") || strings.Contains(k, "main") {
			t.Fatalf("storage key leaks git semantics: %s", k)
		}
	}
	if h.storedBytesContain(t, "project/data/", []byte("hello via r2")) {
		t.Fatal("plaintext leaked into stored objects")
	}

	// --- clone into a second working copy ---
	work := t.TempDir()
	bob := filepath.Join(work, "bob")
	if out, err := h.git(t, work, nil, "clone", "-q", remoteURL, "bob"); err != nil {
		t.Fatalf("clone failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(bob, "README.md"))
	if err != nil || string(data) != "# hello via r2\n" {
		t.Fatalf("cloned content wrong: %q, %v", data, err)
	}

	// --- push from the clone, pull back into the original ---
	if err := os.WriteFile(filepath.Join(bob, "feature.txt"), []byte("bob was here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, bob, "add", ".")
	h.mustGit(t, bob, "commit", "-q", "-m", "bob adds a feature")
	h.mustGit(t, bob, "push", "-q", "origin", "main")

	h.mustGit(t, alice, "pull", "-q", "origin", "main")
	if _, err := os.Stat(filepath.Join(alice, "feature.txt")); err != nil {
		t.Fatalf("pull did not bring bob's commit: %v", err)
	}

	// --- non-fast-forward is rejected, force push wins ---
	h.mustGit(t, alice, "commit", "-q", "--amend", "-m", "rewritten history")
	if out, err := h.git(t, alice, nil, "push", "origin", "main"); err == nil {
		t.Fatalf("non-fast-forward push should fail:\n%s", out)
	}
	h.mustGit(t, alice, "push", "--force", "origin", "main")

	// --- tags round-trip ---
	h.mustGit(t, bob, "tag", "v0.1.0")
	h.mustGit(t, bob, "push", "origin", "v0.1.0")
	carol := filepath.Join(work, "carol")
	if out, err := h.git(t, work, nil, "clone", "-q", remoteURL, "carol"); err != nil {
		t.Fatalf("second clone failed: %v\n%s", err, out)
	}
	if tags := strings.TrimSpace(h.mustGit(t, carol, "tag", "-l")); tags != "v0.1.0" {
		t.Fatalf("tags = %q", tags)
	}

	// --- branch delete removes the ref ---
	h.mustGit(t, bob, "checkout", "-q", "-b", "topic")
	h.mustGit(t, bob, "push", "-q", "origin", "topic")
	if refs := h.mustGit(t, bob, "ls-remote", "origin"); !strings.Contains(refs, "refs/heads/topic") {
		t.Fatalf("topic branch not pushed:\n%s", refs)
	}
	h.mustGit(t, bob, "push", "-q", "origin", ":topic")
	if refs := h.mustGit(t, bob, "ls-remote", "origin"); strings.Contains(refs, "refs/heads/topic") {
		t.Fatalf("topic branch still listed after delete:\n%s", refs)
	}
}

func TestCloneWithoutIdentityFails(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/locked"

	src := t.TempDir()
	h.mustGit(t, src, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(src, "secret.txt"), []byte("classified\n"), 0o644)
	h.mustGit(t, src, "add", ".")
	h.mustGit(t, src, "commit", "-q", "-m", "secret")
	h.mustGit(t, src, "remote", "add", "origin", remoteURL)
	h.mustGit(t, src, "push", "-q", "origin", "main")

	work := t.TempDir()
	out, err := h.git(t, work, []string{"GIT_REMOTE_S3EE_AGE_IDENTITY_FILE="}, "clone", remoteURL, "mallory")
	if err == nil {
		t.Fatalf("clone without an age identity must fail:\n%s", out)
	}
	if !strings.Contains(out, "identity") {
		t.Logf("clone failed as expected (output: %s)", firstLine(out))
	}
}

func TestPushTimingSanity(t *testing.T) {
	// Guards against accidentally re-bundling the world on every helper
	// invocation: a no-op push should finish quickly.
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/timing"

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o644)
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")
	h.mustGit(t, repo, "remote", "add", "origin", remoteURL)
	h.mustGit(t, repo, "push", "-q", "origin", "main")

	start := time.Now()
	out := h.mustGit(t, repo, "push", "origin", "main")
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("no-op push took %v:\n%s", d, out)
	}
	if !strings.Contains(out, "Everything up-to-date") {
		t.Logf("note: second push output: %s", firstLine(out))
	}
}

// TestSetupCommandFlow provisions a repo with `git-remote-s3ee setup` alone —
// no manual key generation, no env-provided age configuration — then pushes
// and clones with what setup wrote.
func TestSetupCommandFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/via-setup"

	// Drop the env-based age config so only setup's output is in play; keep
	// endpoint + credentials. XDG_CONFIG_HOME hosts the generated identity.
	cfgHome := t.TempDir()
	env := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=",
		"GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("setup flow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "first")

	setup := exec.Command(filepath.Join(h.binDir, "git-remote-s3ee"), "setup", remoteURL)
	setup.Dir = repo
	setup.Env = append(append([]string{}, h.baseEnv...), env...)
	out, err := setup.CombinedOutput()
	if err != nil {
		t.Fatalf("setup command failed: %v\n%s", err, out)
	}
	for _, want := range []string{"generated this machine's key", "bucket reachable", "git push -u origin"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("setup output missing %q:\n%s", want, out)
		}
	}

	if gout, err := h.git(t, repo, env, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("push after setup failed: %v\n%s", err, gout)
	}

	// Data landed encrypted under the kopia prefix.
	if len(h.listKeys(t, "via-setup/data/")) == 0 {
		t.Fatalf("no data stored: %v", h.listKeys(t, "via-setup/"))
	}
	if h.storedBytesContain(t, "via-setup/data/", []byte("setup flow")) {
		t.Fatal("plaintext leaked into stored objects")
	}

	// Cloning works because the same XDG_CONFIG_HOME holds the identity;
	// recipients live in the cloned repo's config only after setup, so the
	// clone itself needs just the identity for decryption.
	work := t.TempDir()
	if gout, err := h.git(t, work, env, "clone", "-q", remoteURL, "copy"); err != nil {
		t.Fatalf("clone after setup failed: %v\n%s", err, gout)
	}
	if data, err := os.ReadFile(filepath.Join(work, "copy", "app.txt")); err != nil || string(data) != "setup flow\n" {
		t.Fatalf("cloned content wrong: %q, %v", data, err)
	}
}

// TestRecoveryKeyDisasterRecovery walks the full "lost laptop" story:
// setup mints a recovery key (shown exactly once), the laptop dies, and a
// brand-new machine regains access with only the recovery secret and the
// s3ee:// URL via `key recover` + `git clone`.
func TestRecoveryKeyDisasterRecovery(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/dr-test"

	bin := filepath.Join(h.binDir, "git-remote-s3ee")
	runBin := func(dir string, env []string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, h.baseEnv...), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Day 0: laptop #1 — setup creates the keyring AND the recovery key.
	cfgHome1 := t.TempDir()
	env1 := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome1,
	}
	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "precious.txt"), []byte("do not lose me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "precious data")

	out, err := runBin(repo, env1, "setup", remoteURL)
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	secret := regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]+`).FindString(out)
	if secret == "" {
		t.Fatalf("setup did not print a recovery key:\n%s", out)
	}
	if !strings.Contains(out, "key recover "+remoteURL) {
		t.Errorf("setup output should include the recovery command:\n%s", out)
	}
	if out, err := h.git(t, repo, env1, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("push: %v\n%s", err, out)
	}

	// The recovery slot exists; its public half enables future rotation.
	if keys := h.listKeys(t, "dr-test/.keys/dek/recovery."); len(keys) != 2 {
		t.Fatalf("recovery slot objects = %v", keys)
	}

	// Day 1: the laptop is gone. New machine: only the secret + URL.
	cfgHome2 := t.TempDir()
	env2 := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome2,
	}
	work := t.TempDir()

	// A wrong recovery key must fail.
	wrong, _ := age.GenerateX25519Identity()
	badEnv := append(append([]string{}, env2...), "GIT_REMOTE_S3EE_RECOVERY_KEY="+wrong.String())
	if out, err := runBin(work, badEnv, "key", "recover", remoteURL); err == nil {
		t.Fatalf("recover with wrong key must fail:\n%s", out)
	}

	goodEnv := append(append([]string{}, env2...), "GIT_REMOTE_S3EE_RECOVERY_KEY="+secret)
	out, err = runBin(work, goodEnv, "key", "recover", remoteURL)
	if err != nil {
		t.Fatalf("key recover: %v\n%s", err, out)
	}
	idPath := filepath.Join(cfgHome2, "git-remote-s3ee", "identity.txt")
	if _, err := os.Stat(idPath); err != nil {
		t.Fatalf("identity not created at default location: %v", err)
	}

	// The repository comes back — decrypted with the NEW machine identity,
	// no recovery key in the environment anymore.
	if out, err := h.git(t, work, env2, "clone", "-q", remoteURL, "recovered"); err != nil {
		t.Fatalf("clone after recover: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(work, "recovered", "precious.txt"))
	if err != nil || string(data) != "do not lose me\n" {
		t.Fatalf("recovered content wrong: %q, %v", data, err)
	}
}

// TestGrantTeamFlow: alice creates and pushes a repo; bob is granted access
// with a single `key grant` — no re-encryption, no re-push — and can clone
// the full pre-existing history immediately.
func TestGrantTeamFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/team-repo"

	bin := filepath.Join(h.binDir, "git-remote-s3ee")
	runBin := func(dir string, env []string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, h.baseEnv...), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Alice: setup + push (her key wraps the repo DEK).
	aliceCfg := t.TempDir()
	aliceEnv := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + aliceCfg,
	}
	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "history.txt"), []byte("pre-bob history\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "before bob joined")
	if out, err := runBin(repo, aliceEnv, "setup", remoteURL); err != nil {
		t.Fatalf("alice setup: %v\n%s", err, out)
	}
	if out, err := h.git(t, repo, aliceEnv, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("alice push: %v\n%s", err, out)
	}

	// Snapshot the stored data set before bob is granted.
	dataBefore := strings.Join(h.listKeys(t, "team-repo/data/"), ",")

	// Bob: has an identity, but no access yet — his clone must fail.
	bob, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	bobIDFile := filepath.Join(t.TempDir(), "bob-identity.txt")
	if err := os.WriteFile(bobIDFile, []byte(bob.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bobEnv := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=",
		"GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=" + bobIDFile,
		"XDG_CONFIG_HOME=" + t.TempDir(),
	}
	work := t.TempDir()
	if out, err := h.git(t, work, bobEnv, "clone", remoteURL, "denied"); err == nil {
		t.Fatalf("bob's clone must fail before grant:\n%s", out)
	}

	// Alice grants bob's public key. One small upload, nothing re-pushed.
	out, err := runBin(repo, aliceEnv, "key", "grant", "--name", "bob", bob.Recipient().String())
	if err != nil {
		t.Fatalf("key grant: %v\n%s", err, out)
	}
	if !strings.Contains(out, "No re-encryption needed") {
		t.Errorf("grant output:\n%s", out)
	}

	// `key list` shows alice's slot, the recovery slot, and bob's.
	out, err = runBin(repo, aliceEnv, "key", "list")
	if err != nil {
		t.Fatalf("key list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "3 key slot(s)") || !strings.Contains(out, bob.Recipient().String()) ||
		!strings.Contains(out, "recovery") {
		t.Errorf("key list output:\n%s", out)
	}

	// The stored data set is untouched...
	if dataAfter := strings.Join(h.listKeys(t, "team-repo/data/"), ","); dataAfter != dataBefore {
		t.Fatal("grant must not modify stored data blobs")
	}

	// ...yet bob can now clone the pre-grant history.
	if out, err := h.git(t, work, bobEnv, "clone", "-q", remoteURL, "granted"); err != nil {
		t.Fatalf("bob's clone after grant: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(work, "granted", "history.txt"))
	if err != nil || string(data) != "pre-bob history\n" {
		t.Fatalf("bob's clone content: %q, %v", data, err)
	}

	// Revoke bob; future unwraps fail (a fresh clone can no longer decrypt).
	if out, err := runBin(repo, aliceEnv, "key", "revoke", "bob"); err != nil {
		t.Fatalf("key revoke: %v\n%s", err, out)
	}
	if out, err := h.git(t, work, bobEnv, "clone", remoteURL, "revoked"); err == nil {
		t.Fatalf("bob's clone after revoke must fail:\n%s", out)
	}
}

// TestSavedCredentialsFlow proves that credentials stored in
// ~/.config/git-remote-s3ee/credentials are enough on their own: with no
// AWS_* variables in the environment, setup reports the saved
// entry and git push / clone authenticate through it.
func TestSavedCredentialsFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/saved-creds"

	// Seed the credential store, keyed by the MinIO endpoint.
	cfgHome := t.TempDir()
	credDir := filepath.Join(cfgHome, "git-remote-s3ee")
	if err := os.MkdirAll(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	credFile := fmt.Sprintf("[endpoint:%s bucket:%s]\naccess_key_id = %s\nsecret_access_key = %s\n",
		h.endpoint, bucket, h.username, h.password)
	if err := os.WriteFile(filepath.Join(credDir, "credentials"), []byte(credFile), 0o600); err != nil {
		t.Fatal(err)
	}

	// Strip every credential variable; only the store remains.
	env := []string{
		"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=",
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("via saved creds\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")

	setup := exec.Command(filepath.Join(h.binDir, "git-remote-s3ee"), "setup", remoteURL)
	setup.Dir = repo
	setup.Env = append(append([]string{}, h.baseEnv...), env...)
	out, err := setup.CombinedOutput()
	if err != nil {
		t.Fatalf("setup with saved credentials: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "using saved credentials") {
		t.Errorf("setup should report the credential source:\n%s", out)
	}

	if gout, err := h.git(t, repo, env, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("push with saved credentials: %v\n%s", err, gout)
	}
	work := t.TempDir()
	if gout, err := h.git(t, work, env, "clone", "-q", remoteURL, "c"); err != nil {
		t.Fatalf("clone with saved credentials: %v\n%s", err, gout)
	}
	if data, err := os.ReadFile(filepath.Join(work, "c", "f.txt")); err != nil || string(data) != "via saved creds\n" {
		t.Fatalf("cloned content: %q, %v", data, err)
	}
}

// TestInteractiveWizardFlow drives `git-remote-s3ee setup` with no arguments,
// answering the wizard over stdin, then pushes and clones with what it
// configured.
func TestInteractiveWizardFlow(t *testing.T) {
	h := newHarness(t)

	cfgHome := t.TempDir()
	env := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "w.txt"), []byte("wizard\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")

	// Answers: endpoint (Enter → AWS_ENDPOINT_URL env default), bucket,
	// prefix, remote name (Enter → origin), confirmation (Enter → Y).
	// Credentials are skipped (present in the environment).
	setup := exec.Command(filepath.Join(h.binDir, "git-remote-s3ee"), "setup")
	setup.Dir = repo
	setup.Env = append(append([]string{}, h.baseEnv...), env...)
	setup.Stdin = strings.NewReader("\n" + bucket + "\nwizard-repo\n\n\n")
	out, err := setup.CombinedOutput()
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "→ s3ee://"+bucket+"/wizard-repo") {
		t.Errorf("wizard should echo the assembled URL:\n%s", out)
	}

	if gout, err := h.git(t, repo, env, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("push after wizard: %v\n%s", err, gout)
	}
	work := t.TempDir()
	if gout, err := h.git(t, work, env, "clone", "-q", "s3ee://"+bucket+"/wizard-repo", "w"); err != nil {
		t.Fatalf("clone after wizard: %v\n%s", err, gout)
	}
	if data, err := os.ReadFile(filepath.Join(work, "w", "w.txt")); err != nil || string(data) != "wizard\n" {
		t.Fatalf("cloned content: %q, %v", data, err)
	}
}

// TestDedupAcrossPushesAndTags measures, against the real S3 backend,
// that repeated full-bundle pushes only add roughly the changed bytes:
// a tag push (identical content) is nearly free and a small commit costs
// a small fraction of the repository size.
func TestDedupAcrossPushesAndTags(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/dedup"

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	// ~3MB of incompressible data so dedup (not compression) is measured.
	asset := make([]byte, 3<<20)
	if _, err := rand.Read(asset); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "asset.bin"), asset, 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "base")
	h.mustGit(t, repo, "remote", "add", "origin", remoteURL)
	h.mustGit(t, repo, "push", "-q", "origin", "main")
	base := h.bucketSize(t, "dedup/data/")
	if base < 3<<20 {
		t.Fatalf("initial push too small (%d bytes) — asset not stored?", base)
	}

	// A tag points at identical content: near-free.
	h.mustGit(t, repo, "tag", "v1")
	h.mustGit(t, repo, "push", "-q", "origin", "v1")
	afterTag := h.bucketSize(t, "dedup/data/")
	if growth := afterTag - base; growth > 512<<10 {
		t.Fatalf("tag push should be nearly free, grew %d bytes", growth)
	}

	// A small commit re-pushes the full bundle, but only the delta lands.
	if err := os.WriteFile(filepath.Join(repo, "note.txt"), []byte("small change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "small")
	h.mustGit(t, repo, "push", "-q", "origin", "main")
	afterCommit := h.bucketSize(t, "dedup/data/")
	if growth := afterCommit - afterTag; growth > 1<<20 {
		t.Fatalf("small-commit push should cost a fraction of the repo, grew %d bytes (repo ~%d)", growth, base)
	}
	t.Logf("sizes: base=%d afterTag=+%d afterCommit=+%d", base, afterTag-base, afterCommit-afterTag)
}

// TestCloneCommandFlow: onboarding machine #2 with `git-remote-s3ee clone`.
// First run has no access — it prints the machine's public key and the
// exact grant command; after a member grants it, the re-run clones.
func TestCloneCommandFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "s3ee://" + bucket + "/clone-cmd"

	bin := filepath.Join(h.binDir, "git-remote-s3ee")
	runBin := func(dir string, env []string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(append([]string{}, h.baseEnv...), env...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Alice publishes the repository.
	aliceEnv := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + t.TempDir(),
	}
	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "hello.txt"), []byte("clone me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")
	if out, err := runBin(repo, aliceEnv, "setup", remoteURL); err != nil {
		t.Fatalf("alice setup: %v\n%s", err, out)
	}
	if out, err := h.git(t, repo, aliceEnv, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("alice push: %v\n%s", err, out)
	}

	// Bob's fresh machine: `clone` refuses with actionable instructions.
	bobEnv := []string{
		"GIT_REMOTE_S3EE_AGE_RECIPIENTS=", "GIT_REMOTE_S3EE_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + t.TempDir(),
	}
	work := t.TempDir()
	out, err := runBin(work, bobEnv, "clone", remoteURL, "myclone")
	if err == nil {
		t.Fatalf("clone before grant must fail:\n%s", out)
	}
	if !strings.Contains(out, "key grant age1") {
		t.Fatalf("expected the exact grant command in output:\n%s", out)
	}
	bobPub := regexp.MustCompile(`age1[a-z0-9]+`).FindString(out)
	if bobPub == "" {
		t.Fatalf("no public key in output:\n%s", out)
	}

	// Alice grants; bob re-runs the same command and gets a working clone.
	if out, err := runBin(repo, aliceEnv, "key", "grant", bobPub); err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	out, err = runBin(work, bobEnv, "clone", remoteURL, "myclone")
	if err != nil {
		t.Fatalf("clone after grant: %v\n%s", err, out)
	}
	if !strings.Contains(out, "access confirmed") {
		t.Errorf("missing access confirmation:\n%s", out)
	}
	data, err := os.ReadFile(filepath.Join(work, "myclone", "hello.txt"))
	if err != nil || string(data) != "clone me\n" {
		t.Fatalf("cloned content: %q, %v", data, err)
	}

	// Backend settings were persisted into the fresh repository.
	cmd := exec.Command("git", "config", "remote.origin.endpoint")
	cmd.Dir = filepath.Join(work, "myclone")
	cmd.Env = append(append([]string{}, h.baseEnv...), bobEnv...)
	if ep, err := cmd.Output(); err != nil || strings.TrimSpace(string(ep)) != h.endpoint {
		t.Errorf("endpoint not persisted in clone: %q, %v", ep, err)
	}

	// The interactive wizard path: `clone` with no arguments, answers over
	// stdin (endpoint default from env, credentials from env, bucket,
	// prefix, directory, confirm).
	wiz := exec.Command(bin, "clone")
	wiz.Dir = work
	wiz.Env = append(append([]string{}, h.baseEnv...), bobEnv...)
	wiz.Stdin = strings.NewReader("\n" + bucket + "\nclone-cmd\nwizclone\n\n")
	out, err = func() (string, error) { b, e := wiz.CombinedOutput(); return string(b), e }()
	if err != nil {
		t.Fatalf("wizard clone: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(filepath.Join(work, "wizclone", "hello.txt")); err != nil || string(data) != "clone me\n" {
		t.Fatalf("wizard-cloned content: %q, %v", data, err)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
