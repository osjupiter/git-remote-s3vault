// Package e2e exercises the compiled git-remote-r2 binary end-to-end
// against a real S3-compatible backend (MinIO in a testcontainer), driving
// it exactly the way users do: through git push / clone / pull.
package e2e

import (
	"bytes"
	"context"
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
	build := exec.Command("go", "build", "-o", filepath.Join(binDir, "git-remote-r2"), "../cmd/git-remote-r2")
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
		"GIT_REMOTE_R2_AGE_RECIPIENTS="+id.Recipient().String(),
		"GIT_REMOTE_R2_AGE_IDENTITY_FILE="+idFile,
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

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)
	remoteURL := "r2://" + bucket + "/project"

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

	// --- everything at rest is an age ciphertext ---
	keys := h.listKeys(t, "project/refs/")
	if len(keys) != 1 || !strings.HasSuffix(keys[0], ".bundle.age") {
		t.Fatalf("expected one .bundle.age object, got %v", keys)
	}
	obj, err := h.s3c.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(keys[0]),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if !bytes.HasPrefix(raw, []byte("age-encryption.org/")) {
		t.Fatalf("object at rest is not age-encrypted: %q...", raw[:min(40, len(raw))])
	}
	if bytes.Contains(raw, []byte("hello via r2")) {
		t.Fatal("plaintext leaked into the stored object")
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

	// --- old bundle is garbage-collected after the fast-forward push ---
	if keys := h.listKeys(t, "project/refs/heads/main/"); len(keys) != 1 {
		t.Fatalf("expected exactly one bundle after ff push, got %v", keys)
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

	// --- branch delete removes the remote objects ---
	h.mustGit(t, bob, "checkout", "-q", "-b", "topic")
	h.mustGit(t, bob, "push", "-q", "origin", "topic")
	if keys := h.listKeys(t, "project/refs/heads/topic/"); len(keys) != 1 {
		t.Fatalf("topic branch not pushed: %v", keys)
	}
	h.mustGit(t, bob, "push", "-q", "origin", ":topic")
	if keys := h.listKeys(t, "project/refs/heads/topic/"); len(keys) != 0 {
		t.Fatalf("topic branch objects not deleted: %v", keys)
	}
}

func TestCloneWithoutIdentityFails(t *testing.T) {
	h := newHarness(t)
	remoteURL := "r2://" + bucket + "/locked"

	src := t.TempDir()
	h.mustGit(t, src, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(src, "secret.txt"), []byte("classified\n"), 0o644)
	h.mustGit(t, src, "add", ".")
	h.mustGit(t, src, "commit", "-q", "-m", "secret")
	h.mustGit(t, src, "remote", "add", "origin", remoteURL)
	h.mustGit(t, src, "push", "-q", "origin", "main")

	work := t.TempDir()
	out, err := h.git(t, work, []string{"GIT_REMOTE_R2_AGE_IDENTITY_FILE="}, "clone", remoteURL, "mallory")
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
	remoteURL := "r2://" + bucket + "/timing"

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

// TestSetupCommandFlow provisions a repo with `git-remote-r2 setup` alone —
// no manual key generation, no env-provided age configuration — then pushes
// and clones with what setup wrote.
func TestSetupCommandFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "r2://" + bucket + "/via-setup"

	// Drop the env-based age config so only setup's output is in play; keep
	// endpoint + credentials. XDG_CONFIG_HOME hosts the generated identity.
	cfgHome := t.TempDir()
	env := []string{
		"GIT_REMOTE_R2_AGE_RECIPIENTS=",
		"GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "app.txt"), []byte("setup flow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "first")

	setup := exec.Command(filepath.Join(h.binDir, "git-remote-r2"), "setup", remoteURL)
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

	// Stored object is encrypted with the setup-generated key.
	keys := h.listKeys(t, "via-setup/refs/heads/main/")
	if len(keys) != 1 || !strings.HasSuffix(keys[0], ".bundle.age") {
		t.Fatalf("expected one encrypted bundle, got %v", keys)
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
// r2:// URL via `key recover` + `git clone`.
func TestRecoveryKeyDisasterRecovery(t *testing.T) {
	h := newHarness(t)
	remoteURL := "r2://" + bucket + "/dr-test"

	bin := filepath.Join(h.binDir, "git-remote-r2")
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
		"GIT_REMOTE_R2_AGE_RECIPIENTS=", "GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
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
		"GIT_REMOTE_R2_AGE_RECIPIENTS=", "GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome2,
	}
	work := t.TempDir()

	// A wrong recovery key must fail.
	wrong, _ := age.GenerateX25519Identity()
	badEnv := append(append([]string{}, env2...), "GIT_REMOTE_R2_RECOVERY_KEY="+wrong.String())
	if out, err := runBin(work, badEnv, "key", "recover", remoteURL); err == nil {
		t.Fatalf("recover with wrong key must fail:\n%s", out)
	}

	goodEnv := append(append([]string{}, env2...), "GIT_REMOTE_R2_RECOVERY_KEY="+secret)
	out, err = runBin(work, goodEnv, "key", "recover", remoteURL)
	if err != nil {
		t.Fatalf("key recover: %v\n%s", err, out)
	}
	idPath := filepath.Join(cfgHome2, "git-remote-r2", "identity.txt")
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
	remoteURL := "r2://" + bucket + "/team-repo"

	bin := filepath.Join(h.binDir, "git-remote-r2")
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
		"GIT_REMOTE_R2_AGE_RECIPIENTS=", "GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
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

	// Snapshot the encrypted bundle as it exists before bob is granted.
	bundleKeys := h.listKeys(t, "team-repo/refs/heads/main/")
	if len(bundleKeys) != 1 {
		t.Fatalf("bundles = %v", bundleKeys)
	}
	obj, err := h.s3c.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(bundleKeys[0]),
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleBefore, _ := io.ReadAll(obj.Body)
	obj.Body.Close()

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
		"GIT_REMOTE_R2_AGE_RECIPIENTS=",
		"GIT_REMOTE_R2_AGE_IDENTITY_FILE=" + bobIDFile,
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

	// The bundle bytes are untouched...
	obj, err = h.s3c.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(bundleKeys[0]),
	})
	if err != nil {
		t.Fatal(err)
	}
	bundleAfter, _ := io.ReadAll(obj.Body)
	obj.Body.Close()
	if !bytes.Equal(bundleBefore, bundleAfter) {
		t.Fatal("grant must not modify stored bundles")
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
// ~/.config/git-remote-r2/credentials are enough on their own: with no
// AWS_* variables in the environment, setup reports the saved
// entry and git push / clone authenticate through it.
func TestSavedCredentialsFlow(t *testing.T) {
	h := newHarness(t)
	remoteURL := "r2://" + bucket + "/saved-creds"

	// Seed the credential store, keyed by the MinIO endpoint.
	cfgHome := t.TempDir()
	credDir := filepath.Join(cfgHome, "git-remote-r2")
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
		"GIT_REMOTE_R2_AGE_RECIPIENTS=", "GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "f.txt"), []byte("via saved creds\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")

	setup := exec.Command(filepath.Join(h.binDir, "git-remote-r2"), "setup", remoteURL)
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

// TestInteractiveWizardFlow drives `git-remote-r2 setup` with no arguments,
// answering the wizard over stdin, then pushes and clones with what it
// configured.
func TestInteractiveWizardFlow(t *testing.T) {
	h := newHarness(t)

	cfgHome := t.TempDir()
	env := []string{
		"GIT_REMOTE_R2_AGE_RECIPIENTS=", "GIT_REMOTE_R2_AGE_IDENTITY_FILE=",
		"XDG_CONFIG_HOME=" + cfgHome,
	}

	repo := t.TempDir()
	h.mustGit(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "w.txt"), []byte("wizard\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.mustGit(t, repo, "add", ".")
	h.mustGit(t, repo, "commit", "-q", "-m", "c")

	// Answers: backend (Enter → 2, derived from AWS_ENDPOINT_URL in the
	// env), endpoint (Enter → env default), bucket, prefix, remote name
	// (Enter → origin).
	setup := exec.Command(filepath.Join(h.binDir, "git-remote-r2"), "setup")
	setup.Dir = repo
	setup.Env = append(append([]string{}, h.baseEnv...), env...)
	setup.Stdin = strings.NewReader("\n\n" + bucket + "\nwizard-repo\n\n")
	out, err := setup.CombinedOutput()
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "→ r2://"+bucket+"/wizard-repo") {
		t.Errorf("wizard should echo the assembled URL:\n%s", out)
	}

	if gout, err := h.git(t, repo, env, "push", "-q", "-u", "origin", "main"); err != nil {
		t.Fatalf("push after wizard: %v\n%s", err, gout)
	}
	work := t.TempDir()
	if gout, err := h.git(t, work, env, "clone", "-q", "r2://"+bucket+"/wizard-repo", "w"); err != nil {
		t.Fatalf("clone after wizard: %v\n%s", err, gout)
	}
	if data, err := os.ReadFile(filepath.Join(work, "w", "w.txt")); err != nil || string(data) != "wizard\n" {
		t.Fatalf("cloned content: %q, %v", data, err)
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
