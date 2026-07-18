package setupcmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/osjupiter/git-remote-s3vault/internal/credstore"
)

func gitOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("git", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func setupRepo(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	// Isolate the default identity location, the ~/.ssh scan, and global
	// git config from the developer's real machine.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".xdg"))
	t.Setenv("HOME", filepath.Join(dir, ".home"))
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	if out, err := gitOut(t, "init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runWithInput(t, "", args...)
}

func runWithInput(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Run(context.Background(), args, strings.NewReader(input), &out, &out)
	return out.String(), err
}

func TestSetupFreshRepo(t *testing.T) {
	setupRepo(t)
	out, err := run(t, "--no-verify", "s3vault://bucket/proj")
	if err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}

	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "s3vault://bucket/proj" {
		t.Errorf("remote url = %q", url)
	}
	recips, _ := gitOut(t, "config", "--get-all", "remote.origin.agerecipients")
	if !strings.HasPrefix(recips, "age1") {
		t.Errorf("recipient not configured: %q", recips)
	}

	// A fresh identity was generated at the default location with 0600.
	idPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git-remote-s3vault", "identity.txt")
	st, err := os.Stat(idPath)
	if err != nil {
		t.Fatalf("identity not generated: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("identity mode = %v, want 0600", st.Mode().Perm())
	}
	if !strings.Contains(out, "machine's key") {
		t.Errorf("missing machine key message:\n%s", out)
	}
}

func TestSetupIsIdempotent(t *testing.T) {
	setupRepo(t)
	if _, err := run(t, "--no-verify", "s3vault://bucket/proj"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "--no-verify", "--recipient",
		"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p", "s3vault://bucket/proj")
	if err != nil {
		t.Fatalf("second setup failed: %v\n%s", err, out)
	}

	recips, _ := gitOut(t, "config", "--get-all", "remote.origin.agerecipients")
	lines := strings.Split(recips, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected own key + 1 teammate, got %d recipients:\n%s", len(lines), recips)
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if seen[l] {
			t.Fatalf("duplicate recipient written: %s", l)
		}
		seen[l] = true
	}
}

func TestSetupUpdatesExistingRemote(t *testing.T) {
	setupRepo(t)
	gitOut(t, "remote", "add", "origin", "https://example.com/old.git")
	out, err := run(t, "--no-verify", "--endpoint", "https://ep.example.com", "s3vault://bucket/new-home")
	if err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "s3vault://bucket/new-home" {
		t.Errorf("remote url not updated: %q", url)
	}
	if v, _ := gitOut(t, "config", "remote.origin.endpoint"); v != "https://ep.example.com" {
		t.Errorf("endpoint = %q", v)
	}
}

func TestSetupEncryptionNone(t *testing.T) {
	setupRepo(t)
	out, err := run(t, "--no-verify", "--encryption", "none", "s3vault://bucket/plain")
	if err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}
	if v, _ := gitOut(t, "config", "remote.origin.encryption"); v != "none" {
		t.Errorf("encryption = %q", v)
	}
	if !strings.Contains(out, "PLAINTEXT") {
		t.Errorf("missing plaintext warning:\n%s", out)
	}
	if recips, err := gitOut(t, "config", "--get-all", "remote.origin.agerecipients"); err == nil {
		t.Errorf("recipients should not be set in plaintext mode: %q", recips)
	}
}

func TestWizardBuildsURLFromAnswers(t *testing.T) {
	setupRepo(t)
	// Endpoint, credentials skipped, bucket, prefix, default remote name.
	out, err := runWithInput(t,
		"https://ep.example.com\n\nmy-bucket\nmy-prefix\n\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "s3vault://my-bucket/my-prefix" {
		t.Errorf("remote url = %q", url)
	}
	if v, _ := gitOut(t, "config", "remote.origin.endpoint"); v != "https://ep.example.com" {
		t.Errorf("endpoint = %q", v)
	}
}

func TestWizardDefaultsAndEndpointBackend(t *testing.T) {
	setupRepo(t)
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")
	// With credentials in the environment the wizard skips its credential
	// questions entirely.
	t.Setenv("AWS_ACCESS_KEY_ID", "env-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	// Enter accepts backend=2 (env-derived) and the endpoint default; the
	// prefix default is the repository directory name.
	out, err := runWithInput(t,
		"\nbkt\n\nupstream\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "using credentials from the environment") {
		t.Errorf("credential questions should be skipped with env creds:\n%s", out)
	}
	top, _ := gitOut(t, "rev-parse", "--show-toplevel")
	wantURL := "s3vault://bkt/" + filepath.Base(top)
	if url, _ := gitOut(t, "remote", "get-url", "upstream"); url != wantURL {
		t.Errorf("remote url = %q, want %q", url, wantURL)
	}
	if v, _ := gitOut(t, "config", "remote.upstream.endpoint"); v != "http://127.0.0.1:9000" {
		t.Errorf("endpoint = %q", v)
	}
}

func TestWizardReusesExistingRemote(t *testing.T) {
	setupRepo(t)
	gitOut(t, "remote", "add", "origin", "s3vault://old-bucket/old-prefix")
	out, err := runWithInput(t, "\n", "--no-verify") // Enter = "Y", use it
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "s3vault://old-bucket/old-prefix" {
		t.Errorf("remote url = %q", url)
	}
}

func TestWizardCollectsCredentialsBeforeBucket(t *testing.T) {
	setupRepo(t)
	// Endpoint, THEN access key + secret, THEN bucket etc.
	out, err := runWithInput(t,
		"https://ep.example.com\nAKIA123\ntopsecret\nmy-bucket\nmy-prefix\n\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	c, ok := credstore.Lookup("https://ep.example.com", "my-bucket")
	if !ok || c.AccessKeyID != "AKIA123" || c.SecretAccessKey != "topsecret" {
		t.Fatalf("credentials not saved for the chosen bucket: %+v, %v", c, ok)
	}
	if !strings.Contains(out, "credentials saved") {
		t.Errorf("missing save confirmation:\n%s", out)
	}
}

func TestWizardAbortDiscardsEnteredCredentials(t *testing.T) {
	setupRepo(t)
	out, err := runWithInput(t,
		"https://ep.example.com\nAKIA123\ntopsecret\nmy-bucket\nmy-prefix\n\nn\n", // decline at confirm
		"--no-verify")
	if err == nil {
		t.Fatalf("declined confirmation must abort:\n%s", out)
	}
	if _, ok := credstore.Lookup("https://ep.example.com", "my-bucket"); ok {
		t.Fatal("aborting the wizard must not persist credentials")
	}
}

func TestWizardConfirmationAbortsCleanly(t *testing.T) {
	setupRepo(t)
	out, err := runWithInput(t,
		"\n\nmy-bucket\nmy-prefix\n\nn\n", // "n" at the final confirmation
		"--no-verify")
	if err == nil {
		t.Fatalf("declined confirmation must abort:\n%s", out)
	}
	if _, err := gitOut(t, "remote", "get-url", "origin"); err == nil {
		t.Fatal("no remote should have been created after aborting")
	}
}

func TestWizardStripsPasteArtifacts(t *testing.T) {
	setupRepo(t)
	// A bracketed-paste accident: markers and control characters around
	// the bucket answer, and a stray "]" paste remnant as the remote name
	// would have been — here the sanitized empty-ish answer falls back to
	// the default instead.
	out, err := runWithInput(t,
		"\n\n\x1b[200~my-bucket\x1b[201~\nmy-prefix\n\x1b[200~\x1b[201~\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "s3vault://my-bucket/my-prefix" {
		t.Errorf("paste artifacts leaked into the config: url=%q", url)
	}
}

// seedMachineKeys writes an identity file with two age keys and returns
// both recipients.
func seedMachineKeys(t *testing.T) []string {
	t.Helper()
	var recips []string
	var content strings.Builder
	for range 2 {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		recips = append(recips, id.Recipient().String())
		fmt.Fprintf(&content, "%s\n", id)
	}
	dir := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git-remote-s3vault")
	os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "identity.txt"), []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return recips
}

// writeSSHKey creates an OpenSSH keypair under $HOME/.ssh and returns the
// private key path and the public key line.
func writeSSHKey(t *testing.T, name, passphrase string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test key")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test key", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(os.Getenv("HOME"), ".ssh")
	os.MkdirAll(sshDir, 0o700)
	privPath := filepath.Join(sshDir, name)
	if err := os.WriteFile(privPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " test key"
	if err := os.WriteFile(privPath+".pub", []byte(pubLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return privPath, pubLine
}

func TestWizardKeySelectionPicksSpecificAgeKey(t *testing.T) {
	setupRepo(t)
	recips := seedMachineKeys(t)

	// Candidates: 1,2 = age keys, 3 = generate. Pick the second age key.
	out, err := runWithInput(t,
		"\n\nbkt\npfx\n\n2\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	got, _ := gitOut(t, "config", "--get-all", "remote.origin.agerecipients")
	if got != recips[1] {
		t.Errorf("recipients = %q, want exactly the chosen key %q", got, recips[1])
	}
}

func TestWizardKeySelectionSSH(t *testing.T) {
	setupRepo(t)
	seedMachineKeys(t)
	privPath, pubLine := writeSSHKey(t, "id_ed25519", "")

	// Candidates: 1,2 age; 3 SSH; 4 generate. Pick the SSH key.
	out, err := runWithInput(t,
		"\n\nbkt\npfx\n\n3\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	if got, _ := gitOut(t, "config", "--get-all", "remote.origin.agerecipients"); got != pubLine {
		t.Errorf("recipients = %q, want the SSH public key", got)
	}
	if got, _ := gitOut(t, "config", "remote.origin.ageidentityfile"); got != privPath {
		t.Errorf("ageidentityfile = %q, want %q", got, privPath)
	}
}

func TestWizardSkipsPassphraseProtectedSSHKeys(t *testing.T) {
	setupRepo(t)
	seedMachineKeys(t)
	writeSSHKey(t, "id_locked", "s3kret-passphrase")

	// Locked key is not offered: candidates are 2 age keys + generate.
	out, err := runWithInput(t,
		"\n\nbkt\npfx\n\n1\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "passphrase-protected") {
		t.Errorf("expected a note about the skipped key:\n%s", out)
	}
	if strings.Contains(out, "id_locked") {
		t.Errorf("locked key must not be offered:\n%s", out)
	}
}

func TestWizardAbortsOnClosedInput(t *testing.T) {
	setupRepo(t)
	if out, err := runWithInput(t, "", "--no-verify"); err == nil {
		t.Fatalf("wizard with no input must abort cleanly:\n%s", out)
	}
}

func TestCloneRejectsBadInput(t *testing.T) {
	setupRepo(t) // isolates env; clone itself runs anywhere
	runClone := func(args ...string) error {
		var out bytes.Buffer
		return RunClone(context.Background(), args, strings.NewReader(""), &out, &out)
	}
	if err := runClone(); err == nil {
		t.Error("clone without a URL and no wizard input must fail")
	}
	if err := runClone("https://github.com/x/y.git"); err == nil {
		t.Error("clone with a non-r2 URL must fail")
	}
	if err := runClone("s3vault://b/p", "dir", "extra"); err == nil {
		t.Error("clone with too many args must fail")
	}
}

func TestCloneWizardCollectsAnswers(t *testing.T) {
	setupRepo(t) // env isolation
	var out bytes.Buffer
	// endpoint, access key, secret, bucket, prefix, dir (default), confirm.
	a, err := runCloneWizard(strings.NewReader(
		"https://ep.example.com\nAKIA9\nsss\nbkt\nteam/proj\n\n\n"), &out, "")
	if err != nil {
		t.Fatalf("wizard: %v\n%s", err, out.String())
	}
	if a.rawURL != "s3vault://bkt/team/proj" || a.endpoint != "https://ep.example.com" || a.dir != "proj" {
		t.Errorf("answers = %+v", a)
	}
	// Credentials were saved for the bucket after the confirmation.
	if c, ok := credstore.Lookup("https://ep.example.com", "bkt"); !ok || c.AccessKeyID != "AKIA9" {
		t.Errorf("credentials not saved: %+v %v", c, ok)
	}
}

func TestCloneWizardAbortSavesNothing(t *testing.T) {
	setupRepo(t)
	var out bytes.Buffer
	_, err := runCloneWizard(strings.NewReader(
		"https://ep.example.com\nAKIA9\nsss\nbkt\n\n\nn\n"), &out, "")
	if err == nil {
		t.Fatal("declined confirmation must abort")
	}
	if _, ok := credstore.Lookup("https://ep.example.com", "bkt"); ok {
		t.Fatal("aborted wizard must not save credentials")
	}
}

func TestDeriveCloneDir(t *testing.T) {
	cases := map[string]string{
		"s3vault://bucket/team/project": "project",
		"s3vault://bucket/repo.git":     "repo",
		"s3vault://bucket":              "bucket",
		"s3vault://bucket/":             "bucket",
	}
	for url, want := range cases {
		if got := deriveCloneDir(url); got != want {
			t.Errorf("deriveCloneDir(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestSetupRejectsBadInput(t *testing.T) {
	setupRepo(t)
	if _, err := run(t, "--no-verify", "https://github.com/x/y.git"); err == nil {
		t.Error("non-r2 URL should be rejected")
	}
	if _, err := run(t, "--no-verify"); err == nil {
		t.Error("missing URL should be rejected")
	}
	if _, err := run(t, "--no-verify", "--encryption", "rot13", "s3vault://b/p"); err == nil {
		t.Error("bad encryption mode should be rejected")
	}

	// Outside a git repository.
	t.Chdir(t.TempDir())
	if _, err := run(t, "--no-verify", "s3vault://bucket/proj"); err == nil {
		t.Error("setup outside a git repo should fail")
	}
}
