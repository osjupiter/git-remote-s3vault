package setupcmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	// Isolate the default identity location and global git config.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".xdg"))
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
	out, err := run(t, "--no-verify", "r2://bucket/proj")
	if err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}

	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "r2://bucket/proj" {
		t.Errorf("remote url = %q", url)
	}
	recips, _ := gitOut(t, "config", "--get-all", "remote.origin.agerecipients")
	if !strings.HasPrefix(recips, "age1") {
		t.Errorf("recipient not configured: %q", recips)
	}

	// A fresh identity was generated at the default location with 0600.
	idPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git-remote-r2", "identity.txt")
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
	if _, err := run(t, "--no-verify", "r2://bucket/proj"); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "--no-verify", "--recipient",
		"age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p", "r2://bucket/proj")
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
	out, err := run(t, "--no-verify", "--account-id", "acct42", "r2://bucket/new-home")
	if err != nil {
		t.Fatalf("setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "r2://bucket/new-home" {
		t.Errorf("remote url not updated: %q", url)
	}
	if v, _ := gitOut(t, "config", "remote.origin.accountid"); v != "acct42" {
		t.Errorf("accountid = %q", v)
	}
}

func TestSetupEncryptionNone(t *testing.T) {
	setupRepo(t)
	out, err := run(t, "--no-verify", "--encryption", "none", "r2://bucket/plain")
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
	// Backend 1 (R2), account, bucket, default prefix (repo dir name),
	// default remote name.
	out, err := runWithInput(t,
		"1\nacct42\nmy-bucket\nmy-prefix\n\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "r2://my-bucket/my-prefix" {
		t.Errorf("remote url = %q", url)
	}
	if v, _ := gitOut(t, "config", "remote.origin.accountid"); v != "acct42" {
		t.Errorf("accountid = %q", v)
	}
}

func TestWizardDefaultsAndEndpointBackend(t *testing.T) {
	setupRepo(t)
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")
	// Enter accepts backend=2 (env-derived) and the endpoint default; the
	// prefix default is the repository directory name.
	out, err := runWithInput(t,
		"\n\nbkt\n\nupstream\n",
		"--no-verify")
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	top, _ := gitOut(t, "rev-parse", "--show-toplevel")
	wantURL := "r2://bkt/" + filepath.Base(top)
	if url, _ := gitOut(t, "remote", "get-url", "upstream"); url != wantURL {
		t.Errorf("remote url = %q, want %q", url, wantURL)
	}
	if v, _ := gitOut(t, "config", "remote.upstream.endpoint"); v != "http://127.0.0.1:9000" {
		t.Errorf("endpoint = %q", v)
	}
}

func TestWizardReusesExistingRemote(t *testing.T) {
	setupRepo(t)
	gitOut(t, "remote", "add", "origin", "r2://old-bucket/old-prefix")
	out, err := runWithInput(t, "\n", "--no-verify") // Enter = "Y", use it
	if err != nil {
		t.Fatalf("wizard setup failed: %v\n%s", err, out)
	}
	if url, _ := gitOut(t, "remote", "get-url", "origin"); url != "r2://old-bucket/old-prefix" {
		t.Errorf("remote url = %q", url)
	}
}

func TestWizardAbortsOnClosedInput(t *testing.T) {
	setupRepo(t)
	if out, err := runWithInput(t, "", "--no-verify"); err == nil {
		t.Fatalf("wizard with no input must abort cleanly:\n%s", out)
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
	if _, err := run(t, "--no-verify", "--encryption", "rot13", "r2://b/p"); err == nil {
		t.Error("bad encryption mode should be rejected")
	}

	// Outside a git repository.
	t.Chdir(t.TempDir())
	if _, err := run(t, "--no-verify", "r2://bucket/proj"); err == nil {
		t.Error("setup outside a git repo should fail")
	}
}
