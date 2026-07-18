package keycmd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
	"github.com/osjupiter/git-remote-s3vault/internal/keyring"
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

var secretRe = regexp.MustCompile(`AGE-SECRET-KEY-1[0-9A-Z]+`)

// useMemStore routes all key commands in the test to one in-memory bucket.
func useMemStore(t *testing.T) *storage.Memory {
	t.Helper()
	mem := storage.NewMemory()
	orig := newStore
	newStore = func(context.Context, *config.Config) (storage.Storage, error) { return mem, nil }
	t.Cleanup(func() { newStore = orig })
	return mem
}

func writeIdentity(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "identity.txt")
	if err := os.WriteFile(p, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, id
}

// initKeyring seeds the mem store with a keyring owned by a fresh identity.
func initKeyring(t *testing.T, mem *storage.Memory) (string, *age.X25519Identity) {
	t.Helper()
	idPath, id := writeIdentity(t)
	kr := keyring.New(mem, "proj")
	if _, err := kr.Init(context.Background(), []string{id.Recipient().String()}); err != nil {
		t.Fatal(err)
	}
	return idPath, id
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Run(context.Background(), args, &out, &out)
	return out.String(), err
}

// inRepoWithRemote puts the test into a fresh repository whose origin is
// the standard test remote — grant is repository-scoped by design.
func inRepoWithRemote(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"remote", "add", "origin", "s3vault://bucket/proj"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func TestGrantListRevokeCLI(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	bob, _ := age.GenerateX25519Identity()
	inRepoWithRemote(t)

	// grant takes no URL: the repository's remote supplies it.
	if out, err := run(t, "grant", "--identity", idPath, "--name", "bob",
		bob.Recipient().String(), "s3vault://bucket/proj"); err == nil {
		t.Fatalf("grant with a URL argument must be rejected:\n%s", out)
	}
	out, err := run(t, "grant", "--identity", idPath, "--name", "bob", bob.Recipient().String())
	if err != nil {
		t.Fatalf("grant: %v\n%s", err, out)
	}
	if !strings.Contains(out, "No re-encryption needed") {
		t.Errorf("grant output:\n%s", out)
	}

	out, err = run(t, "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 key slot(s)") || !strings.Contains(out, bob.Recipient().String()) {
		t.Errorf("list output:\n%s", out)
	}

	if out, err = run(t, "revoke", "--identity", idPath, "bob"); err != nil {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	out, _ = run(t, "list")
	if !strings.Contains(out, "1 key slot(s)") {
		t.Errorf("bob's slot should be gone:\n%s", out)
	}
}

func TestGrantRequiresAccess(t *testing.T) {
	mem := useMemStore(t)
	initKeyring(t, mem)
	strangerPath, _ := writeIdentity(t) // not granted
	bob, _ := age.GenerateX25519Identity()

	inRepoWithRemote(t)
	out, err := run(t, "grant", "--identity", strangerPath, bob.Recipient().String())
	if err == nil {
		t.Fatalf("a stranger must not be able to grant:\n%s", out)
	}
	if !strings.Contains(err.Error(), "cannot unwrap") {
		t.Errorf("error should explain the problem: %v", err)
	}
}

func TestRecoveryInitAndRecover(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	inRepoWithRemote(t)

	out, err := run(t, "recovery-init", "--identity", idPath)
	if err != nil {
		t.Fatalf("recovery-init: %v\n%s", err, out)
	}
	secret := secretRe.FindString(out)
	if secret == "" {
		t.Fatalf("no recovery secret in output:\n%s", out)
	}
	if raw, ok := mem.Bytes("proj/.keys/dek/recovery.age"); !ok {
		t.Fatal("recovery slot missing")
	} else if bytes.Contains(raw, []byte("AGE-SECRET-KEY-")) {
		t.Fatal("recovery slot leaks a secret key")
	}

	// New machine: only the secret survives.
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", secret)
	newIDPath := filepath.Join(t.TempDir(), "new-machine.txt")
	out, err = run(t, "recover", "--identity", newIDPath, "s3vault://bucket/proj")
	if err != nil {
		t.Fatalf("recover: %v\n%s", err, out)
	}

	// The new machine's identity exists and can unwrap the DEK directly.
	ids, err := os.ReadFile(newIDPath)
	if err != nil {
		t.Fatal(err)
	}
	newID, err := age.ParseX25519Identity(strings.TrimSpace(secretRe.FindString(string(ids))))
	if err != nil {
		t.Fatalf("restored identity unparsable: %v", err)
	}
	kr := keyring.New(mem, "proj")
	if _, ok, err := kr.Unwrap(context.Background(), []age.Identity{newID}); err != nil || !ok {
		t.Fatalf("new machine's key cannot unwrap the DEK after recover: %v", err)
	}
}

func TestRecoverWithWrongKeyFails(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	inRepoWithRemote(t)
	if _, err := run(t, "recovery-init", "--identity", idPath); err != nil {
		t.Fatal(err)
	}

	wrong, _ := age.GenerateX25519Identity()
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", wrong.String())
	out, err := run(t, "recover", "--identity", filepath.Join(t.TempDir(), "x.txt"), "s3vault://bucket/proj")
	if err == nil {
		t.Fatalf("recover with a wrong key must fail:\n%s", out)
	}

	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", "not-a-key-at-all")
	if out, err := run(t, "recover", "s3vault://bucket/proj"); err == nil {
		t.Fatalf("garbage recovery key must fail:\n%s", out)
	}
}

func TestRecoveryInitReplacesOldSecret(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	inRepoWithRemote(t)

	out1, err := run(t, "recovery-init", "--identity", idPath)
	if err != nil {
		t.Fatal(err)
	}
	oldSecret := secretRe.FindString(out1)

	// Replacing the recovery key demands proof of the CURRENT secret —
	// without it (and without --force) the slot must survive untouched.
	if out, err := run(t, "recovery-init", "--identity", idPath); err == nil {
		t.Fatalf("replacement without the current secret must fail:\n%s", out)
	}
	wrong, _ := age.GenerateX25519Identity()
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", wrong.String())
	if out, err := run(t, "recovery-init", "--identity", idPath); err == nil {
		t.Fatalf("replacement with a WRONG secret must fail:\n%s", out)
	}

	// With the correct current secret it goes through.
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", oldSecret)
	out2, err := run(t, "recovery-init", "--identity", idPath)
	if err != nil {
		t.Fatal(err)
	}
	newSecret := secretRe.FindString(out2)
	if oldSecret == newSecret {
		t.Fatal("recovery-init must mint a fresh secret")
	}
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", "")

	// The old secret is dead, the new one works.
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", oldSecret)
	if _, err := run(t, "recover", "--identity", filepath.Join(t.TempDir(), "a.txt"), "s3vault://bucket/proj"); err == nil {
		t.Fatal("old recovery secret must be invalid after re-init")
	}
	t.Setenv("GIT_REMOTE_S3VAULT_RECOVERY_KEY", newSecret)
	if out, err := run(t, "recover", "--identity", filepath.Join(t.TempDir(), "b.txt"), "s3vault://bucket/proj"); err != nil {
		t.Fatalf("new recovery secret should work: %v\n%s", err, out)
	}
}

func TestKeyCommandUsage(t *testing.T) {
	if _, err := run(t, "frobnicate"); err == nil {
		t.Error("unknown subcommand should fail")
	}
	if _, err := run(t); err == nil {
		t.Error("missing subcommand should fail")
	}
	if _, err := run(t, "grant"); err == nil {
		t.Error("grant without a key argument should fail")
	}
}

// TestGrantRefusesTamperedKeyring: grant must abort when the keyring
// seal no longer matches (a slot was planted or swapped with bucket
// write access), and revoke of the rogue slot must repair it.
func TestGrantRefusesTamperedKeyring(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	inRepoWithRemote(t)
	ctx := context.Background()

	evil, _ := age.GenerateX25519Identity()
	pub := evil.Recipient().String() + "\n"
	if err := mem.Put(ctx, "proj/.keys/dek/evil.pub", strings.NewReader(pub), int64(len(pub))); err != nil {
		t.Fatal(err)
	}

	bob, _ := age.GenerateX25519Identity()
	out, err := run(t, "grant", "--identity", idPath, bob.Recipient().String())
	if err == nil || !strings.Contains(err.Error(), "integrity seal") {
		t.Fatalf("grant over a tampered keyring must abort, got %v\n%s", err, out)
	}

	// list flags the mismatch but still works.
	out, err = run(t, "list", "--identity", idPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "MISMATCH") {
		t.Fatalf("list should flag the broken seal:\n%s", out)
	}

	// revoke repairs; grant works again.
	if out, err := run(t, "revoke", "--identity", idPath, "evil"); err != nil {
		t.Fatalf("revoke must repair: %v\n%s", err, out)
	}
	if out, err := run(t, "grant", "--identity", idPath, bob.Recipient().String()); err != nil {
		t.Fatalf("grant after repair: %v\n%s", err, out)
	}
}

// TestRecoveryInitForceSkipsProof: --force replaces the recovery key
// without the current secret (the lost-secret escape hatch), with a
// warning.
func TestRecoveryInitForceSkipsProof(t *testing.T) {
	mem := useMemStore(t)
	idPath, _ := initKeyring(t, mem)
	inRepoWithRemote(t)

	if _, err := run(t, "recovery-init", "--identity", idPath); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "recovery-init", "--identity", idPath, "--force")
	if err != nil {
		t.Fatalf("--force must bypass the proof: %v\n%s", err, out)
	}
	if !strings.Contains(out, "WITHOUT verifying") {
		t.Fatalf("--force should warn loudly:\n%s", out)
	}
}
