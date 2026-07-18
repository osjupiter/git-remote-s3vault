// Package keycmd implements `git-remote-s3ee key ...`: access management for
// the repository's envelope encryption.
//
//	grant / list / revoke   manage who can unwrap the repository key (DEK)
//	recovery-init           (re)create the recovery key slot
//	recover                 regain access on a fresh machine using only the
//	                        recovery secret and the s3ee:// URL
//
// The recovery key is asymmetric on purpose: its public half lives in the
// bucket (.keys/dek/recovery.pub), so future DEK rotations can re-wrap for
// it without knowing any secret, while its secret half is shown exactly
// once and kept offline by the user.
package keycmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/osjupiter/git-remote-s3ee/internal/config"
	"github.com/osjupiter/git-remote-s3ee/internal/cryptox"
	"github.com/osjupiter/git-remote-s3ee/internal/keyring"
	"github.com/osjupiter/git-remote-s3ee/internal/rotation"
	"github.com/osjupiter/git-remote-s3ee/internal/storage"
)

// newStore is swapped out by tests to avoid a real S3 client.
var newStore = func(ctx context.Context, cfg *config.Config) (storage.Storage, error) {
	return storage.New(ctx, cfg)
}

// Run executes `key <grant|list|revoke|recovery-init|recover> [args] [flags]`.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	usage := func() {
		fmt.Fprintln(stderr, "usage: git-remote-s3ee key grant   <pubkey> [s3ee://...] [flags]   give another key access to the repo")
		fmt.Fprintln(stderr, "       git-remote-s3ee key list    [s3ee://bucket/prefix]          show who has access")
		fmt.Fprintln(stderr, "       git-remote-s3ee key revoke  <label|pubkey> [s3ee://...]     remove a key's access slot")
		fmt.Fprintln(stderr, "       git-remote-s3ee key recovery-init [s3ee://...] [flags]      (re)create the recovery key")
		fmt.Fprintln(stderr, "       git-remote-s3ee key recover [s3ee://bucket/prefix] [flags]  regain access with the recovery secret")
		fmt.Fprintln(stderr, "       git-remote-s3ee key rotate  [s3ee://bucket/prefix] [flags]  re-encrypt everything under a new key")
		fmt.Fprintln(stderr, "The URL may be omitted inside a repository that already has an s3ee:// remote.")
	}
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing subcommand")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "grant", "list", "revoke", "recovery-init", "recover", "rotate":
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", sub)
	}

	fs := flag.NewFlagSet("git-remote-s3ee key "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "git remote to resolve the URL from when no URL argument is given")
	name := fs.String("name", "", "grant: slot label for the new key (default: fingerprint of the public key)")
	identityFlag := fs.String("identity", "", "identity file to use; default: configured or ~/.config/git-remote-s3ee/identity.txt")
	yes := fs.Bool("yes", false, "rotate: skip the confirmation prompt")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	// grant/revoke take a key argument before the optional URL.
	var target string
	pos := fs.Args()
	if sub == "grant" || sub == "revoke" {
		if len(pos) == 0 {
			usage()
			return fmt.Errorf("%s requires a public key (or slot label) argument", sub)
		}
		target, pos = pos[0], pos[1:]
	}
	if len(pos) > 1 {
		return fmt.Errorf("at most one URL argument is allowed")
	}

	rawURL := ""
	if len(pos) == 1 {
		rawURL = pos[0]
	}
	if rawURL == "" {
		var err error
		rawURL, err = remoteURL(*remote)
		if err != nil {
			return fmt.Errorf("no URL given and none found on remote %q (outside a repo, pass the s3ee:// URL explicitly): %w", *remote, err)
		}
	}
	if err := config.ValidateURL(rawURL); err != nil {
		return err
	}
	cfg, err := config.Load(*remote, rawURL)
	if err != nil {
		return err
	}
	store, err := newStore(ctx, cfg)
	if err != nil {
		return err
	}

	switch sub {
	case "grant":
		return grant(ctx, store, cfg, target, *name, *identityFlag, rawURL, stdout)
	case "list":
		return list(ctx, store, cfg, stdout)
	case "revoke":
		return revoke(ctx, store, cfg, target, stdout)
	case "recovery-init":
		return recoveryInit(ctx, store, cfg, *identityFlag, rawURL, stdout)
	case "rotate":
		return rotate(ctx, store, cfg, *identityFlag, *yes, stdout)
	default:
		return recover_(ctx, store, cfg, *identityFlag, rawURL, stdout)
	}
}

// rotate re-encrypts the whole remote under a fresh DEK (new kopia master
// key included), then removes the old generation. See internal/rotation.
func rotate(ctx context.Context, store storage.Storage, cfg *config.Config, identityFlag string, yes bool, stdout io.Writer) error {
	var dekOld *age.X25519Identity
	if cfg.Encryption == config.EncryptionAge {
		var err error
		if dekOld, err = unwrapDEK(ctx, store, cfg, identityFlag); err != nil {
			return err
		}
	}

	if !yes {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("no terminal for the confirmation prompt; pass --yes to proceed")
		}
		fmt.Fprintf(tty, "This re-encrypts and re-uploads the ENTIRE repository under a new key,\n")
		fmt.Fprintf(tty, "then deletes the old data. Revoke unwanted key slots first.\n")
		fmt.Fprintf(tty, "Proceed? [y/N]: ")
		line := make([]byte, 8)
		n, _ := tty.Read(line)
		tty.Close()
		if a := strings.ToLower(strings.TrimSpace(string(line[:n]))); a != "y" && a != "yes" {
			return fmt.Errorf("rotation aborted; nothing was changed")
		}
	}

	rot, err := rotation.New(ctx, cfg, store, dekOld, stdout)
	if err != nil {
		return err
	}
	if err := rot.Run(ctx); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "✓ rotation complete (%s → %s)\n", rot.CurGen, rot.NextGen)
	fmt.Fprintf(stdout, "Recommended follow-ups:\n")
	fmt.Fprintf(stdout, "  - rotate the bucket's S3 API token too: a removed member may have retained\n")
	fmt.Fprintf(stdout, "    key material cached locally, and without ciphertext access it is useless\n")
	fmt.Fprintf(stdout, "  - teammates need no action; their existing keys were re-wrapped\n")
	return nil
}

// unwrapDEK loads local identities and recovers the repository key.
func unwrapDEK(ctx context.Context, store storage.Storage, cfg *config.Config, identityFlag string) (*age.X25519Identity, error) {
	idPath, err := identityPath(identityFlag, cfg)
	if err != nil {
		return nil, err
	}
	ids, err := cryptox.LoadIdentityFiles([]string{idPath})
	if err != nil {
		return nil, err
	}
	kr := keyring.New(store, cfg.Prefix)
	if _, exists, err := kr.RepoRecipient(ctx); err != nil {
		return nil, err
	} else if !exists {
		return nil, fmt.Errorf("this remote has no repository key yet; push once (or run setup with credentials) first")
	}
	dek, ok, err := kr.Unwrap(ctx, ids)
	if err != nil {
		return nil, err
	}
	if !ok {
		// The identity file may hold the DEK itself.
		for _, id := range ids {
			if x, okX := id.(*age.X25519Identity); okX {
				if r, _, _ := kr.RepoRecipient(ctx); r != nil {
					if xr, okR := r.(*age.X25519Recipient); okR && xr.String() == x.Recipient().String() {
						return x, nil
					}
				}
			}
		}
		return nil, fmt.Errorf("this machine's key (%s) cannot unwrap the repository key; ask a member to run `git-remote-s3ee key grant <your-public-key>`", idPath)
	}
	return dek, nil
}

func grant(ctx context.Context, store storage.Storage, cfg *config.Config, pubkey, label, identityFlag, rawURL string, stdout io.Writer) error {
	if _, err := cryptox.ParseRecipients([]string{pubkey}); err != nil {
		return err
	}
	dek, err := unwrapDEK(ctx, store, cfg, identityFlag)
	if err != nil {
		return err
	}
	kr := keyring.New(store, cfg.Prefix)
	if err := kr.Grant(ctx, dek, pubkey, label); err != nil {
		return err
	}
	if label == "" {
		label = keyring.DefaultLabel(pubkey)
	}
	fmt.Fprintf(stdout, "✓ access granted to %s (slot %q)\n", pubkey, label)
	fmt.Fprintf(stdout, "No re-encryption needed — the entire existing history is immediately readable.\n")
	fmt.Fprintf(stdout, "They can clone right away:\n  git clone %s\n", rawURL)
	return nil
}

func list(ctx context.Context, store storage.Storage, cfg *config.Config, stdout io.Writer) error {
	kr := keyring.New(store, cfg.Prefix)
	if _, exists, err := kr.RepoRecipient(ctx); err != nil {
		return err
	} else if !exists {
		fmt.Fprintln(stdout, "no repository key yet (it is created on the first push)")
		return nil
	}
	slots, err := kr.Slots(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%d key slot(s) can unwrap this repository's key:\n", len(slots))
	for _, s := range slots {
		rec := s.Recipient
		if rec == "" {
			rec = "(recipient not recorded)"
		}
		fmt.Fprintf(stdout, "  %-14s %s\n", s.Label, rec)
	}
	return nil
}

func revoke(ctx context.Context, store storage.Storage, cfg *config.Config, target string, stdout io.Writer) error {
	kr := keyring.New(store, cfg.Prefix)
	slot, err := kr.Revoke(ctx, target)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "✓ removed key slot %q\n", slot.Label)
	fmt.Fprintf(stdout, "⚠ anyone who already unwrapped the repository key can still decrypt existing\n")
	fmt.Fprintf(stdout, "  data; for a hard cut-off, run `git-remote-s3ee key rotate`.\n")
	if slot.Label == keyring.RecoveryLabel {
		fmt.Fprintf(stdout, "⚠ you removed the RECOVERY slot; run `git-remote-s3ee key recovery-init` to create a new one.\n")
	}
	return nil
}

// recoveryInit creates (or replaces) the recovery key slot. Replacing it
// invalidates any previously issued recovery secret for future unwraps.
func recoveryInit(ctx context.Context, store storage.Storage, cfg *config.Config, identityFlag, rawURL string, stdout io.Writer) error {
	dek, err := unwrapDEK(ctx, store, cfg, identityFlag)
	if err != nil {
		return err
	}
	recovery, err := age.GenerateX25519Identity()
	if err != nil {
		return err
	}
	kr := keyring.New(store, cfg.Prefix)
	if err := kr.Grant(ctx, dek, recovery.Recipient().String(), keyring.RecoveryLabel); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "✓ recovery key created — store this line in a password manager or on paper:\n")
	fmt.Fprintf(stdout, "\n    %s\n\n", recovery)
	fmt.Fprintf(stdout, "  It will NOT be shown again, and it replaces any previous recovery key.\n")
	fmt.Fprintf(stdout, "  Recover from any machine with:\n    git-remote-s3ee key recover %s\n", rawURL)
	return nil
}

// recover_ rebuilds access on a fresh machine: the recovery secret unwraps
// the DEK, a local identity is created (or reused), and that identity is
// granted its own slot so the recovery secret can go back in the drawer.
func recover_(ctx context.Context, store storage.Storage, cfg *config.Config, identityFlag, rawURL string, stdout io.Writer) error {
	secret, err := readRecoverySecret()
	if err != nil {
		return err
	}
	recoveryID, err := age.ParseX25519Identity(strings.TrimSpace(secret))
	if err != nil {
		return fmt.Errorf("that does not look like a recovery key (expected AGE-SECRET-KEY-1...): %w", err)
	}

	kr := keyring.New(store, cfg.Prefix)
	dek, ok, err := kr.Unwrap(ctx, []age.Identity{recoveryID})
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("this recovery key cannot unwrap the repository key (wrong key, or the recovery slot was replaced)")
	}

	idPath, created, recips, err := cryptox.EnsureIdentityFile(identityFlag)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(stdout, "✓ generated this machine's key (age identity): %s\n", idPath)
	} else {
		fmt.Fprintf(stdout, "✓ using this machine's existing key: %s\n", idPath)
	}
	granted := 0
	for _, r := range recips {
		if err := kr.Grant(ctx, dek, r, ""); err != nil {
			return err
		}
		granted++
	}
	if granted == 0 {
		return fmt.Errorf("no X25519 public key could be derived from %s", idPath)
	}
	fmt.Fprintf(stdout, "✓ this machine's key now has access (%d slot(s) added)\n", granted)
	fmt.Fprintf(stdout, "\nYou can now clone:\n  git clone %s\n", rawURL)
	fmt.Fprintf(stdout, "Put the recovery key back somewhere safe — it stays valid.\n")
	return nil
}

// identityPath picks the identity file: explicit flag, then the configured
// identity, then the default location.
func identityPath(flagValue string, cfg *config.Config) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if len(cfg.IdentityFiles) > 0 {
		return cfg.IdentityFiles[0], nil
	}
	return cryptox.DefaultIdentityPath()
}

// readRecoverySecret takes the recovery key from the environment (for
// non-interactive use) or prompts on the controlling terminal (echo off).
func readRecoverySecret() (string, error) {
	if v := os.Getenv("GIT_REMOTE_S3EE_RECOVERY_KEY"); v != "" {
		return v, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal available for the recovery key prompt; set GIT_REMOTE_S3EE_RECOVERY_KEY")
	}
	defer tty.Close()
	fmt.Fprint(tty, "recovery key (AGE-SECRET-KEY-...): ")
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("recovery key must not be empty")
	}
	return string(b), nil
}

func remoteURL(remote string) (string, error) {
	out, err := exec.Command("git", "remote", "get-url", remote).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
