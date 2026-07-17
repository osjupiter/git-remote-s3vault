// Package setupcmd implements `git-remote-r2 setup`, a one-shot command
// that wires an existing git repository up to an encrypted R2/S3 remote:
// it generates an age key if needed, registers the remote, stores all
// settings in repo-local git config, and checks connectivity.
package setupcmd

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"filippo.io/age"
	"golang.org/x/term"

	"github.com/osjupiter/git-remote-r2/internal/config"
	"github.com/osjupiter/git-remote-r2/internal/credstore"
	"github.com/osjupiter/git-remote-r2/internal/cryptox"
	"github.com/osjupiter/git-remote-r2/internal/keyring"
	"github.com/osjupiter/git-remote-r2/internal/storage"
)

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// Run executes the setup command. args are the arguments after "setup".
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("git-remote-r2 setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	remote := fs.String("remote", "origin", "name of the git remote to create or update")
	accountID := fs.String("account-id", "", "Cloudflare account ID (stored in repo config)")
	endpoint := fs.String("endpoint", "", "explicit S3 endpoint URL (MinIO, AWS, ...)")
	identityPath := fs.String("identity", "", "age identity file (default: ~/.config/git-remote-r2/identity.txt, generated if missing)")
	encryption := fs.String("encryption", "age", `encryption mode: "age" (default) or "none"`)
	noVerify := fs.Bool("no-verify", false, "skip the connectivity check against the bucket")
	var extraRecipients stringList
	fs.Var(&extraRecipients, "recipient", "additional age recipient (repeatable): teammate or CI public key")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: git-remote-r2 setup <r2://bucket/prefix> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("exactly one remote URL argument is required")
	}
	rawURL := fs.Arg(0)
	if err := config.ValidateURL(rawURL); err != nil {
		return err
	}
	if *encryption != string(config.EncryptionAge) && *encryption != string(config.EncryptionNone) {
		return fmt.Errorf("invalid --encryption %q (want \"age\" or \"none\")", *encryption)
	}

	// Must run inside the repository we are configuring.
	if err := runGit(nil, "rev-parse", "--git-dir"); err != nil {
		return fmt.Errorf("not inside a git repository (run this from the repo you want to connect): %w", err)
	}

	// 1. Encryption keys.
	var ownRecipients []string
	var idPath string
	if *encryption == string(config.EncryptionAge) {
		var created bool
		var recips []string
		var err error
		idPath, created, recips, err = cryptox.EnsureIdentityFile(*identityPath)
		if err != nil {
			return err
		}
		ownRecipients = recips
		if created {
			fmt.Fprintf(stdout, "✓ generated this machine's key (age identity): %s\n", idPath)
		} else {
			fmt.Fprintf(stdout, "✓ using this machine's existing key: %s\n", idPath)
		}
		if *identityPath != "" {
			if err := runGit(nil, "config", "remote."+*remote+".ageidentityfile", idPath); err != nil {
				return err
			}
		}
		if len(ownRecipients) == 0 && len(extraRecipients) == 0 {
			return fmt.Errorf("could not derive a recipient from %s and no --recipient was given", idPath)
		}
	}

	// 2. Register (or repoint) the remote.
	if err := runGit(nil, "remote", "get-url", *remote); err != nil {
		if err := runGit(nil, "remote", "add", *remote, rawURL); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ added remote %q → %s\n", *remote, rawURL)
	} else {
		if err := runGit(nil, "remote", "set-url", *remote, rawURL); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ updated remote %q → %s\n", *remote, rawURL)
	}

	// 3. Persist settings in repo-local config, scoped to this remote.
	scope := "remote." + *remote + "."
	if *accountID != "" {
		if err := runGit(nil, "config", scope+"accountid", *accountID); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ set account ID (endpoint https://%s.r2.cloudflarestorage.com)\n", *accountID)
	}
	if *endpoint != "" {
		if err := runGit(nil, "config", scope+"endpoint", *endpoint); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ set endpoint %s\n", *endpoint)
	}

	if *encryption == string(config.EncryptionNone) {
		if err := runGit(nil, "config", scope+"encryption", "none"); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "⚠ encryption disabled: bundles will be stored in PLAINTEXT\n")
	} else {
		wanted := append(append([]string{}, ownRecipients...), extraRecipients...)
		if _, err := cryptox.ParseRecipients(wanted); err != nil {
			return err
		}
		existing := gitConfigGetAll(scope + "agerecipients")
		added := 0
		for _, r := range wanted {
			if slices.Contains(existing, r) {
				continue
			}
			if err := runGit(nil, "config", "--add", scope+"agerecipients", r); err != nil {
				return err
			}
			existing = append(existing, r)
			added++
		}
		fmt.Fprintf(stdout, "✓ %d recipient(s) configured (%d added)\n", len(existing), added)
		for _, r := range existing {
			fmt.Fprintf(stdout, "    %s\n", r)
		}
	}

	// 4. Credentials, connectivity check, repository key initialization.
	if !*noVerify {
		cfg, err := config.Load(*remote, rawURL)
		if err != nil {
			return err
		}
		reportSavedCredentials(cfg, stdout)
		if cfg.AccessKeyID == "" && promptCredentials(cfg, stdout) {
			if cfg, err = config.Load(*remote, rawURL); err != nil {
				return err
			}
		}
		store, err := storage.New(ctx, cfg)
		if err == nil {
			err = checkBucket(ctx, store, cfg, stdout)
		}
		if err != nil {
			fmt.Fprintf(stdout, "✗ connectivity check failed: %v\n", err)
			fmt.Fprintf(stdout, "  (re-run setup to enter credentials interactively, set AWS_ACCESS_KEY_ID/\n")
			fmt.Fprintf(stdout, "   AWS_SECRET_ACCESS_KEY or R2_* env vars, or skip this check with --no-verify)\n")
			return fmt.Errorf("setup incomplete: bucket not reachable")
		}
		if *encryption == string(config.EncryptionAge) {
			if err := syncKeyring(ctx, store, cfg, idPath, append(append([]string{}, ownRecipients...), extraRecipients...), stdout); err != nil {
				return err
			}
		}
	} else if *encryption == string(config.EncryptionAge) {
		fmt.Fprintf(stdout, "• repository key not initialized (--no-verify); it will be created on your first push\n")
	}

	fmt.Fprintf(stdout, "\nAll set. Next:\n")
	fmt.Fprintf(stdout, "  git push -u %s <branch>\n", *remote)
	if *encryption == string(config.EncryptionAge) {
		fmt.Fprintf(stdout, "  # add a teammate: git-remote-r2 key grant <their-age-public-key>\n")
	}
	return nil
}

// reportSavedCredentials tells the user when credentials came from the
// on-disk store rather than the environment.
func reportSavedCredentials(cfg *config.Config, stdout io.Writer) {
	envHasCreds := os.Getenv("R2_ACCESS_KEY_ID") != "" || os.Getenv("AWS_ACCESS_KEY_ID") != ""
	if envHasCreds || cfg.AccessKeyID == "" {
		return
	}
	if path, err := credstore.Path(); err == nil {
		fmt.Fprintf(stdout, "✓ using saved credentials from %s\n", path)
	}
}

// promptCredentials interactively collects and stores an access key pair
// when none could be resolved. Returns true if credentials were saved.
// Without a terminal it quietly leaves resolution to the AWS default chain.
func promptCredentials(cfg *config.Config, stdout io.Writer) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(stdout, "• no stored S3 credentials; relying on the AWS default chain\n")
		return false
	}
	defer tty.Close()

	credPath, _ := credstore.Path()
	fmt.Fprintf(tty, "\nNo S3 credentials found (checked the environment and %s).\n", credPath)
	fmt.Fprintf(tty, "Tip: create an R2 API token scoped to ONLY this bucket (Object Read & Write),\n")
	fmt.Fprintf(tty, "     so that a leaked key cannot touch anything else.\n\n")
	fmt.Fprintf(tty, "Access Key ID (leave empty to skip and use the AWS default chain): ")

	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return false
	}
	keyID := strings.TrimSpace(line)
	if keyID == "" {
		return false
	}
	fmt.Fprintf(tty, "Secret Access Key: ")
	secretBytes, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return false
	}
	secret := strings.TrimSpace(string(secretBytes))
	if secret == "" {
		fmt.Fprintf(tty, "✗ empty secret; skipping\n")
		return false
	}

	// Bucket-scoped tokens are the recommended setup, so bucket-scoped
	// storage is the default; account-wide is one keystroke away.
	bucket := cfg.Bucket
	fmt.Fprintf(tty, "Scope: [B] this bucket only (%s, recommended) / [a] whole account: ", cfg.Bucket)
	scopeLine, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return false
	}
	scopeNote := "for bucket " + cfg.Bucket
	if s := strings.ToLower(strings.TrimSpace(scopeLine)); s == "a" || s == "account" {
		bucket = ""
		scopeNote = "shared by every repo on this account"
	}

	path, section, err := credstore.Save(cfg.AccountID, cfg.Endpoint, bucket,
		credstore.Credentials{AccessKeyID: keyID, SecretAccessKey: secret})
	if err != nil {
		fmt.Fprintf(tty, "✗ could not save credentials: %v\n", err)
		return false
	}
	fmt.Fprintf(stdout, "✓ credentials saved to %s [%s] — %s\n", path, section, scopeNote)
	return true
}

func checkBucket(ctx context.Context, store storage.Storage, cfg *config.Config, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	objs, err := store.List(ctx, cfg.Prefix)
	if err != nil {
		return err
	}
	if len(objs) == 0 {
		fmt.Fprintf(stdout, "✓ bucket reachable; remote is empty (first push will initialize it)\n")
	} else {
		fmt.Fprintf(stdout, "✓ bucket reachable; found %d existing object(s) under the prefix\n", len(objs))
	}
	return nil
}

// syncKeyring creates the repository key on a fresh remote, or grants any
// not-yet-covered recipients on an existing one (requiring that the local
// identity can unwrap the key).
func syncKeyring(ctx context.Context, store storage.Storage, cfg *config.Config, idPath string, wanted []string, stdout io.Writer) error {
	kr := keyring.New(store, cfg.Prefix)
	_, exists, err := kr.RepoRecipient(ctx)
	if err != nil {
		return err
	}
	if !exists {
		dek, err := kr.Init(ctx, wanted)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ repository key created; wrapped for %d public key(s)\n", len(wanted))

		// Recovery key: an extra X25519 keypair whose public half lives in
		// the bucket (so future key rotations can re-wrap for it without
		// any secret) and whose secret half is shown exactly once.
		recovery, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		if err := kr.Grant(ctx, dek, recovery.Recipient().String(), keyring.RecoveryLabel); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "✓ recovery key created — store this line in a password manager or on paper:\n")
		fmt.Fprintf(stdout, "\n    %s\n\n", recovery)
		fmt.Fprintf(stdout, "  It will NOT be shown again. Anyone holding it can decrypt this repository.\n")
		fmt.Fprintf(stdout, "  If you ever lose all devices, recover with:\n")
		fmt.Fprintf(stdout, "    git-remote-r2 key recover %s\n", cfg.RawURL)
		return nil
	}

	slots, err := kr.Slots(ctx)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	hasRecovery := false
	for _, s := range slots {
		have[s.Recipient] = true
		if s.Label == keyring.RecoveryLabel {
			hasRecovery = true
		}
	}
	if !hasRecovery {
		fmt.Fprintf(stdout, "• this repository has no recovery key; consider `git-remote-r2 key recovery-init`\n")
	}
	var missing []string
	for _, w := range wanted {
		if !have[strings.TrimSpace(w)] {
			missing = append(missing, w)
		}
	}
	if len(missing) == 0 {
		fmt.Fprintf(stdout, "✓ repository key exists; all %d local recipient(s) already have access\n", len(wanted))
		return nil
	}

	ids, err := cryptox.LoadIdentityFiles([]string{idPath})
	if err != nil {
		return err
	}
	dek, ok, err := kr.Unwrap(ctx, ids)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintf(stdout, "⚠ repository key exists but this machine's key cannot unwrap it.\n")
		fmt.Fprintf(stdout, "  Ask an existing member to grant you access:\n")
		for _, m := range missing {
			fmt.Fprintf(stdout, "    git-remote-r2 key grant %s %s\n", m, cfg.RawURL)
		}
		return nil
	}
	for _, m := range missing {
		if err := kr.Grant(ctx, dek, m, ""); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "✓ repository key: granted access to %d new public key(s)\n", len(missing))
	return nil
}

func runGit(env []string, args ...string) error {
	cmd := exec.Command("git", args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errBuf.String())
		if msg != "" {
			return fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
		}
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func gitConfigGetAll(key string) []string {
	out, err := exec.Command("git", "config", "--get-all", key).Output()
	if err != nil {
		return nil
	}
	var vals []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			vals = append(vals, l)
		}
	}
	return vals
}
