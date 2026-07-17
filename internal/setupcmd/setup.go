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
	"path/filepath"
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

// Run executes the setup command. args are the arguments after "setup";
// stdin feeds the interactive wizard that starts when no URL is given.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
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
		fmt.Fprintf(stderr, "usage: git-remote-r2 setup [r2://bucket/prefix] [flags]\n")
		fmt.Fprintf(stderr, "(with no URL, an interactive wizard asks for everything)\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		fs.Usage()
		return fmt.Errorf("at most one remote URL argument is allowed")
	}
	if *encryption != string(config.EncryptionAge) && *encryption != string(config.EncryptionNone) {
		return fmt.Errorf("invalid --encryption %q (want \"age\" or \"none\")", *encryption)
	}

	// Must run inside the repository we are configuring.
	if err := runGit(nil, "rev-parse", "--git-dir"); err != nil {
		return fmt.Errorf("not inside a git repository (run this from the repo you want to connect): %w", err)
	}

	rawURL := fs.Arg(0)
	var wizKey *keyCandidate
	var wizCredsSaved bool
	if rawURL == "" {
		answers, err := runWizard(stdin, stdout, *remote, *encryption)
		if err != nil {
			return err
		}
		rawURL = answers.rawURL
		*remote = answers.remoteName
		wizKey = answers.key
		wizCredsSaved = answers.credsSaved
		if answers.accountID != "" {
			*accountID = answers.accountID
		}
		if answers.endpoint != "" {
			*endpoint = answers.endpoint
		}
	}
	if err := config.ValidateURL(rawURL); err != nil {
		return err
	}

	// 1. Encryption keys.
	var ownRecipients []string
	var idPath string
	if *encryption == string(config.EncryptionAge) {
		if wizKey != nil {
			// The wizard already picked (or generated) exactly one key.
			ownRecipients = []string{wizKey.recipient}
			if wizKey.identityPath != "" {
				idPath = wizKey.identityPath
				if err := runGit(nil, "config", "remote."+*remote+".ageidentityfile", idPath); err != nil {
					return err
				}
			} else {
				var err error
				if idPath, err = cryptox.DefaultIdentityPath(); err != nil {
					return err
				}
			}
		} else {
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
		if !wizCredsSaved {
			reportSavedCredentials(cfg, stdout)
		}
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
			fmt.Fprintf(stdout, "   AWS_SECRET_ACCESS_KEY env vars, or skip this check with --no-verify)\n")
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

// wizardAnswers is what the interactive wizard collects.
type wizardAnswers struct {
	rawURL     string
	remoteName string
	accountID  string
	endpoint   string
	key        *keyCandidate
	credsSaved bool
}

// runWizard interactively assembles the remote URL, backend settings, and
// key choice. Every question has a sensible default so Enter-Enter-Enter
// works.
func runWizard(stdin io.Reader, stdout io.Writer, defaultRemote, encryption string) (*wizardAnswers, error) {
	in := bufio.NewReader(stdin)
	ask := func(label, def string) (string, error) {
		if def != "" {
			fmt.Fprintf(stdout, "%s [%s]: ", label, def)
		} else {
			fmt.Fprintf(stdout, "%s: ", label)
		}
		line, err := in.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("setup aborted (input closed)")
		}
		if v := sanitizeAnswer(line); v != "" {
			return v, nil
		}
		return def, nil
	}

	fmt.Fprintf(stdout, "Interactive setup — Enter accepts the [default].\n\n")
	a := &wizardAnswers{}

	// Re-runs: offer the repository's existing r2:// remote right away.
	if existing, err := gitOutput("remote", "get-url", defaultRemote); err == nil {
		if config.ValidateURL(existing) == nil {
			use, err := ask(fmt.Sprintf("Found remote %q → %s — use it?", defaultRemote, existing), "Y")
			if err != nil {
				return nil, err
			}
			if s := strings.ToLower(use); s == "y" || s == "yes" {
				a.rawURL = existing
				a.remoteName = defaultRemote
				if encryption == string(config.EncryptionAge) {
					if a.key, err = pickKey(ask, stdout); err != nil {
						return nil, err
					}
				}
				return a, nil
			}
		}
	}

	// Backend: default to whichever the environment already hints at.
	backendDefault := "1"
	if os.Getenv("R2_ACCOUNT_ID") == "" && os.Getenv("CLOUDFLARE_ACCOUNT_ID") == "" &&
		(os.Getenv("AWS_ENDPOINT_URL") != "" || os.Getenv("AWS_ENDPOINT_URL_S3") != "") {
		backendDefault = "2"
	}
	fmt.Fprintf(stdout, "Backend:\n  1) Cloudflare R2\n  2) Other S3-compatible storage (MinIO, AWS S3, ...)\n")
	for {
		choice, err := ask("Backend", backendDefault)
		if err != nil {
			return nil, err
		}
		switch choice {
		case "1":
			def := firstNonEmptyEnv("R2_ACCOUNT_ID", "CLOUDFLARE_ACCOUNT_ID")
			if a.accountID, err = ask("Cloudflare account ID", def); err != nil {
				return nil, err
			}
			if a.accountID == "" {
				fmt.Fprintf(stdout, "An account ID is required for R2.\n")
				continue
			}
		case "2":
			def := firstNonEmptyEnv("AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL")
			if a.endpoint, err = ask("Endpoint URL (empty for AWS S3)", def); err != nil {
				return nil, err
			}
		default:
			fmt.Fprintf(stdout, "Please answer 1 or 2.\n")
			continue
		}
		break
	}

	// Credentials come right after the backend, before the bucket, so all
	// connection settings are entered in one block.
	var creds *credstore.Credentials
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		fmt.Fprintf(stdout, "✓ using credentials from the environment\n")
	} else {
		fmt.Fprintf(stdout, "Credentials — tip: use an API token scoped to ONLY the target bucket\n")
		fmt.Fprintf(stdout, "(Object Read & Write), so a leaked key cannot touch anything else.\n")
		keyID, err := ask("Access Key ID (empty to configure later)", "")
		if err != nil {
			return nil, err
		}
		if keyID != "" {
			secret, err := askSecret(in, stdout, "Secret Access Key")
			if err != nil {
				return nil, err
			}
			if secret == "" {
				return nil, fmt.Errorf("empty secret access key")
			}
			creds = &credstore.Credentials{AccessKeyID: keyID, SecretAccessKey: secret}
		}
	}

	var bucket string
	for bucket == "" {
		var err error
		if bucket, err = ask("Bucket name", ""); err != nil {
			return nil, err
		}
	}

	prefixDefault := ""
	if top, err := gitOutput("rev-parse", "--show-toplevel"); err == nil {
		prefixDefault = filepath.Base(top)
	}
	prefix, err := ask("Prefix inside the bucket", prefixDefault)
	if err != nil {
		return nil, err
	}
	if a.remoteName, err = ask("Remote name", defaultRemote); err != nil {
		return nil, err
	}

	if encryption == string(config.EncryptionAge) {
		if a.key, err = pickKey(ask, stdout); err != nil {
			return nil, err
		}
	}

	a.rawURL = "r2://" + bucket
	if p := strings.Trim(prefix, "/"); p != "" {
		a.rawURL += "/" + p
	}

	// Final confirmation catches paste accidents (a remote named "]", a
	// bucket with a stray newline, ...) before anything is written.
	confirm, err := ask(fmt.Sprintf("Create remote %q → %s?", a.remoteName, a.rawURL), "Y")
	if err != nil {
		return nil, err
	}
	if s := strings.ToLower(confirm); s != "y" && s != "yes" {
		return nil, fmt.Errorf("setup aborted; nothing was changed")
	}

	// Persist credentials only after the confirmation: an aborted wizard
	// leaves no trace.
	if creds != nil {
		path, section, err := credstore.Save(a.accountID, a.endpoint, bucket, *creds)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(stdout, "✓ credentials saved to %s [%s]\n", path, section)
		a.credsSaved = true
	}
	fmt.Fprintf(stdout, "\n")
	return a, nil
}

// askSecret reads a secret with echo off on the controlling terminal,
// falling back to the wizard's input stream when no terminal is available
// (piped input, tests).
func askSecret(in *bufio.Reader, stdout io.Writer, label string) (string, error) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		fmt.Fprintf(tty, "%s: ", label)
		b, rerr := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		if rerr != nil {
			return "", rerr
		}
		return sanitizeAnswer(string(b)), nil
	}
	fmt.Fprintf(stdout, "%s: ", label)
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("setup aborted (input closed)")
	}
	return sanitizeAnswer(line), nil
}

// sanitizeAnswer strips bracketed-paste markers and control characters
// that terminals inject into pasted text; without this a paste accident
// can silently produce a remote named "]" or a bucket with an ESC in it.
func sanitizeAnswer(line string) string {
	for _, marker := range []string{"\x1b[200~", "\x1b[201~"} {
		line = strings.ReplaceAll(line, marker, "")
	}
	line = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, line)
	return strings.TrimSpace(line)
}

func firstNonEmptyEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

// reportSavedCredentials tells the user when credentials came from the
// on-disk store rather than the environment.
func reportSavedCredentials(cfg *config.Config, stdout io.Writer) {
	envHasCreds := os.Getenv("AWS_ACCESS_KEY_ID") != ""
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
		fmt.Fprintf(stdout, "• no S3 credentials found; set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY\n")
		return false
	}
	defer tty.Close()

	credPath, _ := credstore.Path()
	fmt.Fprintf(tty, "\nNo S3 credentials found for bucket %q (checked the environment and %s).\n", cfg.Bucket, credPath)
	fmt.Fprintf(tty, "Tip: create an R2 API token scoped to ONLY this bucket (Object Read & Write),\n")
	fmt.Fprintf(tty, "     so that a leaked key cannot touch anything else.\n\n")
	fmt.Fprintf(tty, "Access Key ID (leave empty to skip): ")

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

	path, section, err := credstore.Save(cfg.AccountID, cfg.Endpoint, cfg.Bucket,
		credstore.Credentials{AccessKeyID: keyID, SecretAccessKey: secret})
	if err != nil {
		fmt.Fprintf(tty, "✗ could not save credentials: %v\n", err)
		return false
	}
	fmt.Fprintf(stdout, "✓ credentials saved to %s [%s]\n", path, section)
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

func gitOutput(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
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
