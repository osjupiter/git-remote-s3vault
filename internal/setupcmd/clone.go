package setupcmd

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/osjupiter/git-remote-s3ee/internal/config"
	"github.com/osjupiter/git-remote-s3ee/internal/cryptox"
	"github.com/osjupiter/git-remote-s3ee/internal/keyring"
	"github.com/osjupiter/git-remote-s3ee/internal/storage"
)

// RunClone implements `git-remote-s3ee clone <url> [dir]`: the onboarding
// path for a second machine or a teammate. It prepares everything a plain
// `git clone` would need — machine key, credentials, access — with
// actionable errors when a step is missing, then runs git clone and
// persists the backend settings into the fresh repository.
func RunClone(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("git-remote-s3ee clone", flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("endpoint", "", "explicit S3 endpoint URL (MinIO, AWS, ...)")
	identityPath := fs.String("identity", "", "machine key file (default: ~/.config/git-remote-s3ee/identity.txt, generated if missing)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: git-remote-s3ee clone <s3ee://bucket/prefix> [directory] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return fmt.Errorf("expected a remote URL and an optional target directory")
	}
	rawURL := fs.Arg(0)
	if err := config.ValidateURL(rawURL); err != nil {
		return err
	}
	// Flags become env vars so both config.Load here and the helper spawned
	// by git clone resolve the same backend.
	if *endpoint != "" {
		os.Setenv("GIT_REMOTE_S3EE_ENDPOINT", *endpoint)
	}
	if *identityPath != "" {
		os.Setenv("GIT_REMOTE_S3EE_AGE_IDENTITY_FILE", *identityPath)
	}

	// 1. Machine key.
	idPath, created, recips, err := cryptox.EnsureIdentityFile(*identityPath)
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintf(stdout, "✓ generated this machine's key (age identity): %s\n", idPath)
	} else {
		fmt.Fprintf(stdout, "✓ using this machine's key: %s\n", idPath)
	}

	// 2. Credentials.
	cfg, err := config.Load("origin", rawURL)
	if err != nil {
		return err
	}
	reportSavedCredentials(cfg, stdout)
	if cfg.AccessKeyID == "" && promptCredentials(cfg, stdout) {
		if cfg, err = config.Load("origin", rawURL); err != nil {
			return err
		}
	}

	// 3. Access check — fail with instructions BEFORE git produces a
	// confusing decryption error.
	if cfg.Encryption == config.EncryptionAge {
		st, err := storage.New(ctx, cfg)
		if err != nil {
			return err
		}
		kr := keyring.New(st, cfg.Prefix)
		if _, exists, err := kr.RepoRecipient(ctx); err != nil {
			return err
		} else if !exists {
			return fmt.Errorf("no encrypted repository found at %s (never pushed to, or wrong URL?)", rawURL)
		}
		ids, err := cryptox.LoadIdentityFiles([]string{idPath})
		if err != nil {
			return err
		}
		if _, ok, err := kr.Access(ctx, ids); err != nil {
			return err
		} else if !ok {
			fmt.Fprintf(stdout, "✗ this machine's key has no access to the repository yet.\n\n")
			for _, r := range recips {
				fmt.Fprintf(stdout, "  Your public key:\n    %s\n\n", r)
				fmt.Fprintf(stdout, "  Ask a member to run:\n    git-remote-s3ee key grant %s %s\n\n", r, rawURL)
			}
			fmt.Fprintf(stdout, "  Or, if you hold the recovery key:\n    git-remote-s3ee key recover %s\n", rawURL)
			return fmt.Errorf("access not granted yet; re-run clone afterwards")
		}
		fmt.Fprintf(stdout, "✓ access confirmed\n")
	}

	// 4. The actual clone.
	dir := fs.Arg(1)
	if dir == "" {
		dir = deriveCloneDir(rawURL)
	}
	git := exec.CommandContext(ctx, "git", "clone", rawURL, dir)
	git.Stdout = stdout
	git.Stderr = stderr
	if err := git.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	// 5. Persist backend settings in the fresh repository so future
	// operations need no environment variables.
	persist := func(key, value string) error {
		if value == "" {
			return nil
		}
		cmd := exec.Command("git", "config", key, value)
		cmd.Dir = dir
		return cmd.Run()
	}
	if err := persist("remote.origin.endpoint", cfg.Endpoint); err != nil {
		return err
	}
	if *identityPath != "" {
		if err := persist("remote.origin.ageidentityfile", idPath); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "✓ cloned into %s\n", dir)
	return nil
}

// deriveCloneDir mimics git's target-directory derivation from a URL.
func deriveCloneDir(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "repo"
	}
	base := path.Base(strings.Trim(u.Path, "/"))
	if base == "" || base == "." || base == "/" {
		base = u.Host
	}
	return strings.TrimSuffix(base, ".git")
}
