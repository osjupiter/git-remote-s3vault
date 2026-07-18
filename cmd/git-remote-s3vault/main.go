// git-remote-s3vault is a git remote helper for Cloudflare R2 and any
// S3-compatible object store, with mandatory client-side age encryption.
//
// git invokes it as `git-remote-s3vault <remote-name> <url>` for URLs of the
// form s3vault://bucket/prefix. Symlink the binary to git-remote-s3 to also
// handle s3:// URLs.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
	"github.com/osjupiter/git-remote-s3vault/internal/helper"
	"github.com/osjupiter/git-remote-s3vault/internal/keycmd"
	"github.com/osjupiter/git-remote-s3vault/internal/setupcmd"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("git-remote-s3vault %s\n", version)
		return
	}
	// git exports GIT_DIR when spawning a remote helper, so its absence
	// distinguishes a user-typed `git-remote-s3vault setup ...` from git driving
	// a remote that happens to be named "setup".
	if len(os.Args) >= 2 && os.Args[1] == "setup" && os.Getenv("GIT_DIR") == "" {
		if err := setupcmd.Run(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "key" && os.Getenv("GIT_DIR") == "" {
		if err := keycmd.Run(ctx, os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "clone" && os.Getenv("GIT_DIR") == "" {
		if err := setupcmd.RunClone(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: git-remote-s3vault <remote-name> <url>")
		fmt.Fprintln(os.Stderr, "       git-remote-s3vault setup [s3vault://bucket/prefix] [flags]")
		fmt.Fprintln(os.Stderr, "       git-remote-s3vault clone <s3vault://bucket/prefix> [dir] [flags]")
		fmt.Fprintln(os.Stderr, "       git-remote-s3vault key grant|list|revoke|recovery-init|recover|rotate [args] [flags]")
		fmt.Fprintln(os.Stderr, "(without \"setup\", this program is a git remote helper run by git, not directly)")
		os.Exit(129)
	}
	remoteName, rawURL := os.Args[1], os.Args[2]

	cfg, err := config.Load(remoteName, rawURL)
	if err != nil {
		fatal(err)
	}
	h := helper.New(cfg, nil, os.Stdin, os.Stdout, os.Stderr)
	if err := h.Run(ctx); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "git-remote-s3vault: fatal: %v\n", err)
	os.Exit(128)
}
