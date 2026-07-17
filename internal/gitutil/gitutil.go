// Package gitutil shells out to git for the plumbing the helper needs:
// creating and unbundling bundles, resolving revisions, and checking
// ancestry for fast-forward enforcement.
package gitutil

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Git runs git commands against the repository the helper was invoked in.
// git sets GIT_DIR in the environment before spawning a remote helper, so
// plain inherited-env exec is sufficient.
type Git struct{}

func (Git) run(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// RevParse resolves a revision to an object ID.
func (g Git) RevParse(rev string) (string, error) {
	return g.run("rev-parse", "--verify", rev+"^{object}")
}

// HasObject reports whether the object exists in the local object database.
func (g Git) HasObject(sha string) bool {
	_, err := g.run("cat-file", "-e", sha)
	return err == nil
}

// IsAncestor reports whether ancestor is reachable from descendant,
// i.e. whether descendant is a fast-forward of ancestor.
func (g Git) IsAncestor(ancestor, descendant string) (bool, error) {
	cmd := exec.Command("git", "merge-base", "--is-ancestor", ancestor, descendant)
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("git merge-base --is-ancestor: %w", err)
}

// BundleCreate writes a self-contained bundle holding the full history of
// sha to path. Bundles need a ref name in their header, so the object is
// pinned under a temporary ref for the duration of the call.
func (g Git) BundleCreate(path, sha string) error {
	tmpRef := "refs/git-remote-s3ee/push-" + sha[:12]
	if _, err := g.run("update-ref", tmpRef, sha); err != nil {
		return err
	}
	defer g.run("update-ref", "-d", tmpRef)
	if _, err := g.run("bundle", "create", path, tmpRef); err != nil {
		return err
	}
	return nil
}

// BundleUnbundle loads all objects from the bundle at path into the local
// object database.
func (g Git) BundleUnbundle(path string) error {
	_, err := g.run("bundle", "unbundle", path)
	return err
}

// LooseObjectStats reports how many loose (unpacked) objects the local
// repository has and their total size in KiB. Bundling is much slower on
// loose objects because git re-deltifies and re-compresses each one,
// whereas packed objects are stream-copied.
func (g Git) LooseObjectStats() (count, sizeKiB int64, err error) {
	out, err := g.run("count-objects", "-v")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "count: "); ok {
			fmt.Sscanf(v, "%d", &count)
		}
		if v, ok := strings.CutPrefix(line, "size: "); ok {
			fmt.Sscanf(v, "%d", &sizeKiB)
		}
	}
	return count, sizeKiB, nil
}

// TempFile creates a temp file for bundle staging, honoring TMPDIR.
func TempFile(pattern string) (*os.File, error) {
	return os.CreateTemp("", pattern)
}
