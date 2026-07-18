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
	tmpRef := "refs/git-remote-s3vault/push-" + sha[:12]
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

// BundleCreateRefs writes one bundle containing the full history of every
// given sha (the fast path when all snapshot refs exist locally). Ref
// names inside the bundle are irrelevant — fetch only unbundles objects.
func (g Git) BundleCreateRefs(path string, shas []string) error {
	var tmpRefs []string
	for i, sha := range shas {
		ref := fmt.Sprintf("refs/git-remote-s3vault/snap-%d", i)
		if _, err := g.run("update-ref", ref, sha); err != nil {
			return err
		}
		tmpRefs = append(tmpRefs, ref)
	}
	defer func() {
		for _, r := range tmpRefs {
			g.run("update-ref", "-d", r) //nolint:errcheck // cleanup
		}
	}()
	if len(tmpRefs) == 0 {
		return fmt.Errorf("refusing to create an empty bundle")
	}
	args := append([]string{"bundle", "create", path}, tmpRefs...)
	_, err := g.run(args...)
	return err
}

// GitDir resolves the absolute .git directory of the repository the
// helper runs in — used as a fetch source for the scratch repo.
func (g Git) GitDir() (string, error) {
	return g.run("rev-parse", "--absolute-git-dir")
}

// Scratch is a temporary bare repository used to merge the remote's
// current snapshot with locally pushed refs before bundling (mattn's
// git-remote-s3 technique) — it guarantees refs absent from the local
// clone survive a push untouched.
type Scratch struct {
	Dir string
}

// runIn runs git against the scratch repo. git exports GIT_DIR (and
// friends) before spawning a remote helper; they point at the invoking
// repository and would hijack any command aimed at another repo, so the
// scratch environment strips them.
func (g Git) runIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR":
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git -C %s %s: %w: %s", dir, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// NewScratch initializes a bare scratch repository in dir (which must
// exist).
func (g Git) NewScratch(dir string) (*Scratch, error) {
	if _, err := (Git{}).runIn(dir, "init", "-q", "--bare"); err != nil {
		return nil, err
	}
	return &Scratch{Dir: dir}, nil
}

// FetchBundle imports every object and ref from a bundle file.
func (g Git) FetchBundle(s *Scratch, bundlePath string) error {
	_, err := g.runIn(s.Dir, "fetch", "--quiet", "--force", "--no-tags", bundlePath, "refs/*:refs/*")
	return err
}

// FetchLocal force-updates ref in the scratch repo to sha, pulling the
// objects from the local repository. --no-tags: automatic tag following
// would collide with an explicit sha:refs/tags/* refspec.
func (g Git) FetchLocal(s *Scratch, gitDir, sha, ref string) error {
	_, err := g.runIn(s.Dir, "fetch", "--quiet", "--force", "--no-tags", gitDir, sha+":"+ref)
	return err
}

// HasObjectIn reports whether the scratch repo's object database has sha.
func (g Git) HasObjectIn(s *Scratch, sha string) bool {
	_, err := g.runIn(s.Dir, "cat-file", "-e", sha)
	return err == nil
}

// UpdateRefIn points ref at sha in the scratch repo (the object must
// already be present).
func (g Git) UpdateRefIn(s *Scratch, ref, sha string) error {
	_, err := g.runIn(s.Dir, "update-ref", ref, sha)
	return err
}

// ListRefsIn returns every ref name in the scratch repo.
func (g Git) ListRefsIn(s *Scratch) ([]string, error) {
	out, err := g.runIn(s.Dir, "for-each-ref", "--format=%(refname)")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}

// DeleteRefIn removes a ref from the scratch repo.
func (g Git) DeleteRefIn(s *Scratch, ref string) error {
	_, err := g.runIn(s.Dir, "update-ref", "-d", ref)
	return err
}

// BundleAll writes a bundle of every ref in the scratch repo.
func (g Git) BundleAll(s *Scratch, path string) error {
	_, err := g.runIn(s.Dir, "bundle", "create", path, "--all")
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
