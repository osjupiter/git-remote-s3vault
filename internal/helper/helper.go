// Package helper implements the git remote-helper protocol
// (gitremote-helpers(7)) on top of a kopia repository stored in an
// S3-compatible bucket.
//
// Remote layout:
//
//	<prefix>/.keys/...   keyring: the repository DEK wrapped per member key
//	<prefix>/data/...    kopia repository (opaque encrypted blobs)
//
// Each pushed ref stores a self-contained git bundle as a kopia object;
// kopia's content-defined chunking deduplicates the redundancy between
// successive bundles and between refs, so a full-bundle push uploads only
// the changed chunks. Refs and HEAD are kopia manifests. The kopia
// repository password is the DEK managed by the keyring (an age X25519
// identity wrapped per member public key).
package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"filippo.io/age"

	"github.com/osjupiter/git-remote-s3vault/internal/config"
	"github.com/osjupiter/git-remote-s3vault/internal/cryptox"
	"github.com/osjupiter/git-remote-s3vault/internal/gitutil"
	"github.com/osjupiter/git-remote-s3vault/internal/keyring"
	"github.com/osjupiter/git-remote-s3vault/internal/kopiax"
	"github.com/osjupiter/git-remote-s3vault/internal/storage"
)

// errEmptyRemote marks a remote that has never been pushed to (no keyring,
// no kopia repository). Listing it yields no refs.
var errEmptyRemote = errors.New("remote is empty")

// Above these thresholds of loose (unpacked) objects, bundling gets
// noticeably slow (git re-compresses every loose object; packed objects
// are stream-copied ~20x faster) — worth telling the user about.
// Variables so tests can lower them.
var (
	looseCountHint int64 = 256
	looseKiBHint   int64 = 32 * 1024 // 32 MiB
)

type remoteRef struct {
	sha    string
	object string // kopia object ID of the bundle
}

// Helper drives one remote-helper session over stdin/stdout.
type Helper struct {
	cfg   *config.Config
	store storage.Storage // keyring side; lazily built when nil
	git   gitutil.Git

	in   *bufio.Scanner
	out  *bufio.Writer
	errW io.Writer

	refs        map[string]remoteRef // refname -> current state, from the last list
	headRef     string
	forceAll    bool
	verbose     int
	progress    bool
	gcHintShown bool

	krepo      *kopiax.Repo
	password   string
	identities []age.Identity
}

// New wires up a session. store may be nil, in which case it is built
// lazily from cfg on first use (so `capabilities` works without creds).
func New(cfg *config.Config, store storage.Storage, in io.Reader, out, errW io.Writer) *Helper {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	return &Helper{
		cfg:      cfg,
		store:    store,
		in:       sc,
		out:      bufio.NewWriter(out),
		errW:     errW,
		verbose:  1,
		progress: true,
	}
}

// Run processes commands until EOF or an empty line outside a batch.
func (h *Helper) Run(ctx context.Context) error {
	defer func() {
		if h.krepo != nil {
			h.krepo.Close(ctx) //nolint:errcheck // read-side close on exit
		}
	}()
	for h.in.Scan() {
		line := strings.TrimRight(h.in.Text(), "\n")
		switch {
		case line == "":
			return h.out.Flush()
		case line == "capabilities":
			h.printf("option\nfetch\npush\n\n")
		case strings.HasPrefix(line, "option "):
			h.handleOption(strings.TrimPrefix(line, "option "))
		case line == "list", line == "list for-push":
			if err := h.cmdList(ctx); err != nil {
				return err
			}
		case strings.HasPrefix(line, "fetch "):
			if err := h.cmdFetchBatch(ctx, line); err != nil {
				return err
			}
		case strings.HasPrefix(line, "push "):
			if err := h.cmdPushBatch(ctx, line); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown remote-helper command %q", line)
		}
		if err := h.out.Flush(); err != nil {
			return err
		}
	}
	if err := h.in.Err(); err != nil {
		return err
	}
	return h.out.Flush()
}

func (h *Helper) printf(format string, args ...any) {
	fmt.Fprintf(h.out, format, args...)
}

func (h *Helper) logf(format string, args ...any) {
	if h.verbose >= 2 || os.Getenv("GIT_REMOTE_S3VAULT_DEBUG") != "" {
		fmt.Fprintf(h.errW, "git-remote-s3vault: "+format+"\n", args...)
	}
}

func (h *Helper) warnf(format string, args ...any) {
	fmt.Fprintf(h.errW, "git-remote-s3vault: warning: "+format+"\n", args...)
}

// progressf narrates the slow parts (bundling, uploading, downloading) on
// stderr, which git passes through to the user. Silenced by `git push -q`
// (verbosity 0) and --no-progress.
func (h *Helper) progressf(format string, args ...any) {
	if !h.progress || h.verbose < 1 {
		return
	}
	fmt.Fprintf(h.errW, "git-remote-s3vault: "+format+"\n", args...)
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func (h *Helper) handleOption(opt string) {
	name, value, _ := strings.Cut(opt, " ")
	switch name {
	case "verbosity":
		fmt.Sscanf(value, "%d", &h.verbose)
		h.printf("ok\n")
	case "force":
		h.forceAll = value == "true"
		h.printf("ok\n")
	case "progress":
		h.progress = value != "false"
		h.printf("ok\n")
	default:
		h.printf("unsupported\n")
	}
}

func (h *Helper) ensureStore(ctx context.Context) error {
	if h.store != nil {
		return nil
	}
	s, err := storage.New(ctx, h.cfg)
	if err != nil {
		return err
	}
	h.store = s
	return nil
}

// ensureRepo opens (and with create, initializes) the kopia repository of
// the currently active data generation.
func (h *Helper) ensureRepo(ctx context.Context, create bool) error {
	if h.krepo != nil {
		return nil
	}
	pw, err := h.repoPassword(ctx, create)
	if err != nil {
		return err
	}
	if err := h.ensureStore(ctx); err != nil {
		return err
	}
	gen := kopiax.CurrentGeneration(ctx, h.store, h.cfg.Prefix)
	kr, err := kopiax.Open(ctx, h.cfg, pw, gen, create)
	if err != nil {
		return err
	}
	h.krepo = kr
	return nil
}

// repoPassword resolves the kopia repository password: the plaintext-mode
// constant, or the DEK unwrapped from (or initialized into) the keyring.
func (h *Helper) repoPassword(ctx context.Context, create bool) (string, error) {
	if h.password != "" {
		return h.password, nil
	}
	if h.cfg.Encryption == config.EncryptionNone {
		h.password = kopiax.PlaintextPassword
		return h.password, nil
	}
	if err := h.ensureStore(ctx); err != nil {
		return "", err
	}
	kr := keyring.New(h.store, h.cfg.Prefix)
	repoPub, exists, err := kr.RepoRecipient(ctx)
	if err != nil {
		return "", err
	}

	if !exists {
		if !create {
			return "", errEmptyRemote
		}
		specs, err := h.initialRecipientSpecs()
		if err != nil {
			return "", err
		}
		dek, err := kr.Init(ctx, specs)
		if errors.Is(err, keyring.ErrAlreadyInitialized) {
			// Lost an init race: someone else created the keyring between
			// our check and our write. Join as a regular member instead.
			h.warnf("repository key was initialized concurrently by someone else; joining as a member")
			return h.repoPassword(ctx, false)
		}
		if err != nil {
			return "", err
		}
		h.warnf("initialized repository key; access granted to %d public key(s)", len(specs))
		h.warnf("no recovery key was created; run `git-remote-s3vault key recovery-init` to add one")
		h.password = dek.String()
		return h.password, nil
	}

	ids, err := h.loadIdentities()
	if err != nil {
		return "", err
	}
	dek, ok, err := kr.Unwrap(ctx, ids)
	if err != nil {
		return "", err
	}
	if !ok {
		// The identity file may hold the DEK itself.
		if x25519, okR := repoPub.(*age.X25519Recipient); okR {
			for _, id := range ids {
				if x, okX := id.(*age.X25519Identity); okX && x.Recipient().String() == x25519.String() {
					h.password = x.String()
					return h.password, nil
				}
			}
		}
		return "", fmt.Errorf("none of your keys can unwrap the repository key; " +
			"ask a member to run `git-remote-s3vault key grant <your-public-key>` " +
			"or recover with `git-remote-s3vault key recover`")
	}
	h.password = dek.String()
	return h.password, nil
}

// loadRemoteRefs reads refs and HEAD from the kopia repository. A remote
// that was never pushed to yields empty results.
func (h *Helper) loadRemoteRefs(ctx context.Context) error {
	h.refs = map[string]remoteRef{}
	h.headRef = ""

	err := h.ensureRepo(ctx, false)
	if errors.Is(err, errEmptyRemote) || errors.Is(err, kopiax.ErrNotInitialized) {
		return nil
	}
	if err != nil {
		return err
	}

	refs, err := h.krepo.Refs(ctx)
	if err != nil {
		return err
	}
	for name, ri := range refs {
		h.refs[name] = remoteRef{sha: ri.SHA, object: ri.Object}
	}

	head, err := h.krepo.Head(ctx)
	if err != nil {
		return err
	}
	if _, ok := h.refs[head]; ok {
		h.headRef = head
	}
	if h.headRef == "" {
		for _, fallback := range []string{"refs/heads/main", "refs/heads/master"} {
			if _, ok := h.refs[fallback]; ok {
				h.headRef = fallback
				break
			}
		}
	}
	if h.headRef == "" {
		var branches []string
		for r := range h.refs {
			if strings.HasPrefix(r, "refs/heads/") {
				branches = append(branches, r)
			}
		}
		sort.Strings(branches)
		if len(branches) > 0 {
			h.headRef = branches[0]
		}
	}
	return nil
}

func (h *Helper) cmdList(ctx context.Context) error {
	if err := h.loadRemoteRefs(ctx); err != nil {
		return err
	}
	names := make([]string, 0, len(h.refs))
	for r := range h.refs {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		h.printf("%s %s\n", h.refs[r].sha, r)
	}
	if h.headRef != "" {
		h.printf("@%s HEAD\n", h.headRef)
	}
	h.printf("\n")
	return nil
}

// --- fetch ---

func (h *Helper) cmdFetchBatch(ctx context.Context, first string) error {
	type want struct{ sha, name string }
	wants := []want{}
	line := first
	for {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) == 3 && parts[0] == "fetch" {
			wants = append(wants, want{parts[1], parts[2]})
		}
		if !h.in.Scan() {
			break
		}
		line = h.in.Text()
		if line == "" {
			break
		}
	}

	if h.refs == nil {
		if err := h.loadRemoteRefs(ctx); err != nil {
			return err
		}
	}

	done := map[string]bool{}
	for _, w := range wants {
		if done[w.sha] {
			continue
		}
		if err := h.fetchOne(ctx, w.sha, w.name); err != nil {
			return fmt.Errorf("fetching %s (%s): %w", w.name, w.sha[:12], err)
		}
		done[w.sha] = true
	}
	h.printf("\n")
	return nil
}

func (h *Helper) fetchOne(ctx context.Context, sha, name string) error {
	var found *remoteRef
	if rr, ok := h.refs[name]; ok && rr.sha == sha {
		found = &rr
	} else {
		// The exact sha may live under another ref, or the listing may be
		// stale; search all known refs for it.
		for _, rr := range h.refs {
			if rr.sha == sha {
				found = &rr
				break
			}
		}
	}
	if found == nil || found.object == "" {
		return fmt.Errorf("no bundle found for %s", sha)
	}

	body, size, err := h.krepo.OpenBundle(ctx, found.object)
	if err != nil {
		return err
	}
	defer body.Close()
	h.progressf("downloading %s (%s)", name, humanSize(size))

	tmp, err := gitutil.TempFile("git-remote-s3vault-fetch-*.bundle")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	h.progressf("unbundling %s", name)
	return h.git.BundleUnbundle(tmp.Name())
}

// --- push ---

func (h *Helper) cmdPushBatch(ctx context.Context, first string) error {
	specs := []string{}
	line := first
	for {
		if s, ok := strings.CutPrefix(line, "push "); ok {
			specs = append(specs, s)
		}
		if !h.in.Scan() {
			break
		}
		line = h.in.Text()
		if line == "" {
			break
		}
	}

	if h.refs == nil {
		if err := h.loadRemoteRefs(ctx); err != nil {
			return err
		}
	}
	h.maybeSuggestGC()

	for _, spec := range specs {
		force := strings.HasPrefix(spec, "+") || h.forceAll
		spec = strings.TrimPrefix(spec, "+")
		src, dst, ok := strings.Cut(spec, ":")
		if !ok || dst == "" {
			h.printf("error %s malformed refspec\n", spec)
			continue
		}
		var err error
		if src == "" {
			err = h.pushDelete(ctx, dst)
		} else {
			err = h.pushRef(ctx, src, dst, force)
		}
		if err != nil {
			h.printf("error %s %s\n", dst, strings.ReplaceAll(err.Error(), "\n", " "))
		} else {
			h.printf("ok %s\n", dst)
		}
	}
	h.printf("\n")
	return nil
}

func (h *Helper) pushDelete(ctx context.Context, dst string) error {
	if _, ok := h.refs[dst]; !ok || h.krepo == nil {
		return fmt.Errorf("remote ref does not exist")
	}
	if err := h.krepo.DeleteRef(ctx, dst); err != nil {
		return err
	}
	delete(h.refs, dst)
	if h.headRef == dst {
		if err := h.krepo.DeleteHead(ctx); err != nil {
			h.warnf("could not delete remote HEAD: %v", err)
		}
		h.headRef = ""
	}
	return nil
}

func (h *Helper) pushRef(ctx context.Context, src, dst string, force bool) error {
	localSHA, err := h.git.RevParse(src)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", src, err)
	}

	if existing, ok := h.refs[dst]; ok && existing.sha != localSHA && !force {
		if !h.git.HasObject(existing.sha) {
			return fmt.Errorf("remote is at %s which is not known locally; fetch first", existing.sha[:12])
		}
		ffwd, err := h.git.IsAncestor(existing.sha, localSHA)
		if err != nil {
			return err
		}
		if !ffwd {
			return fmt.Errorf("non-fast-forward (remote is at %s); fetch first or force-push", existing.sha[:12])
		}
	}

	// 1. Bundle the full history of the pushed commit. Deduplication
	// against everything already stored happens inside kopia, so only the
	// changed chunks are actually uploaded.
	h.progressf("bundling %s (full history)", dst)
	tmp, err := gitutil.TempFile("git-remote-s3vault-push-*.bundle")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)
	if err := h.git.BundleCreate(tmpName, localSHA); err != nil {
		return err
	}

	// 2. Store bundle + ref (+ HEAD on the first branch) in one session.
	if err := h.ensureRepo(ctx, true); err != nil {
		return err
	}
	f, err := os.Open(tmpName)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if h.cfg.Encryption == config.EncryptionNone {
		h.progressf("uploading %s (%s bundle, deduplicated, PLAINTEXT)", dst, humanSize(st.Size()))
	} else {
		h.progressf("uploading %s (%s bundle, deduplicated, encrypted)", dst, humanSize(st.Size()))
	}
	setHead := h.headRef == "" && strings.HasPrefix(dst, "refs/heads/")
	oid, err := h.krepo.PushRef(ctx, dst, localSHA, f, setHead)
	if err != nil {
		return err
	}
	h.logf("bundle stored as kopia object %s", oid)

	if setHead {
		h.headRef = dst
	}
	h.refs[dst] = remoteRef{sha: localSHA, object: oid}
	return nil
}

// maybeSuggestGC recommends `git gc` (once per session) when the local
// repository has enough loose objects to make bundling noticeably slow.
func (h *Helper) maybeSuggestGC() {
	if h.gcHintShown {
		return
	}
	count, sizeKiB, err := h.git.LooseObjectStats()
	if err != nil {
		return
	}
	if count < looseCountHint && sizeKiB < looseKiBHint {
		return
	}
	h.gcHintShown = true
	h.warnf("this repository has %d loose objects (%s), which makes preparing the push slow;", count, humanSize(sizeKiB*1024))
	h.warnf("run `git gc` once — packed repositories bundle roughly 20x faster")
}

// --- key material ---

func defaultConfigPath(name string) string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	p := path.Join(dir, "git-remote-s3vault", name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// initialRecipientSpecs decides who can unwrap a brand-new repository key:
// explicitly configured recipients, else the public halves of the local
// identities.
func (h *Helper) initialRecipientSpecs() ([]string, error) {
	specs := append([]string{}, h.cfg.Recipients...)
	files := h.cfg.RecipientFiles
	if len(specs) == 0 && len(files) == 0 {
		if p := defaultConfigPath("recipients.txt"); p != "" {
			files = []string{p}
		}
	}
	fromFiles, err := cryptox.LoadRecipientFiles(files)
	if err != nil {
		return nil, err
	}
	for _, s := range fromFiles {
		if s = strings.TrimSpace(s); s != "" && !strings.HasPrefix(s, "#") {
			specs = append(specs, s)
		}
	}
	if len(specs) == 0 {
		if ids, err := h.loadIdentities(); err == nil {
			for _, id := range ids {
				if x, ok := id.(*age.X25519Identity); ok {
					specs = append(specs, x.Recipient().String())
				}
			}
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("cannot initialize the repository key: no public keys available; " +
			"run `git-remote-s3vault setup`, set r2.ageRecipients, or opt out with r2.encryption=none")
	}
	if _, err := cryptox.ParseRecipients(specs); err != nil {
		return nil, err
	}
	return specs, nil
}

func (h *Helper) loadIdentities() ([]age.Identity, error) {
	if h.identities != nil {
		return h.identities, nil
	}
	files := h.cfg.IdentityFiles
	if len(files) == 0 {
		if p := defaultConfigPath("identity.txt"); p != "" {
			files = []string{p}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("the remote is encrypted but no machine key is configured; " +
			"set r2.ageIdentityFile (git config) or GIT_REMOTE_S3VAULT_AGE_IDENTITY_FILE")
	}
	ids, err := cryptox.LoadIdentityFiles(files)
	if err != nil {
		return nil, err
	}
	h.identities = ids
	return ids, nil
}
