// Package helper implements the git remote-helper protocol
// (gitremote-helpers(7)) on top of a kopia repository stored in an
// S3-compatible bucket.
//
// Remote layout:
//
//	<prefix>/.keys/...     keyring: the repository DEK wrapped per member key
//	<prefix>/state-<gen>   snapshot state record: complete ref table, HEAD,
//	                       and the object ID of the all-refs bundle
//	                       (age-encrypted, ETag compare-and-swap)
//	<prefix>/data/...      kopia repository (opaque encrypted blobs)
//
// Every push stores ONE self-contained git bundle covering all refs as a
// kopia object and swaps the state record in atomically; kopia's
// content-defined chunking deduplicates successive bundles, so a push
// uploads only the changed chunks and a clone downloads one bundle no
// matter how many refs exist. Concurrent pushes lose the CAS cleanly and
// are told to fetch and retry. Remotes written by the older per-ref
// format (refs as kopia manifests) are still readable; the first push
// migrates them. The kopia repository password is the DEK managed by the
// keyring (an age X25519 identity wrapped per member public key).
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
	"github.com/osjupiter/git-remote-s3vault/internal/snapshot"
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
	object string // per-ref bundle object ID (pre-snapshot v2 format only)
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
	gen        string          // active data generation
	state      *snapshot.State // current snapshot (nil = empty or v2 remote)
	stateETag  string          // CAS token captured when the state was read
	unbundled  bool            // the snapshot bundle was already applied locally
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
	h.gen = kopiax.CurrentGeneration(ctx, h.store, h.cfg.Prefix)
	kr, err := kopiax.Open(ctx, h.cfg, pw, h.gen, create)
	if err != nil {
		return err
	}
	h.krepo = kr
	return nil
}

// dekIdentity returns the DEK as an age identity for state
// encryption/decryption (nil in plaintext mode).
func (h *Helper) dekIdentity() *age.X25519Identity {
	if h.cfg.Encryption == config.EncryptionNone || h.password == "" {
		return nil
	}
	id, err := age.ParseX25519Identity(h.password)
	if err != nil {
		return nil
	}
	return id
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

// loadRemoteRefs reads refs and HEAD: from the snapshot state record
// (current format), or from per-ref kopia manifests (pre-snapshot v2
// remotes, read-only compatibility). A remote never pushed to yields
// empty results.
func (h *Helper) loadRemoteRefs(ctx context.Context) error {
	h.refs = map[string]remoteRef{}
	h.headRef = ""
	h.state = nil
	h.stateETag = ""

	err := h.ensureRepo(ctx, false)
	if errors.Is(err, errEmptyRemote) || errors.Is(err, kopiax.ErrNotInitialized) {
		return nil
	}
	if err != nil {
		return err
	}

	st, etag, err := snapshot.Load(ctx, h.store, h.cfg.Prefix, h.gen, h.dekIdentity())
	if err != nil {
		return err
	}
	if st != nil {
		h.state = st
		h.stateETag = etag
		for name, sha := range st.Refs {
			h.refs[name] = remoteRef{sha: sha}
		}
		h.headRef = h.pickHead(st.Head)
		return nil
	}

	// v2 fallback: refs as individual kopia manifests.
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
	h.headRef = h.pickHead(head)
	return nil
}

// pickHead validates the stored HEAD target and falls back to a sensible
// branch when it is unset or dangling.
func (h *Helper) pickHead(stored string) string {
	if _, ok := h.refs[stored]; ok {
		return stored
	}
	for _, fallback := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, ok := h.refs[fallback]; ok {
			return fallback
		}
	}
	var branches []string
	for r := range h.refs {
		if strings.HasPrefix(r, "refs/heads/") {
			branches = append(branches, r)
		}
	}
	sort.Strings(branches)
	if len(branches) > 0 {
		return branches[0]
	}
	return ""
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
		// Already present locally — e.g. a lightweight tag on a commit the
		// snapshot bundle delivered: no download needed.
		if h.git.HasObject(w.sha) {
			h.logf("%s (%s) already present locally; skipping download", w.name, w.sha[:12])
			done[w.sha] = true
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
	// Snapshot format: ONE bundle covers every ref; unbundle it once and
	// every subsequent want in the batch is satisfied from the local odb.
	if h.state != nil {
		if h.unbundled {
			if h.git.HasObject(sha) {
				return nil
			}
			return fmt.Errorf("object %s missing from the snapshot bundle", sha[:12])
		}
		if err := h.applyBundleObject(ctx, h.state.Bundle, "snapshot"); err != nil {
			return err
		}
		h.unbundled = true
		if !h.git.HasObject(sha) {
			return fmt.Errorf("object %s missing from the snapshot bundle (stale listing? run fetch again)", sha[:12])
		}
		return nil
	}

	// v2 fallback: one bundle per ref.
	var found *remoteRef
	if rr, ok := h.refs[name]; ok && rr.sha == sha {
		found = &rr
	} else {
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
	return h.applyBundleObject(ctx, found.object, name)
}

// downloadBundleToTemp streams a stored bundle into a temp file.
func (h *Helper) downloadBundleToTemp(ctx context.Context, objectID, label string) (string, func(), error) {
	body, size, err := h.krepo.OpenBundle(ctx, objectID)
	if err != nil {
		return "", nil, err
	}
	defer body.Close()
	h.progressf("downloading %s (%s)", label, humanSize(size))

	tmp, err := gitutil.TempFile("git-remote-s3vault-fetch-*.bundle")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.Remove(tmp.Name()) }
	if _, err := io.Copy(tmp, body); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmp.Name(), cleanup, nil
}

// applyBundleObject downloads a stored bundle and unbundles its objects
// into the local repository.
func (h *Helper) applyBundleObject(ctx context.Context, objectID, label string) error {
	path, cleanup, err := h.downloadBundleToTemp(ctx, objectID, label)
	if err != nil {
		return err
	}
	defer cleanup()
	h.progressf("unbundling %s", label)
	return h.git.BundleUnbundle(path)
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

	// Validate every refspec against the current snapshot; the survivors
	// are applied as ONE new snapshot, atomically.
	type update struct {
		dst    string
		sha    string // "" = delete
		isNew  bool
		delete bool
	}
	var updates []update
	report := map[string]string{} // dst -> "" (ok) or error text
	order := []string{}
	for _, spec := range specs {
		force := strings.HasPrefix(spec, "+") || h.forceAll
		spec = strings.TrimPrefix(spec, "+")
		src, dst, ok := strings.Cut(spec, ":")
		if !ok || dst == "" {
			h.printf("error %s malformed refspec\n", spec)
			continue
		}
		order = append(order, dst)
		if src == "" {
			if _, exists := h.refs[dst]; !exists {
				report[dst] = "remote ref does not exist"
				continue
			}
			updates = append(updates, update{dst: dst, delete: true})
			report[dst] = ""
			continue
		}
		localSHA, err := h.git.RevParse(src)
		if err != nil {
			report[dst] = fmt.Sprintf("cannot resolve %s: %v", src, err)
			continue
		}
		if existing, exists := h.refs[dst]; exists && existing.sha != localSHA && !force {
			if !h.git.HasObject(existing.sha) {
				report[dst] = fmt.Sprintf("remote is at %s which is not known locally; fetch first", existing.sha[:12])
				continue
			}
			ffwd, err := h.git.IsAncestor(existing.sha, localSHA)
			if err != nil {
				report[dst] = err.Error()
				continue
			}
			if !ffwd {
				report[dst] = fmt.Sprintf("non-fast-forward (remote is at %s); fetch first or force-push", existing.sha[:12])
				continue
			}
		}
		_, exists := h.refs[dst]
		updates = append(updates, update{dst: dst, sha: localSHA, isNew: !exists})
		report[dst] = ""
	}

	if len(updates) > 0 {
		// Compute the new complete ref table.
		newRefs := map[string]string{}
		for name, rr := range h.refs {
			newRefs[name] = rr.sha
		}
		for _, u := range updates {
			if u.delete {
				delete(newRefs, u.dst)
			} else {
				newRefs[u.dst] = u.sha
			}
		}
		head := h.headRef
		if _, ok := newRefs[head]; !ok {
			head = ""
		}
		if head == "" {
			for _, u := range updates {
				if !u.delete && strings.HasPrefix(u.dst, "refs/heads/") {
					head = u.dst
					break
				}
			}
		}

		if err := h.pushSnapshot(ctx, newRefs, head); err != nil {
			msg := strings.ReplaceAll(err.Error(), "\n", " ")
			for _, u := range updates {
				report[u.dst] = msg
			}
		} else {
			h.headRef = head
			refs := map[string]remoteRef{}
			for name, sha := range newRefs {
				refs[name] = remoteRef{sha: sha}
			}
			h.refs = refs
		}
	}

	seen := map[string]bool{}
	for _, dst := range order {
		if seen[dst] {
			continue
		}
		seen[dst] = true
		if msg := report[dst]; msg != "" {
			h.printf("error %s %s\n", dst, msg)
		} else {
			h.printf("ok %s\n", dst)
		}
	}
	h.printf("\n")
	return nil
}

// pushSnapshot builds the all-refs bundle for the new ref table, uploads
// it, and swaps the state record in with a compare-and-swap.
func (h *Helper) pushSnapshot(ctx context.Context, newRefs map[string]string, head string) error {
	if err := h.ensureRepo(ctx, true); err != nil {
		return err
	}

	tmp, err := gitutil.TempFile("git-remote-s3vault-push-*.bundle")
	if err != nil {
		return err
	}
	bundlePath := tmp.Name()
	tmp.Close()
	os.Remove(bundlePath) // bundle create wants to create it itself
	defer os.Remove(bundlePath)

	if len(newRefs) > 0 {
		if err := h.buildSnapshotBundle(ctx, newRefs, bundlePath); err != nil {
			return err
		}
	}

	newState := &snapshot.State{Refs: newRefs, Head: head}
	if len(newRefs) > 0 {
		f, err := os.Open(bundlePath)
		if err != nil {
			return err
		}
		var size int64
		if st, err := f.Stat(); err == nil {
			size = st.Size()
		}
		if h.cfg.Encryption == config.EncryptionNone {
			h.progressf("uploading snapshot (%s bundle, %d refs, deduplicated, PLAINTEXT)", humanSize(size), len(newRefs))
		} else {
			h.progressf("uploading snapshot (%s bundle, %d refs, deduplicated, encrypted)", humanSize(size), len(newRefs))
		}
		oid, err := h.krepo.WriteBundle(ctx, f)
		f.Close()
		if err != nil {
			return err
		}
		newState.Bundle = oid
		h.logf("snapshot bundle stored as kopia object %s", oid)
	}

	var recipient age.Recipient
	if id := h.dekIdentity(); id != nil {
		recipient = id.Recipient()
	}
	if err := snapshot.Save(ctx, h.store, h.cfg.Prefix, h.gen, newState, recipient, h.stateETag); err != nil {
		if errors.Is(err, snapshot.ErrConcurrentUpdate) {
			return fmt.Errorf("concurrent push detected: the remote changed since it was read; fetch and retry")
		}
		return err
	}

	// Migration: a successful snapshot push supersedes v2 per-ref manifests.
	if h.state == nil && len(h.refs) > 0 {
		if err := h.krepo.DeleteV2Manifests(ctx); err != nil {
			h.warnf("could not clean up pre-snapshot manifests: %v", err)
		} else {
			h.logf("migrated remote to the snapshot format")
		}
	}

	h.state = newState
	h.stateETag, _ = h.store.ETag(ctx, snapshot.Key(h.cfg.Prefix, h.gen))
	h.unbundled = false
	return nil
}

// buildSnapshotBundle produces one bundle containing the full history of
// every ref in newRefs. Fast path: everything is in the local odb. Slow
// path (refs exist remotely that this clone never fetched): merge the
// remote's current objects with the pushed refs in a scratch bare repo.
func (h *Helper) buildSnapshotBundle(ctx context.Context, newRefs map[string]string, bundlePath string) error {
	shas := make([]string, 0, len(newRefs))
	haveAll := true
	for _, sha := range newRefs {
		shas = append(shas, sha)
		if !h.git.HasObject(sha) {
			haveAll = false
		}
	}
	sort.Strings(shas)

	if haveAll {
		h.progressf("bundling snapshot (%d refs)", len(newRefs))
		return h.git.BundleCreateRefs(bundlePath, shas)
	}

	h.progressf("merging remote refs absent from this clone (%d refs total)", len(newRefs))
	scratchDir, err := os.MkdirTemp("", "git-remote-s3vault-scratch-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratchDir)
	scratch, err := h.git.NewScratch(scratchDir)
	if err != nil {
		return err
	}

	// Seed the scratch repo with the remote's objects.
	if h.state != nil && h.state.Bundle != "" {
		path, cleanup, err := h.downloadBundleToTemp(ctx, h.state.Bundle, "current snapshot")
		if err != nil {
			return err
		}
		err = h.git.FetchBundle(scratch, path)
		cleanup()
		if err != nil {
			return err
		}
	} else {
		for name, rr := range h.refs {
			if rr.object == "" {
				continue
			}
			path, cleanup, err := h.downloadBundleToTemp(ctx, rr.object, name)
			if err != nil {
				return err
			}
			err = h.git.FetchBundle(scratch, path)
			cleanup()
			if err != nil {
				return err
			}
		}
	}

	// Normalize the scratch refs to exactly the new ref table (bundle
	// headers carry temporary names, so seeded ref names are junk).
	gitDir, err := h.git.GitDir()
	if err != nil {
		return err
	}
	for name, sha := range newRefs {
		if h.git.HasObjectIn(scratch, sha) {
			if err := h.git.UpdateRefIn(scratch, name, sha); err != nil {
				return err
			}
		} else if err := h.git.FetchLocal(scratch, gitDir, sha, name); err != nil {
			return err
		}
	}
	existing, err := h.git.ListRefsIn(scratch)
	if err != nil {
		return err
	}
	for _, name := range existing {
		if _, keep := newRefs[name]; !keep {
			h.git.DeleteRefIn(scratch, name) //nolint:errcheck // cleanup
		}
	}
	return h.git.BundleAll(scratch, bundlePath)
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
