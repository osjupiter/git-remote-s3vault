# git-remote-r2

A git remote helper that stores repositories in **Cloudflare R2** (or any
S3-compatible object store) as **age-encrypted** git bundles.

```console
$ git remote add origin r2://my-bucket/my-repo
$ git push origin main
$ git clone r2://my-bucket/my-repo
```

## Why this instead of git-remote-s3?

- **Single static binary.** Written in Go — no Python, no pip, no runtime.
  Drop `git-remote-r2` on your `PATH` and git finds it.
- **Encrypted before it leaves your machine.** Every bundle is encrypted
  with [age](https://age-encryption.org) client-side, by default, always.
  Your storage provider only ever sees ciphertext. Plaintext storage
  requires an explicit opt-out.
- **R2 first-class.** Point it at a Cloudflare account ID and the endpoint,
  region, and addressing style are derived for you. Generic S3 (AWS, MinIO,
  Garage, Ceph, …) works through the same binary.
- **Tested for real.** The e2e suite spins up MinIO in a testcontainer and
  drives the compiled binary through actual `git push`, `clone`, `pull`,
  force-pushes, tags, and branch deletion.

## Install

```console
$ go install github.com/osjupiter/git-remote-r2/cmd/git-remote-r2@latest
```

or grab a release binary and put it on your `PATH`. To also handle
`s3://` URLs, add a symlink named `git-remote-s3` pointing at the same
binary.

## Quick start

From inside any existing repository, one command does the whole thing —
generates an age key if you don't have one, registers the remote, writes
repo-local config, and checks that the bucket is reachable:

```console
$ export R2_ACCOUNT_ID=<cloudflare account id>   # R2 API token, S3 compatibility mode
$ export R2_ACCESS_KEY_ID=<key id>
$ export R2_SECRET_ACCESS_KEY=<secret>

$ git-remote-r2 setup r2://my-bucket/my-repo
✓ generated this machine's key (age identity): ~/.config/git-remote-r2/identity.txt
✓ added remote "origin" → r2://my-bucket/my-repo
✓ 1 recipient(s) configured (1 added)
✓ bucket reachable; remote is empty (first push will initialize it)
✓ repository key created; wrapped for 1 public key(s)
✓ recovery key created — store this line in a password manager or on paper:

    AGE-SECRET-KEY-1...

  It will NOT be shown again. Anyone holding it can decrypt this repository.

All set. Next:
  git push -u origin main

$ git push -u origin main
```

Useful flags: `--remote <name>`, `--recipient <age1...>` (repeatable; add
teammates or CI public keys), `--account-id <id>`, `--endpoint <url>` (for
MinIO/AWS), `--identity <path>`, `--encryption none`, `--no-verify`.
Re-running setup is safe and idempotent — run it again to add recipients or
repoint the remote.

Adding a teammate later is one command (see "Envelope encryption" below):

```console
$ git-remote-r2 key grant age1<their-public-key>
✓ access granted (no re-encryption needed — existing history is immediately readable)
```

### Recovery key & disaster recovery

When setup initializes a repository it also mints a **recovery key** and
prints its secret exactly once:

```
✓ recovery key created — store this line in a password manager or on paper:

    AGE-SECRET-KEY-1....

  It will NOT be shown again.
```

Store that one line somewhere durable. Losing every device is then a
non-event — a brand-new machine needs only the recovery secret and the
URL:

```console
$ git-remote-r2 key recover r2://my-bucket/my-repo
recovery key (AGE-SECRET-KEY-...):
✓ generated this machine's key (age identity): ~/.config/git-remote-r2/identity.txt
✓ this machine's key now has access
$ git clone r2://my-bucket/my-repo
```

`recover` mints a fresh machine key and grants it access using the
recovery key, so the recovery secret goes straight back in the drawer.

The recovery key is deliberately **asymmetric** (a keypair, not a
passphrase): its public half lives in the bucket
(`.keys/dek/recovery.pub`), which means a future key rotation can re-wrap
the new repository key for it *without knowing any secret*. A
passphrase-based (symmetric) recovery scheme cannot do that — rotation
would stall waiting for someone to type the passphrase.

`git-remote-r2 key recovery-init` mints a replacement recovery key at any
time (the old secret stops working). For non-interactive use set
`GIT_REMOTE_R2_RECOVERY_KEY`.

Even without a recovery key, all is not lost while any clone survives:
generate a new key and force-push every ref to re-encrypt the remote.

### Without the setup command

`setup` is a convenience, not a requirement. If a machine key exists (any
age identity file works — `age-keygen` output is fine) and the helper can
find at least one public key, the first push initializes the repository
key by itself:

```console
$ age-keygen -o ~/.config/git-remote-r2/identity.txt
$ git remote add origin r2://my-bucket/my-repo
$ git push origin main   # repository key is created here, wrapped for your key
```

The machine key at `~/.config/git-remote-r2/identity.txt` and any public
keys listed in `~/.config/git-remote-r2/recipients.txt` (or in the
`r2.ageRecipients` git config) are picked up automatically. Note that this
path creates **no recovery key** — run `git-remote-r2 key recovery-init`
afterwards if you want one.

## Configuration

Everything can be set per-remote (`remote.<name>.<key>`), globally
(`r2.<key>`), or by environment variable. Precedence: **env > remote-scoped
git config > global git config**.

| git config key | environment | meaning |
|---|---|---|
| `r2.accountId` | `R2_ACCOUNT_ID`, `CLOUDFLARE_ACCOUNT_ID` | Cloudflare account ID; derives the R2 endpoint |
| `r2.endpoint` | `AWS_ENDPOINT_URL[_S3]`, `GIT_REMOTE_R2_ENDPOINT` | explicit S3 endpoint (MinIO, AWS, …); wins over accountId |
| `r2.region` | `AWS_REGION` | region (`auto` for R2, `us-east-1` otherwise) |
| `r2.usePathStyle` | `GIT_REMOTE_R2_PATH_STYLE` | path-style addressing; auto-detected for self-hosted endpoints |
| `r2.ageRecipients` (multi) | `GIT_REMOTE_R2_AGE_RECIPIENTS` (comma-sep) | public keys (`age1...` / `ssh-...`) granted access when the repository key is first created; afterwards use `key grant` |
| `r2.ageRecipientsFile` | `GIT_REMOTE_R2_AGE_RECIPIENTS_FILE` | file with one such public key per line |
| `r2.ageIdentityFile` | `GIT_REMOTE_R2_AGE_IDENTITY_FILE` | this machine's key (age identity or SSH private key), used to unwrap the repository key |
| `r2.encryption` | `GIT_REMOTE_R2_ENCRYPTION` | `age` (default) or `none` (explicit opt-out) |

Credentials use the standard AWS chain (`AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`, shared config files, IAM roles);
`R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` are accepted as aliases.

### MinIO / self-hosted S3 example

```console
$ export AWS_ENDPOINT_URL=http://127.0.0.1:9000
$ export AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin
$ git clone r2://my-bucket/my-repo
```

## How it works

### Envelope encryption (sops-style)

Every repository gets its own **data-encryption key (DEK)** — an age
X25519 keypair generated automatically on setup / first push. Bundles are
encrypted only to the DEK; the DEK's secret half is stored in the bucket,
wrapped once per member public key:

```
<prefix>/.keys/repo.pub           # DEK public key (plaintext — it's public)
<prefix>/.keys/dek/<label>.age    # DEK secret, wrapped to one member key
<prefix>/.keys/dek/<label>.pub    # that member's public key (for `key list`)
<prefix>/refs/heads/main/<sha>.bundle.age   # full-history bundle → DEK only
<prefix>/HEAD                     # default branch pointer
```

Because history is encrypted to the per-repo DEK rather than to member
keys directly:

- **Granting access is O(1)**: wrap the DEK for one more public key —
  the entire existing history becomes readable to them instantly, with no
  re-encryption and no re-push.
- **Repos are isolated**: each has its own DEK, so one machine key can
  serve every repo without coupling them cryptographically.

```console
$ git-remote-r2 key grant age1<teammate> ; git-remote-r2 key list ; git-remote-r2 key revoke <label>
```

`key revoke` removes a member's ability to unwrap the DEK in the future,
but anyone who already unwrapped it may have cached it — a hard cut-off
additionally requires rotating the DEK and re-pushing (planned as
`key rotate`).

### Storage model

Each push uploads a **self-contained git bundle** of the ref's full
history:

- `list` reconstructs the remote's refs from object keys — no index files,
  no extra state to corrupt.
- Pushes enforce fast-forward unless `--force` is used (ancestry is checked
  locally against the advertised remote sha).
- After a successful upload the superseded bundle is deleted, so a ref's
  directory converges to a single object.

### Threat model

Bundle **contents** (commits, trees, blobs, messages) are encrypted
end-to-end; the storage provider sees only ciphertext and the DEK never
exists unencrypted outside your machines. Object **keys** are not
encrypted: ref names, member count (one wrapped-DEK slot each), object
sizes, and push timing are visible to the provider. Don't put secrets in
branch names.

### Caveats

- Full-history bundles make push cost grow with repository size — great
  for small/medium private repos, wrong tool for monorepos.
- Two clients force-pushing the same ref at the same instant can race;
  the helper detects leftover duplicate bundles and warns on the next
  operation.

## Development

```console
$ make test        # unit tests
$ make e2e         # full git flows against MinIO (needs Docker)
$ make build
```

## License

MIT
