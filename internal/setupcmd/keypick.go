package setupcmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"

	"github.com/osjupiter/git-remote-s3vault/internal/cryptox"
)

// keyCandidate is one selectable public key in the wizard.
type keyCandidate struct {
	label        string
	recipient    string // public key spec (age1... or ssh-... line)
	identityPath string // private key file when it is not the default one
	generate     bool   // "make a new age key" pseudo-candidate
}

// listKeyCandidates enumerates every usable key on this machine: X25519
// identities in the default machine-key file, plus SSH keys under ~/.ssh
// whose private half can decrypt (passphrase-protected ones are counted
// but not offered). A "generate new" candidate is always appended.
func listKeyCandidates() (cands []keyCandidate, skipped int) {
	if p, err := cryptox.DefaultIdentityPath(); err == nil {
		if ids, err := cryptox.LoadIdentityFiles([]string{p}); err == nil {
			for _, id := range ids {
				x, ok := id.(*age.X25519Identity)
				if !ok {
					continue
				}
				r := x.Recipient().String()
				cands = append(cands, keyCandidate{
					label:     fmt.Sprintf("age key %s (%s)", shortKey(r), p),
					recipient: r,
				})
			}
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		sshDir := filepath.Join(home, ".ssh")
		entries, _ := os.ReadDir(sshDir)
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
				continue
			}
			privPath := filepath.Join(sshDir, strings.TrimSuffix(e.Name(), ".pub"))
			privData, err := os.ReadFile(privPath)
			if err != nil {
				continue // public key without a usable private half
			}
			if _, err := agessh.ParseIdentity(privData); err != nil {
				skipped++ // passphrase-protected or unsupported key type
				continue
			}
			pubData, err := os.ReadFile(filepath.Join(sshDir, e.Name()))
			if err != nil {
				continue
			}
			pubLine := strings.TrimSpace(strings.SplitN(string(pubData), "\n", 2)[0])
			if _, err := cryptox.ParseRecipients([]string{pubLine}); err != nil {
				continue
			}
			cands = append(cands, keyCandidate{
				label:        fmt.Sprintf("SSH key %s (%s)", sshLabel(pubLine), privPath),
				recipient:    pubLine,
				identityPath: privPath,
			})
		}
	}

	cands = append(cands, keyCandidate{label: "Generate a new age key", generate: true})
	return cands, skipped
}

// pickKey runs the key-selection step of the wizard. With only the
// generate-new candidate available it selects it silently.
func pickKey(ask func(label, def string) (string, error), stdout io.Writer) (*keyCandidate, error) {
	cands, skipped := listKeyCandidates()
	if skipped > 0 {
		fmt.Fprintf(stdout, "(%d passphrase-protected SSH key(s) not offered — not supported)\n", skipped)
	}

	var chosen keyCandidate
	if len(cands) == 1 {
		chosen = cands[0]
	} else {
		fmt.Fprintf(stdout, "Which key should be able to decrypt this repository?\n")
		for i, c := range cands {
			fmt.Fprintf(stdout, "  %d) %s\n", i+1, c.label)
		}
		for {
			answer, err := ask("Key", "1")
			if err != nil {
				return nil, err
			}
			var n int
			if _, err := fmt.Sscanf(answer, "%d", &n); err != nil || n < 1 || n > len(cands) {
				fmt.Fprintf(stdout, "Please answer 1-%d.\n", len(cands))
				continue
			}
			chosen = cands[n-1]
			break
		}
	}

	if chosen.generate {
		path, err := cryptox.DefaultIdentityPath()
		if err != nil {
			return nil, err
		}
		id, err := cryptox.AppendNewIdentity(path)
		if err != nil {
			return nil, err
		}
		chosen = keyCandidate{
			label:     fmt.Sprintf("age key %s (%s)", shortKey(id.Recipient().String()), path),
			recipient: id.Recipient().String(),
		}
		fmt.Fprintf(stdout, "✓ generated a new machine key: %s (%s)\n", shortKey(chosen.recipient), path)
	} else {
		fmt.Fprintf(stdout, "✓ using %s\n", chosen.label)
	}
	return &chosen, nil
}

func shortKey(r string) string {
	if len(r) > 20 {
		return r[:20] + "…"
	}
	return r
}

// sshLabel condenses "ssh-ed25519 AAAA... comment" into "ssh-ed25519 (comment)".
func sshLabel(pubLine string) string {
	fields := strings.Fields(pubLine)
	switch {
	case len(fields) >= 3:
		return fields[0] + " " + strings.Join(fields[2:], " ")
	case len(fields) >= 1:
		return fields[0]
	default:
		return pubLine
	}
}
