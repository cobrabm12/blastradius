// Package policy loads guard.yaml and decides what the analysis is allowed to do.
package policy

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/cobrabm12/blastradius/internal/effects"
)

// Decision is a verdict's outcome, ordered by severity: Allow < Ask < Block.
type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Block Decision = "block"
)

// severity orders decisions so the most restrictive one across a blast radius wins.
func severity(d Decision) int {
	switch d {
	case Block:
		return 2
	case Ask:
		return 1
	default:
		return 0
	}
}

// Rule is one ordered policy entry. Exactly one of Deny, Ask, or Allow carries
// the verbs it governs; the others are empty.
type Rule struct {
	Match  string         `yaml:"match"`
	Deny   []effects.Verb `yaml:"deny"`
	Ask    []effects.Verb `yaml:"ask"`
	Allow  []effects.Verb `yaml:"allow"`
	Reason string         `yaml:"reason"`
}

// GitRules covers repository operations that no path or host rule describes.
type GitRules struct {
	ProtectedBranches []string `yaml:"protected_branches"`
	Deny              []string `yaml:"deny"`
}

// AuditConfig says where the decision log is written.
type AuditConfig struct {
	Path string `yaml:"path"`
}

// Policy is a parsed guard.yaml.
type Policy struct {
	Version int         `yaml:"version"`
	OnError Decision    `yaml:"on_error"`
	Paths   []Rule      `yaml:"paths"`
	Hosts   []Rule      `yaml:"hosts"`
	Git     GitRules    `yaml:"git"`
	Audit   AuditConfig `yaml:"audit"`
}

var pathVerbs = map[effects.Verb]bool{
	effects.VerbRead:     true,
	effects.VerbWrite:    true,
	effects.VerbDelete:   true,
	effects.VerbTruncate: true,
}

var hostVerbs = map[effects.Verb]bool{
	effects.VerbRead:  true,
	effects.VerbWrite: true,
	effects.VerbExec:  true,
}

// Load parses and validates a policy document.
func Load(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version %d, want 1", p.Version)
	}
	if p.OnError == "" {
		p.OnError = Ask
	}
	switch p.OnError {
	case Allow, Ask, Block:
	default:
		return nil, fmt.Errorf("invalid on_error %q, want allow, ask, or block", p.OnError)
	}
	if err := validate(p.Paths, pathVerbs, "paths"); err != nil {
		return nil, err
	}
	if err := validate(p.Hosts, hostVerbs, "hosts"); err != nil {
		return nil, err
	}
	return &p, nil
}

func validate(rules []Rule, allowed map[effects.Verb]bool, section string) error {
	for i, r := range rules {
		if r.Match == "" {
			return fmt.Errorf("%s[%d]: match is required", section, i)
		}
		if len(r.Deny)+len(r.Ask)+len(r.Allow) == 0 {
			return fmt.Errorf("%s[%d]: rule names no verbs", section, i)
		}
		for _, group := range [][]effects.Verb{r.Deny, r.Ask, r.Allow} {
			for _, v := range group {
				if !allowed[v] {
					return fmt.Errorf("%s[%d]: %q is not a valid verb for this section", section, i, v)
				}
			}
		}
	}
	return nil
}

// Merge combines repository and user policy. User rules are appended last so
// that, under last-match-wins evaluation, machine policy is authoritative.
func Merge(repo, user *Policy) *Policy {
	if repo == nil {
		return user
	}
	if user == nil {
		return repo
	}
	out := *repo
	out.Paths = append(append([]Rule{}, repo.Paths...), user.Paths...)
	out.Hosts = append(append([]Rule{}, repo.Hosts...), user.Hosts...)
	out.Git.ProtectedBranches = append(append([]string{}, repo.Git.ProtectedBranches...), user.Git.ProtectedBranches...)
	out.Git.Deny = append(append([]string{}, repo.Git.Deny...), user.Git.Deny...)
	out.OnError = user.OnError
	if user.Audit.Path != "" {
		out.Audit.Path = user.Audit.Path
	}
	return &out
}
