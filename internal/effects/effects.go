// Package effects maps a command invocation to what it does to the world.
//
// Every extractor is registered by command name. A command with no registered
// extractor produces Unknown rather than an empty result: absence of knowledge
// is never evidence of safety.
package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

// Verb is the closed vocabulary of actions a policy can rule on.
type Verb string

const (
	VerbRead     Verb = "read"
	VerbWrite    Verb = "write"
	VerbDelete   Verb = "delete"
	VerbTruncate Verb = "truncate"
	VerbExec     Verb = "exec"
)

// Remote is a network endpoint an invocation acts on.
type Remote struct {
	Host string
	Verb Verb
}

// Effects is the blast radius of one or more invocations.
type Effects struct {
	Deletes   []paths.Path
	Writes    []paths.Path
	Truncates []paths.Path
	Reads     []paths.Path
	Remotes   []Remote

	Irreversible bool     // no undo exists for at least one effect
	Unknown      bool     // analysis could not complete
	Notes        []string // human-readable observations for `explain`
}

// Merge folds another set of effects into this one.
func (e *Effects) Merge(o Effects) {
	e.Deletes = append(e.Deletes, o.Deletes...)
	e.Writes = append(e.Writes, o.Writes...)
	e.Truncates = append(e.Truncates, o.Truncates...)
	e.Reads = append(e.Reads, o.Reads...)
	e.Remotes = append(e.Remotes, o.Remotes...)
	e.Irreversible = e.Irreversible || o.Irreversible
	e.Unknown = e.Unknown || o.Unknown
	e.Notes = append(e.Notes, o.Notes...)
}

// Extractor computes the effects of one invocation of a known command.
type Extractor func(inv shell.Invocation, ctx paths.Context) Effects

var registry = map[string]Extractor{}

// Register associates a command name with its extractor. Call from init.
func Register(name string, fn Extractor) { registry[name] = fn }

// Registered reports the command names with an extractor, for `doctor`.
func Registered() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	return out
}

// Extract computes the effects of an invocation, including those implied by its
// redirections.
func Extract(inv shell.Invocation, ctx paths.Context) Effects {
	var out Effects
	if len(inv.Argv) == 0 {
		return out
	}
	if fn, ok := registry[base(inv.Argv[0])]; ok {
		out = fn(inv, ctx)
	} else {
		out.Unknown = true
		out.Notes = append(out.Notes, "unregistered command: "+inv.Argv[0])
	}
	out.Merge(redirectEffects(inv, ctx))
	if inv.Unknown {
		out.Unknown = true
	}
	return out
}

// redirectEffects reports what a statement's redirections do on their own.
// `: > file` truncates without naming a destructive command.
func redirectEffects(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	for _, r := range inv.Redirects {
		targets := paths.Expand(r.Target, ctx)
		switch r.Op {
		case shell.RedirWrite:
			e.Truncates = append(e.Truncates, targets...)
			e.Irreversible = true
		case shell.RedirAppend:
			e.Writes = append(e.Writes, targets...)
		case shell.RedirRead:
			e.Reads = append(e.Reads, targets...)
		}
	}
	return e
}

// base strips any directory prefix, so /bin/rm and rm resolve alike.
func base(cmd string) string {
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}

// operands splits argv into flags and operands, honouring the -- terminator and
// expanding combined short flags such as -rf into r and f.
func operands(argv []string) (flags map[byte]bool, rest []string) {
	flags = map[byte]bool{}
	seenDoubleDash := false
	for _, a := range argv[1:] {
		switch {
		case seenDoubleDash:
			rest = append(rest, a)
		case a == "--":
			seenDoubleDash = true
		case len(a) > 2 && a[:2] == "--":
			if k := longFlagKey(a); k != 0 {
				flags[k] = true
			}
		case len(a) > 1 && a[0] == '-':
			for i := 1; i < len(a); i++ {
				flags[a[i]] = true
			}
		default:
			rest = append(rest, a)
		}
	}
	return flags, rest
}

// longFlagKey maps a long flag to the short flag byte it is equivalent to, so
// extractors test one key. Unrecognised long flags map to 0.
func longFlagKey(a string) byte {
	switch a {
	case "--recursive":
		return 'r'
	case "--force":
		return 'f'
	case "--append":
		return 'a'
	default:
		return 0
	}
}
