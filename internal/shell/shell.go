// Package shell turns bash source into the concrete invocations it performs.
//
// It renders each word to a literal string where that is possible, and to the
// Unresolvable sentinel where it is not. A word that cannot be rendered marks
// its invocation Unknown, because analysis that could not complete must never
// be reported as safe.
package shell

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Unresolvable stands in for a word whose value cannot be known from source
// alone: command substitution, arithmetic expansion, process substitution.
const Unresolvable = "\x00blastradius:unresolvable\x00"

// maxDepth bounds recursion through nested interpreters. A command nested more
// deeply than this is reported Unknown rather than analyzed.
const maxDepth = 8

// RedirOp is the kind of redirection applied to a command.
type RedirOp int

const (
	RedirWrite  RedirOp = iota // > — creates or truncates
	RedirAppend                // >> — creates or extends
	RedirRead                  // <
)

// Redirect is one redirection attached to a statement.
type Redirect struct {
	Op     RedirOp
	Target string
}

// Invocation is one concrete command: its argv and the redirections applied to
// it. Unknown reports that some part could not be resolved from source.
type Invocation struct {
	Argv      []string
	Redirects []Redirect
	Unknown   bool
}

// Parse renders bash source as the invocations it performs, in source order.
func Parse(src string) ([]Invocation, error) {
	return parseAt(src, 0)
}

func parseAt(src string, depth int) ([]Invocation, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	var out []Invocation
	syntax.Walk(f, func(n syntax.Node) bool {
		stmt, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		out = append(out, expand(invocationFrom(call, stmt.Redirs), depth)...)
		return true
	})
	return out, nil
}

func invocationFrom(call *syntax.CallExpr, redirs []*syntax.Redirect) Invocation {
	inv := Invocation{}
	for _, w := range call.Args {
		lit, ok := word(w)
		if !ok {
			inv.Unknown = true
		}
		inv.Argv = append(inv.Argv, lit)
	}
	for _, r := range redirs {
		op, ok := redirOp(r.Op)
		if !ok {
			continue // duplications such as 2>&1 move no file data
		}
		target, exact := word(r.Word)
		if !exact {
			inv.Unknown = true
		}
		inv.Redirects = append(inv.Redirects, Redirect{Op: op, Target: target})
	}
	return inv
}

func redirOp(op syntax.RedirOperator) (RedirOp, bool) {
	switch op {
	case syntax.RdrOut, syntax.RdrAll:
		return RedirWrite, true
	case syntax.AppOut, syntax.AppAll:
		return RedirAppend, true
	case syntax.RdrIn:
		return RedirRead, true
	default:
		return 0, false
	}
}

// word renders a single word. The bool reports whether the rendering is exact.
func word(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch x := part.(type) {
		case *syntax.Lit:
			b.WriteString(x.Value)
		case *syntax.SglQuoted:
			b.WriteString(x.Value)
		case *syntax.DblQuoted:
			for _, inner := range x.Parts {
				switch y := inner.(type) {
				case *syntax.Lit:
					b.WriteString(y.Value)
				case *syntax.ParamExp:
					b.WriteString("${" + y.Param.Value + "}")
				default:
					return Unresolvable, false
				}
			}
		case *syntax.ParamExp:
			b.WriteString("${" + x.Param.Value + "}")
		default:
			return Unresolvable, false
		}
	}
	return b.String(), true
}

// expand rewrites one invocation into the invocations it actually performs:
// stripping wrapper prefixes, descending into nested shells, and recovering the
// command xargs will run.
func expand(inv Invocation, depth int) []Invocation {
	if depth > maxDepth {
		inv.Unknown = true
		return []Invocation{inv}
	}
	if len(inv.Argv) == 0 {
		return nil
	}

	switch base(inv.Argv[0]) {
	case "sudo", "doas":
		rest := stripFlags(inv.Argv[1:])
		if len(rest) == 0 {
			return []Invocation{inv}
		}
		return expand(Invocation{Argv: rest, Redirects: inv.Redirects, Unknown: inv.Unknown}, depth+1)

	case "env":
		rest := inv.Argv[1:]
		for len(rest) > 0 && strings.Contains(rest[0], "=") {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return []Invocation{inv}
		}
		return expand(Invocation{Argv: rest, Redirects: inv.Redirects, Unknown: inv.Unknown}, depth+1)

	case "bash", "sh", "zsh", "dash":
		script, ok := dashCArgument(inv.Argv)
		if !ok {
			return []Invocation{inv}
		}
		if script == Unresolvable {
			inv.Unknown = true
			return []Invocation{inv}
		}
		nested, err := parseAt(script, depth+1)
		if err != nil || len(nested) == 0 {
			inv.Unknown = true
			return []Invocation{inv}
		}
		return nested

	case "xargs":
		rest := stripFlags(inv.Argv[1:])
		if len(rest) == 0 {
			return []Invocation{inv}
		}
		// xargs appends argv read from stdin, which source alone cannot supply.
		out := expand(Invocation{Argv: rest, Redirects: inv.Redirects}, depth+1)
		for i := range out {
			out[i].Unknown = true
		}
		return out
	}

	return []Invocation{inv}
}

// dashCArgument returns the script passed to a shell's -c flag.
func dashCArgument(argv []string) (string, bool) {
	for i := 1; i < len(argv)-1; i++ {
		if argv[i] == "-c" {
			return argv[i+1], true
		}
	}
	return "", false
}

// stripFlags drops leading dash-prefixed arguments to reach the wrapped command.
func stripFlags(argv []string) []string {
	for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
		argv = argv[1:]
	}
	return argv
}

// base strips any directory prefix, so /bin/rm and rm resolve alike.
func base(cmd string) string {
	if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
		return cmd[i+1:]
	}
	return cmd
}
