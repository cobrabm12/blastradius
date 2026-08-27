# blastradius Analysis Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic core that turns a shell command into a computed blast radius and a policy verdict, exposed through `blastradius explain`.

**Architecture:** A single pure pipeline — `shell.Parse` turns bash source into concrete invocations, `paths.Expand` resolves the strings they touch into absolute paths, `effects.Extract` maps each invocation to what it destroys, and `policy.Evaluate` matches that against ordered rules to produce a verdict with rule provenance. No I/O inside the pipeline; the CLI is the only boundary that touches the filesystem.

**Tech Stack:** Go 1.25, `mvdan.cc/sh/v3` (bash AST), `github.com/bmatcuk/doublestar/v4` (glob matching), `gopkg.in/yaml.v3`.

**Spec:** `docs/superpowers/specs/2026-08-27-blastradius-design.md`

## Global Constraints

- Module path: `github.com/cobrabm12/blastradius`.
- Go 1.25.0 or later. `go.mod` declares `go 1.25.0`; the toolchain upgrades itself.
- Pinned dependencies: `mvdan.cc/sh/v3 v3.13.1`, `github.com/bmatcuk/doublestar/v4 v4.10.0`, `gopkg.in/yaml.v3 v3.0.1`. No others in this plan.
- **No language model is consulted anywhere in this codebase.** Spec §7.
- **Incomplete analysis is never silent approval.** Any unresolved word, unregistered command, or parse failure sets `Unknown`, which routes to the policy's `on_error`. Spec §7.
- Closed verb vocabulary. Paths: `read`, `write`, `delete`, `truncate`. Hosts: `read`, `write`, `exec`. Nothing else is a verb. Spec §4.
- Every `Verdict` carries the identifier of the rule that produced it. A verdict without provenance is a bug. Spec §3.
- The whole pipeline is a pure function of `(command, cwd, env, policy)`. No filesystem access, no network, no clock reads inside `internal/`.
- All identifiers, comments, commit messages, and documentation in English — this is a public repository.

**Refinement of spec §3 adopted by this plan:** the `Effects` struct gains a `Truncates` field, separate from `Writes`. Spec §4 defines `truncate` as a distinct policy verb, so the analysis must distinguish it. This is an addition, not a contradiction.

## File Structure

| File | Responsibility |
|---|---|
| `go.mod`, `go.sum` | Module definition and pinned dependencies |
| `internal/shell/shell.go` | Bash source → `[]Invocation`; word rendering; descent into nested commands |
| `internal/shell/shell_test.go` | Parser behavior, including every bypass from spec §1 |
| `internal/paths/paths.go` | `Path`, `Context`, `Expand` — tilde, variables, braces, globs, absolutization |
| `internal/paths/paths_test.go` | Expansion behavior and unresolvability |
| `internal/effects/effects.go` | `Effects`, `Verb`, `Remote`, registry, `Extract` |
| `internal/effects/fs.go` | Extractors for filesystem commands: `rm`, `mv`, `cp`, `dd`, `truncate`, `tee` |
| `internal/effects/find.go` | `find` extractor, including `-delete` and `-exec` |
| `internal/effects/git.go` | `git` extractor: `clean`, `reset --hard`, `push --force`, `checkout` |
| `internal/effects/remote.go` | `ssh`, `scp`, `rsync`, `psql`, `mysql`, `docker`, `pm2` |
| `internal/effects/*_test.go` | One test file per extractor file |
| `internal/policy/policy.go` | `Policy`, `Rule`, `Decision`, `Load`, `Merge` |
| `internal/policy/evaluate.go` | `Verdict`, `Evaluate` — last-match-wins, severity resolution |
| `internal/policy/*_test.go` | Loading, merging, evaluation |
| `internal/engine/engine.go` | `Analyze` — wires the pipeline together |
| `internal/engine/corpus_test.go` | Declarative YAML corpus harness (spec §8) |
| `testdata/corpus/*.yaml` | Corpus cases |
| `testdata/policies/*.yaml` | Policies referenced by corpus cases |
| `cmd/blastradius/main.go` | CLI entrypoint |
| `cmd/blastradius/explain.go` | `explain` subcommand and its rendering |

---

### Task 1: Module skeleton and literal word rendering

**Files:**
- Create: `go.mod`
- Create: `internal/shell/shell.go`
- Test: `internal/shell/shell_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `shell.Unresolvable` (string sentinel), `shell.Invocation{Argv []string; Redirects []Redirect; Unknown bool}`, `shell.Parse(src string) ([]Invocation, error)`.

- [ ] **Step 1: Write the failing test**

```go
// internal/shell/shell_test.go
package shell

import "testing"

func TestParseSimpleCommand(t *testing.T) {
	invs, err := Parse(`rm -r -f /tmp/x`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 1 {
		t.Fatalf("got %d invocations, want 1", len(invs))
	}
	want := []string{"rm", "-r", "-f", "/tmp/x"}
	if got := invs[0].Argv; !equal(got, want) {
		t.Errorf("Argv = %q, want %q", got, want)
	}
}

func TestParseQuotingAndVariables(t *testing.T) {
	invs, err := Parse(`rm -rf "$HOME/p" '/lit eral'`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"rm", "-rf", "${HOME}/p", "/lit eral"}
	if got := invs[0].Argv; !equal(got, want) {
		t.Errorf("Argv = %q, want %q", got, want)
	}
}

func TestParseCommandSubstitutionIsUnresolvable(t *testing.T) {
	invs, err := Parse(`rm -rf $(cat target.txt)`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !invs[0].Unknown {
		t.Error("Unknown = false, want true for command substitution")
	}
	if invs[0].Argv[2] != Unresolvable {
		t.Errorf("Argv[2] = %q, want the Unresolvable sentinel", invs[0].Argv[2])
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/shell/ -run TestParse -v
```

Expected: build failure — `undefined: Parse`, `undefined: Unresolvable`, `undefined: Invocation`.

- [ ] **Step 3: Write the minimal implementation**

Create `go.mod`:

```bash
cd ~/blastradius
go mod init github.com/cobrabm12/blastradius
go get mvdan.cc/sh/v3@v3.13.1
```

```go
// internal/shell/shell.go

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
	f, err := syntax.NewParser().Parse(strings.NewReader(src), "")
	if err != nil {
		return nil, err
	}
	var out []Invocation
	syntax.Walk(f, func(n syntax.Node) bool {
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		inv := Invocation{}
		for _, w := range call.Args {
			lit, ok := word(w)
			if !ok {
				inv.Unknown = true
			}
			inv.Argv = append(inv.Argv, lit)
		}
		out = append(out, inv)
		return true
	})
	return out, nil
}

// word renders a single word. The bool reports whether the rendering is exact.
func word(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", true
	}
	var b strings.Builder
	exact := true
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
	return b.String(), exact
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/shell/ -v
```

Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add go.mod go.sum internal/shell/
git commit -m "feat(shell): parse bash into invocations with literal word rendering"
```

---

### Task 2: Redirections, pipelines, and command chains

**Files:**
- Modify: `internal/shell/shell.go`
- Test: `internal/shell/shell_test.go`

**Interfaces:**
- Consumes: `Invocation`, `Redirect`, `Parse` from Task 1.
- Produces: `Parse` now populates `Invocation.Redirects`; redirections are attached to the invocation they belong to.

Redirections hang off `*syntax.Stmt`, not off `*syntax.CallExpr`, so the walk must key on statements to associate the two. This is why `: > production.db` is invisible to the walk written in Task 1.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/shell/shell_test.go

func TestParseTruncatingRedirect(t *testing.T) {
	invs, err := Parse(`: > production.db`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 1 {
		t.Fatalf("got %d invocations, want 1", len(invs))
	}
	if len(invs[0].Redirects) != 1 {
		t.Fatalf("got %d redirects, want 1", len(invs[0].Redirects))
	}
	r := invs[0].Redirects[0]
	if r.Op != RedirWrite || r.Target != "production.db" {
		t.Errorf("redirect = %+v, want {RedirWrite production.db}", r)
	}
}

func TestParsePipelineAndChain(t *testing.T) {
	invs, err := Parse(`cat a | tee b && rm -rf c`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 3 {
		t.Fatalf("got %d invocations, want 3", len(invs))
	}
	if invs[0].Argv[0] != "cat" || invs[1].Argv[0] != "tee" || invs[2].Argv[0] != "rm" {
		t.Errorf("commands = %q/%q/%q, want cat/tee/rm",
			invs[0].Argv[0], invs[1].Argv[0], invs[2].Argv[0])
	}
}

func TestParseAppendRedirect(t *testing.T) {
	invs, err := Parse(`echo x >> log.txt`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if invs[0].Redirects[0].Op != RedirAppend {
		t.Errorf("op = %v, want RedirAppend", invs[0].Redirects[0].Op)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/shell/ -run 'Redirect|Pipeline' -v
```

Expected: FAIL — `got 0 redirects, want 1`, because Task 1 never reads `Stmt.Redirs`.

- [ ] **Step 3: Write the minimal implementation**

Replace the body of `Parse` in `internal/shell/shell.go`:

```go
// Parse renders bash source as the invocations it performs, in source order.
func Parse(src string) ([]Invocation, error) {
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
		out = append(out, invocationFrom(call, stmt.Redirs))
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
			continue // duplications like 2>&1 move no file data
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
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/shell/ -v
```

Expected: PASS, including the Task 1 tests, which must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/shell/
git commit -m "feat(shell): attach redirections to their statement's invocation"
```

---

### Task 3: Descent into nested commands

**Files:**
- Modify: `internal/shell/shell.go`
- Test: `internal/shell/shell_test.go`

**Interfaces:**
- Consumes: `Parse`, `Invocation` from Task 2.
- Produces: `Parse` now also yields invocations nested inside `bash -c`, behind `sudo`/`env` prefixes, and after `xargs`. `find -exec` is handled in Task 7, where `find`'s own flags are parsed.

This task closes three of the six bypasses catalogued in spec §1.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/shell/shell_test.go

func TestParseDescendsIntoBashDashC(t *testing.T) {
	invs, err := Parse(`bash -c 'rm -rf ~/data'`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var found bool
	for _, inv := range invs {
		if inv.Argv[0] == "rm" && inv.Argv[len(inv.Argv)-1] == "~/data" {
			found = true
		}
	}
	if !found {
		t.Errorf("no rm invocation recovered from bash -c; got %+v", invs)
	}
}

func TestParseStripsSudoAndEnvPrefixes(t *testing.T) {
	for _, src := range []string{`sudo rm -rf /srv/x`, `env FOO=1 rm -rf /srv/x`} {
		invs, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if invs[0].Argv[0] != "rm" {
			t.Errorf("Parse(%q) argv[0] = %q, want rm", src, invs[0].Argv[0])
		}
	}
}

func TestParseXargsYieldsTrailingCommandAsUnknown(t *testing.T) {
	invs, err := Parse(`xargs rm < filelist`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var rm *Invocation
	for i := range invs {
		if invs[i].Argv[0] == "rm" {
			rm = &invs[i]
		}
	}
	if rm == nil {
		t.Fatal("no rm invocation recovered from xargs")
	}
	if !rm.Unknown {
		t.Error("Unknown = false, want true: xargs supplies argv from stdin")
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/shell/ -run 'BashDashC|Sudo|Xargs' -v
```

Expected: FAIL — `no rm invocation recovered from bash -c`, and `argv[0] = "sudo", want rm`.

- [ ] **Step 3: Write the minimal implementation**

Add to `internal/shell/shell.go`, and call `expand` on each invocation inside `Parse` before appending:

```go
// maxDepth bounds recursion through nested interpreters. A command nested more
// deeply than this is reported Unknown rather than analyzed.
const maxDepth = 8

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

	switch inv.Argv[0] {
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
		if err != nil {
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
```

Restructure `Parse` so recursion carries depth:

```go
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
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/shell/ -v
```

Expected: PASS for all Task 1–3 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/shell/
git commit -m "feat(shell): descend into bash -c, sudo/env prefixes, and xargs"
```

---

### Task 4: Path expansion and resolution

**Files:**
- Create: `internal/paths/paths.go`
- Test: `internal/paths/paths_test.go`

**Interfaces:**
- Consumes: `shell.Unresolvable` from Task 1.
- Produces: `paths.Path{Raw, Abs string; Resolved, IsGlob bool}`, `paths.Context{Cwd, Home string; Env map[string]string}`, `paths.Expand(raw string, ctx Context) []Path`.

Brace expansion yields several paths from one word, which is why `Expand` returns a slice. Globs are *not* expanded against a real filesystem — the pipeline is pure, and policy matching in Task 10 compares patterns directly.

- [ ] **Step 1: Write the failing test**

```go
// internal/paths/paths_test.go
package paths

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/shell"
)

func ctx() Context {
	return Context{
		Cwd:  "/home/u/app",
		Home: "/home/u",
		Env:  map[string]string{"HOME": "/home/u", "TARGET": "/srv/data"},
	}
}

func TestExpandTilde(t *testing.T) {
	got := Expand("~/data", ctx())
	if len(got) != 1 || got[0].Abs != "/home/u/data" || !got[0].Resolved {
		t.Errorf("got %+v, want one resolved /home/u/data", got)
	}
}

func TestExpandVariable(t *testing.T) {
	got := Expand("${TARGET}/x", ctx())
	if len(got) != 1 || got[0].Abs != "/srv/data/x" {
		t.Errorf("got %+v, want /srv/data/x", got)
	}
}

func TestExpandUnsetVariableIsUnresolved(t *testing.T) {
	got := Expand("${NOPE}/x", ctx())
	if len(got) != 1 || got[0].Resolved {
		t.Errorf("got %+v, want a single unresolved path", got)
	}
}

func TestExpandRelativeAgainstCwd(t *testing.T) {
	got := Expand("build", ctx())
	if got[0].Abs != "/home/u/app/build" {
		t.Errorf("Abs = %q, want /home/u/app/build", got[0].Abs)
	}
}

func TestExpandBraces(t *testing.T) {
	got := Expand("/srv/{a,b}/x", ctx())
	if len(got) != 2 || got[0].Abs != "/srv/a/x" || got[1].Abs != "/srv/b/x" {
		t.Errorf("got %+v, want /srv/a/x and /srv/b/x", got)
	}
}

func TestExpandGlobIsMarkedNotExpanded(t *testing.T) {
	got := Expand("*.db", ctx())
	if len(got) != 1 || !got[0].IsGlob || got[0].Abs != "/home/u/app/*.db" {
		t.Errorf("got %+v, want a single glob /home/u/app/*.db", got)
	}
}

func TestExpandUnresolvableSentinel(t *testing.T) {
	got := Expand(shell.Unresolvable, ctx())
	if len(got) != 1 || got[0].Resolved {
		t.Errorf("got %+v, want a single unresolved path", got)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/paths/ -v
```

Expected: build failure — `undefined: Expand`, `undefined: Context`, `undefined: Path`.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/paths/paths.go

// Package paths resolves the strings a command names into absolute paths.
//
// Resolution is pure: it consults the supplied Context, never the filesystem.
// Anything it cannot resolve is returned with Resolved false, which the policy
// layer treats as unknown rather than as safe.
package paths

import (
	"path/filepath"
	"strings"

	"github.com/cobrabm12/blastradius/internal/shell"
)

// Path is one filesystem target named by a command.
type Path struct {
	Raw      string // as written in the command
	Abs      string // absolute; a glob pattern when IsGlob
	Resolved bool   // false when the value could not be determined from source
	IsGlob   bool   // contains wildcard metacharacters, left unexpanded
}

// Context is the environment a command runs in.
type Context struct {
	Cwd  string
	Home string
	Env  map[string]string
}

// Expand resolves one word into the paths it names. Brace expansion can yield
// several; everything else yields exactly one.
func Expand(raw string, ctx Context) []Path {
	if raw == shell.Unresolvable || raw == "" {
		return []Path{{Raw: raw, Resolved: false}}
	}
	var out []Path
	for _, branch := range expandBraces(raw) {
		out = append(out, resolveOne(branch, raw, ctx))
	}
	return out
}

func resolveOne(s, raw string, ctx Context) Path {
	s, ok := substituteVars(s, ctx.Env)
	if !ok {
		return Path{Raw: raw, Resolved: false}
	}
	if s == "~" {
		s = ctx.Home
	} else if strings.HasPrefix(s, "~/") {
		s = filepath.Join(ctx.Home, s[2:])
	}
	isGlob := strings.ContainsAny(s, "*?[")
	if !filepath.IsAbs(s) {
		s = filepath.Join(ctx.Cwd, s)
	} else {
		s = filepath.Clean(s)
	}
	return Path{Raw: raw, Abs: s, Resolved: true, IsGlob: isGlob}
}

// substituteVars replaces ${NAME} references. The bool reports whether every
// reference was known.
func substituteVars(s string, env map[string]string) (string, bool) {
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			return s, true
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			return s, false
		}
		end += start
		name := s[start+2 : end]
		val, ok := env[name]
		if !ok {
			return s, false
		}
		s = s[:start] + val + s[end+1:]
	}
}

// expandBraces performs one level of brace expansion: /a/{x,y}/z yields two.
func expandBraces(s string) []string {
	open := strings.Index(s, "{")
	if open < 0 {
		return []string{s}
	}
	close := strings.Index(s[open:], "}")
	if close < 0 {
		return []string{s}
	}
	close += open
	prefix, suffix := s[:open], s[close+1:]
	var out []string
	for _, alt := range strings.Split(s[open+1:close], ",") {
		out = append(out, expandBraces(prefix+alt+suffix)...)
	}
	return out
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/paths/ -v
```

Expected: PASS for all seven tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/paths/
git commit -m "feat(paths): resolve tildes, variables, braces, and globs purely"
```

---

### Task 5: Effects model, registry, and the `rm` extractor

**Files:**
- Create: `internal/effects/effects.go`
- Create: `internal/effects/fs.go`
- Test: `internal/effects/fs_test.go`

**Interfaces:**
- Consumes: `shell.Invocation` (Task 3), `paths.Path`, `paths.Context`, `paths.Expand` (Task 4).
- Produces: `effects.Verb` (`VerbRead`/`VerbWrite`/`VerbDelete`/`VerbTruncate`/`VerbExec`), `effects.Remote{Host string; Verb Verb}`, `effects.Effects{Deletes, Writes, Truncates, Reads []paths.Path; Remotes []Remote; Irreversible, Unknown bool; Notes []string}`, `(*Effects).Merge(Effects)`, `effects.Register(name string, fn Extractor)`, `effects.Extract(inv shell.Invocation, ctx paths.Context) Effects`.

The registry is the growth surface of the project: adding a command is a table entry plus corpus cases, never a new code path. An unregistered command yields `Unknown`, per spec §5.

- [ ] **Step 1: Write the failing test**

```go
// internal/effects/fs_test.go
package effects

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func ctx() paths.Context {
	return paths.Context{
		Cwd:  "/home/u/app",
		Home: "/home/u",
		Env:  map[string]string{"HOME": "/home/u"},
	}
}

func extract(t *testing.T, src string) Effects {
	t.Helper()
	invs, err := shell.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	var total Effects
	for _, inv := range invs {
		total.Merge(Extract(inv, ctx()))
	}
	return total
}

func TestRmRecursiveSplitFlags(t *testing.T) {
	// The bypass from spec §1: split flags plus a variable.
	got := extract(t, `rm -r -f "$HOME/p"`)
	if len(got.Deletes) != 1 || got.Deletes[0].Abs != "/home/u/p" {
		t.Fatalf("Deletes = %+v, want /home/u/p", got.Deletes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true")
	}
}

func TestRmCombinedFlags(t *testing.T) {
	got := extract(t, `rm -rf /srv/data`)
	if len(got.Deletes) != 1 || got.Deletes[0].Abs != "/srv/data" {
		t.Errorf("Deletes = %+v, want /srv/data", got.Deletes)
	}
}

func TestRmDoubleDashEndsFlags(t *testing.T) {
	got := extract(t, `rm -f -- -weird-name`)
	if len(got.Deletes) != 1 || got.Deletes[0].Abs != "/home/u/app/-weird-name" {
		t.Errorf("Deletes = %+v, want /home/u/app/-weird-name", got.Deletes)
	}
}

func TestUnregisteredCommandIsUnknown(t *testing.T) {
	got := extract(t, `frobnicate --wipe /srv`)
	if !got.Unknown {
		t.Error("Unknown = false, want true for an unregistered command")
	}
	if len(got.Deletes) != 0 {
		t.Errorf("Deletes = %+v, want none — an unknown command claims no effects", got.Deletes)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/effects/ -v
```

Expected: build failure — `undefined: Effects`, `undefined: Extract`.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/effects/effects.go

// Package effects maps a command invocation to what it does to the world.
//
// Every extractor is registered by command name. A command with no registered
// extractor produces Unknown rather than an empty result: absence of knowledge
// is never evidence of safety.
package effects

import (
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
	if inv.Unknown {
		out.Unknown = true
	}
	return out
}

// base strips any directory prefix, so /bin/rm and rm resolve alike.
func base(cmd string) string {
	for i := len(cmd) - 1; i >= 0; i-- {
		if cmd[i] == '/' {
			return cmd[i+1:]
		}
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
			flags[longFlagKey(a)] = true
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
	default:
		return 0
	}
}
```

```go
// internal/effects/fs.go
package effects

import (
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() {
	Register("rm", extractRm)
}

func extractRm(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	flags, targets := operands(inv.Argv)
	for _, t := range targets {
		e.Deletes = append(e.Deletes, paths.Expand(t, ctx)...)
	}
	// Deletion has no undo. Recursion only widens the radius.
	e.Irreversible = len(e.Deletes) > 0
	if flags['r'] {
		e.Notes = append(e.Notes, "recursive delete")
	}
	return e
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/effects/ -v
```

Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/effects/
git commit -m "feat(effects): effect model, extractor registry, and rm"
```

---

### Task 6: Redirection effects and the remaining filesystem commands

**Files:**
- Modify: `internal/effects/effects.go` (redirection handling inside `Extract`)
- Modify: `internal/effects/fs.go`
- Test: `internal/effects/fs_test.go`

**Interfaces:**
- Consumes: everything from Task 5.
- Produces: extractors registered for `mv`, `cp`, `dd`, `truncate`, `tee`; `Extract` now folds in effects implied by `Invocation.Redirects`.

`: > production.db` destroys a database without naming any destructive command. It is caught here, by reading redirections rather than argv.

- [ ] **Step 1: Write the failing test**

```go
// append to internal/effects/fs_test.go

func TestTruncatingRedirectIsATruncate(t *testing.T) {
	got := extract(t, `: > production.db`)
	if len(got.Truncates) != 1 || got.Truncates[0].Abs != "/home/u/app/production.db" {
		t.Fatalf("Truncates = %+v, want /home/u/app/production.db", got.Truncates)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true: truncation discards content")
	}
}

func TestAppendRedirectIsAWriteNotATruncate(t *testing.T) {
	got := extract(t, `echo x >> log.txt`)
	if len(got.Truncates) != 0 {
		t.Errorf("Truncates = %+v, want none for >>", got.Truncates)
	}
	if len(got.Writes) != 1 || got.Writes[0].Abs != "/home/u/app/log.txt" {
		t.Errorf("Writes = %+v, want /home/u/app/log.txt", got.Writes)
	}
}

func TestMvReadsSourceAndWritesDestination(t *testing.T) {
	got := extract(t, `mv a.txt /srv/b.txt`)
	if len(got.Deletes) != 1 || got.Deletes[0].Abs != "/home/u/app/a.txt" {
		t.Errorf("Deletes = %+v, want the source /home/u/app/a.txt", got.Deletes)
	}
	if len(got.Writes) != 1 || got.Writes[0].Abs != "/srv/b.txt" {
		t.Errorf("Writes = %+v, want /srv/b.txt", got.Writes)
	}
}

func TestDdIsIrreversible(t *testing.T) {
	got := extract(t, `dd if=/dev/zero of=/srv/disk.img`)
	if len(got.Writes) != 1 || got.Writes[0].Abs != "/srv/disk.img" {
		t.Errorf("Writes = %+v, want /srv/disk.img", got.Writes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for dd")
	}
}

func TestTeeWritesEachOperand(t *testing.T) {
	got := extract(t, `cat x | tee a.log b.log`)
	if len(got.Writes) != 2 {
		t.Errorf("Writes = %+v, want two", got.Writes)
	}
}
```

Note: `cat` is unregistered, so this last case also carries `Unknown` — which is correct and asserted in Task 11's corpus rather than here.

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/effects/ -run 'Redirect|Mv|Dd|Tee' -v
```

Expected: FAIL — `Truncates = [], want /home/u/app/production.db`, and `undefined` behavior for `mv`, `dd`, `tee` producing empty effects with `Unknown` set.

- [ ] **Step 3: Write the minimal implementation**

In `internal/effects/effects.go`, extend `Extract` to fold redirections in before returning:

```go
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
```

In `internal/effects/fs.go`, register the rest:

```go
func init() {
	Register("rm", extractRm)
	Register("mv", extractMv)
	Register("cp", extractCp)
	Register("dd", extractDd)
	Register("truncate", extractTruncate)
	Register("tee", extractTee)
}

// extractMv: every operand but the last is removed from its old location; the
// last is written.
func extractMv(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	for _, src := range ops[:len(ops)-1] {
		e.Deletes = append(e.Deletes, paths.Expand(src, ctx)...)
	}
	e.Writes = append(e.Writes, paths.Expand(ops[len(ops)-1], ctx)...)
	e.Irreversible = true
	return e
}

// extractCp: sources are read, the destination is written.
func extractCp(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	for _, src := range ops[:len(ops)-1] {
		e.Reads = append(e.Reads, paths.Expand(src, ctx)...)
	}
	e.Writes = append(e.Writes, paths.Expand(ops[len(ops)-1], ctx)...)
	return e
}

// extractDd reads if= and writes of=. Its writes are raw and unrecoverable.
func extractDd(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	for _, a := range inv.Argv[1:] {
		switch {
		case len(a) > 3 && a[:3] == "of=":
			e.Writes = append(e.Writes, paths.Expand(a[3:], ctx)...)
			e.Irreversible = true
		case len(a) > 3 && a[:3] == "if=":
			e.Reads = append(e.Reads, paths.Expand(a[3:], ctx)...)
		}
	}
	if len(e.Writes) == 0 {
		e.Unknown = true
	}
	return e
}

func extractTruncate(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	for _, t := range ops {
		e.Truncates = append(e.Truncates, paths.Expand(t, ctx)...)
	}
	e.Irreversible = len(e.Truncates) > 0
	return e
}

func extractTee(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	flags, ops := operands(inv.Argv)
	for _, t := range ops {
		expanded := paths.Expand(t, ctx)
		if flags['a'] {
			e.Writes = append(e.Writes, expanded...)
		} else {
			e.Truncates = append(e.Truncates, expanded...)
		}
	}
	return e
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/effects/ -v
```

Expected: PASS for all Task 5 and Task 6 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/effects/
git commit -m "feat(effects): redirections, mv, cp, dd, truncate, tee"
```

---

### Task 7: `find` and `git`

**Files:**
- Create: `internal/effects/find.go`
- Create: `internal/effects/git.go`
- Test: `internal/effects/find_test.go`, `internal/effects/git_test.go`

**Interfaces:**
- Consumes: everything from Task 6.
- Produces: extractors registered for `find` and `git`; `Effects.Notes` carries git subcommand detail used by `explain` and by the git rules in Task 10.

Two of the six bypasses in spec §1 — `find . -name '*.db' -delete` and `git clean -xfd` — delete files without invoking `rm`.

- [ ] **Step 1: Write the failing test**

```go
// internal/effects/find_test.go
package effects

import "testing"

func TestFindDeleteDeletesUnderTheSearchRoot(t *testing.T) {
	got := extract(t, `find . -name '*.db' -delete`)
	if len(got.Deletes) != 1 {
		t.Fatalf("Deletes = %+v, want one", got.Deletes)
	}
	if got.Deletes[0].Abs != "/home/u/app/*.db" || !got.Deletes[0].IsGlob {
		t.Errorf("Deletes[0] = %+v, want the glob /home/u/app/*.db", got.Deletes[0])
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true")
	}
}

func TestFindWithoutDeleteOnlyReads(t *testing.T) {
	got := extract(t, `find /srv -name '*.log'`)
	if len(got.Deletes) != 0 {
		t.Errorf("Deletes = %+v, want none without -delete", got.Deletes)
	}
	if len(got.Reads) == 0 {
		t.Error("Reads is empty, want the search root")
	}
}

func TestFindExecRmIsAnalyzed(t *testing.T) {
	got := extract(t, `find /srv -name '*.tmp' -exec rm -f {} ;`)
	if len(got.Deletes) == 0 {
		t.Error("Deletes is empty, want the -exec rm target treated as a delete")
	}
}
```

```go
// internal/effects/git_test.go
package effects

import "testing"

func TestGitCleanDeletesWorkingTree(t *testing.T) {
	got := extract(t, `git clean -xfd`)
	if len(got.Deletes) != 1 || got.Deletes[0].Abs != "/home/u/app" {
		t.Fatalf("Deletes = %+v, want the working tree /home/u/app", got.Deletes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true: git clean discards untracked files")
	}
}

func TestGitResetHardIsIrreversible(t *testing.T) {
	got := extract(t, `git reset --hard HEAD~3`)
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for reset --hard")
	}
}

func TestGitForcePushIsNotedAsIrreversible(t *testing.T) {
	got := extract(t, `git push --force origin main`)
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for a force push")
	}
	if !hasNote(got, "git:push --force") {
		t.Errorf("Notes = %q, want a git:push --force note", got.Notes)
	}
}

func TestGitStatusIsHarmless(t *testing.T) {
	got := extract(t, `git status`)
	if got.Irreversible || len(got.Deletes) != 0 {
		t.Errorf("got %+v, want no destructive effects for git status", got)
	}
}

func hasNote(e Effects, want string) bool {
	for _, n := range e.Notes {
		if n == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/effects/ -run 'Find|Git' -v
```

Expected: FAIL — `find` and `git` are unregistered, so every case reports empty effects with `Unknown` set.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/effects/find.go
package effects

import (
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() { Register("find", extractFind) }

// extractFind models find as acting on `<root>/<name pattern>`. Without -name,
// the whole subtree under the root is the radius.
func extractFind(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	root := "."
	pattern := ""
	deleting := false
	var execArgv []string

	args := inv.Argv[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-delete":
			deleting = true
		case "-name", "-iname", "-path", "-wholename":
			if i+1 < len(args) {
				pattern = args[i+1]
				i++
			}
		case "-exec", "-execdir":
			for j := i + 1; j < len(args); j++ {
				if args[j] == ";" || args[j] == "+" {
					break
				}
				if args[j] != "{}" {
					execArgv = append(execArgv, args[j])
				}
			}
			i = len(args)
		default:
			if i == 0 && args[i] != "" && args[i][0] != '-' {
				root = args[i]
			}
		}
	}

	target := root
	if pattern != "" {
		target = root + "/" + pattern
	}
	expanded := paths.Expand(target, ctx)

	if deleting {
		e.Deletes = append(e.Deletes, expanded...)
		e.Irreversible = true
	} else {
		e.Reads = append(e.Reads, expanded...)
	}

	// -exec runs another command once per match; analyze it against the matches.
	if len(execArgv) > 0 {
		nested := Extract(shell.Invocation{Argv: append(execArgv, target)}, ctx)
		e.Merge(nested)
	}
	return e
}
```

```go
// internal/effects/git.go
package effects

import (
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() { Register("git", extractGit) }

// extractGit models the git subcommands that destroy work. Everything else is
// reported as a read of the working tree.
func extractGit(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	tree := paths.Expand(".", ctx)

	sub := ""
	var rest []string
	for _, a := range inv.Argv[1:] {
		if sub == "" && a != "" && a[0] != '-' {
			sub = a
			continue
		}
		rest = append(rest, a)
	}

	switch sub {
	case "clean":
		e.Deletes = append(e.Deletes, tree...)
		e.Irreversible = true
		e.Notes = append(e.Notes, "git:clean")
	case "reset":
		if hasArg(rest, "--hard") {
			e.Writes = append(e.Writes, tree...)
			e.Irreversible = true
			e.Notes = append(e.Notes, "git:reset --hard")
		} else {
			e.Reads = append(e.Reads, tree...)
		}
	case "push":
		if hasArg(rest, "--force") || hasArg(rest, "-f") || hasArg(rest, "--force-with-lease") {
			e.Irreversible = true
			e.Notes = append(e.Notes, "git:push --force")
		}
		e.Notes = append(e.Notes, "git:push:"+branchOf(rest))
	case "checkout", "switch", "restore":
		e.Writes = append(e.Writes, tree...)
		e.Notes = append(e.Notes, "git:"+sub)
	default:
		e.Reads = append(e.Reads, tree...)
	}
	return e
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// branchOf returns the last non-flag operand, which for `git push <remote>
// <branch>` is the branch. Empty when none is given.
func branchOf(args []string) string {
	last := ""
	for _, a := range args {
		if a != "" && a[0] != '-' {
			last = a
		}
	}
	return last
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/effects/ -v
```

Expected: PASS for every effects test.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/effects/
git commit -m "feat(effects): find -delete/-exec and destructive git subcommands"
```

---

### Task 8: Remote targets

**Files:**
- Create: `internal/effects/remote.go`
- Test: `internal/effects/remote_test.go`

**Interfaces:**
- Consumes: everything from Task 7.
- Produces: extractors registered for `ssh`, `scp`, `rsync`, `psql`, `mysql`, `docker`, `pm2`; each appends to `Effects.Remotes`.

Host rules are the half of the policy that protects production servers. Spec §4.

- [ ] **Step 1: Write the failing test**

```go
// internal/effects/remote_test.go
package effects

import "testing"

func hasRemote(e Effects, host string, verb Verb) bool {
	for _, r := range e.Remotes {
		if r.Host == host && r.Verb == verb {
			return true
		}
	}
	return false
}

func TestSSHIsRemoteExec(t *testing.T) {
	got := extract(t, `ssh deploy@86.123.173.94 'systemctl restart app'`)
	if !hasRemote(got, "86.123.173.94", VerbExec) {
		t.Errorf("Remotes = %+v, want exec on 86.123.173.94", got.Remotes)
	}
}

func TestRsyncToRemoteIsRemoteWrite(t *testing.T) {
	got := extract(t, `rsync -av ./dist/ deploy@prod.ezweb.ro:/var/www/`)
	if !hasRemote(got, "prod.ezweb.ro", VerbWrite) {
		t.Errorf("Remotes = %+v, want write on prod.ezweb.ro", got.Remotes)
	}
}

func TestRsyncFromRemoteIsRemoteRead(t *testing.T) {
	got := extract(t, `rsync -av deploy@prod.ezweb.ro:/var/www/ ./dist/`)
	if !hasRemote(got, "prod.ezweb.ro", VerbRead) {
		t.Errorf("Remotes = %+v, want read on prod.ezweb.ro", got.Remotes)
	}
}

func TestPsqlDropIsIrreversibleRemoteWrite(t *testing.T) {
	got := extract(t, `psql -h db.ezweb.ro -c 'DROP TABLE orders'`)
	if !hasRemote(got, "db.ezweb.ro", VerbWrite) {
		t.Errorf("Remotes = %+v, want write on db.ezweb.ro", got.Remotes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for DROP")
	}
}

func TestPsqlSelectIsRemoteRead(t *testing.T) {
	got := extract(t, `psql -h db.ezweb.ro -c 'SELECT 1'`)
	if !hasRemote(got, "db.ezweb.ro", VerbRead) {
		t.Errorf("Remotes = %+v, want read on db.ezweb.ro", got.Remotes)
	}
}

func TestLocalDockerIsNotARemote(t *testing.T) {
	got := extract(t, `docker ps`)
	if len(got.Remotes) != 0 {
		t.Errorf("Remotes = %+v, want none without -H", got.Remotes)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/effects/ -run 'SSH|Rsync|Psql|Docker' -v
```

Expected: FAIL — `Remotes = [], want …` for each case.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/effects/remote.go
package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() {
	Register("ssh", extractSSH)
	Register("scp", extractTransfer)
	Register("rsync", extractTransfer)
	Register("psql", extractSQL)
	Register("mysql", extractSQL)
	Register("docker", extractDocker)
	Register("pm2", extractPM2)
}

// hostOf strips a user@ prefix and any :path suffix from a remote spec.
// The bool reports whether the argument names a remote at all.
func hostOf(arg string) (string, bool) {
	if i := strings.Index(arg, ":"); i >= 0 {
		arg = arg[:i]
	} else if !strings.Contains(arg, "@") {
		return "", false
	}
	if i := strings.Index(arg, "@"); i >= 0 {
		arg = arg[i+1:]
	}
	if arg == "" {
		return "", false
	}
	return arg, true
}

func extractSSH(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) == 0 {
		e.Unknown = true
		return e
	}
	host := ops[0]
	if i := strings.Index(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbExec})
	if len(ops) > 1 {
		// The remote command is not analyzed: it runs under a different
		// filesystem and policy than the one we hold.
		e.Unknown = true
		e.Notes = append(e.Notes, "remote command not analyzed: "+strings.Join(ops[1:], " "))
	}
	return e
}

// extractTransfer covers scp and rsync: a remote source is a read, a remote
// destination is a write.
func extractTransfer(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	dst := ops[len(ops)-1]
	if host, ok := hostOf(dst); ok {
		e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbWrite})
	} else {
		e.Writes = append(e.Writes, paths.Expand(dst, ctx)...)
	}
	for _, src := range ops[:len(ops)-1] {
		if host, ok := hostOf(src); ok {
			e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbRead})
		} else {
			e.Reads = append(e.Reads, paths.Expand(src, ctx)...)
		}
	}
	return e
}

// destructiveSQL reports whether a statement destroys data. Matching is
// deliberately coarse: an unrecognised statement is treated as a write.
var destructiveSQL = []string{"drop ", "truncate ", "delete "}

func extractSQL(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	host := ""
	sql := ""
	for i, a := range inv.Argv[1:] {
		switch a {
		case "-h", "--host":
			if i+2 < len(inv.Argv) {
				host = inv.Argv[i+2]
			}
		case "-c", "--command", "-e":
			if i+2 < len(inv.Argv) {
				sql = inv.Argv[i+2]
			}
		}
	}
	if host == "" {
		host = "localhost"
	}

	verb := VerbWrite
	lower := strings.ToLower(strings.TrimSpace(sql))
	switch {
	case sql == "":
		e.Unknown = true
		e.Notes = append(e.Notes, "SQL not given on the command line")
	case strings.HasPrefix(lower, "select"), strings.HasPrefix(lower, "explain"):
		verb = VerbRead
	default:
		for _, d := range destructiveSQL {
			if strings.Contains(lower, d) {
				e.Irreversible = true
			}
		}
	}
	e.Remotes = append(e.Remotes, Remote{Host: host, Verb: verb})
	return e
}

func extractDocker(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	for i, a := range inv.Argv[1:] {
		if (a == "-H" || a == "--host") && i+2 < len(inv.Argv) {
			e.Remotes = append(e.Remotes, Remote{Host: inv.Argv[i+2], Verb: VerbExec})
		}
	}
	e.Notes = append(e.Notes, "docker: container effects are not modeled")
	e.Unknown = true
	return e
}

func extractPM2(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) > 0 && (ops[0] == "delete" || ops[0] == "kill") {
		e.Irreversible = true
	}
	e.Notes = append(e.Notes, "pm2: process effects are not modeled")
	return e
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/effects/ -v
```

Expected: PASS for every effects test.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/effects/
git commit -m "feat(effects): remote targets for ssh, transfers, SQL, docker, pm2"
```

---

### Task 9: Policy loading, validation, and merging

**Files:**
- Create: `internal/policy/policy.go`
- Test: `internal/policy/policy_test.go`

**Interfaces:**
- Consumes: `effects.Verb` from Task 5.
- Produces: `policy.Decision` (`Allow`/`Ask`/`Block`), `policy.Rule{Match string; Deny, Ask, Allow []effects.Verb; Reason string}`, `policy.GitRules{ProtectedBranches, Deny []string}`, `policy.Policy{Version int; OnError Decision; Paths, Hosts []Rule; Git GitRules; Audit struct{Path string}}`, `policy.Load(data []byte) (*Policy, error)`, `policy.Merge(repo, user *Policy) *Policy`.

Merge order is load-bearing: repository rules first, user rules last. Combined with the last-match-wins evaluation of Task 10, that makes machine policy authoritative — a repository cannot relax a protection its owner set. Spec §4.

- [ ] **Step 1: Write the failing test**

```go
// internal/policy/policy_test.go
package policy

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/effects"
)

const sample = `
version: 1
on_error: ask
paths:
  - match: "~/prod/**"
    deny: [write, delete, truncate]
    reason: "Production source."
  - match: "**/node_modules/**"
    allow: [delete, truncate]
hosts:
  - match: "86.123.173.94"
    deny: [write, exec]
git:
  protected_branches: [main]
  deny: [force_push]
`

func TestLoadParsesRules(t *testing.T) {
	p, err := Load([]byte(sample))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.OnError != Ask {
		t.Errorf("OnError = %q, want ask", p.OnError)
	}
	if len(p.Paths) != 2 || p.Paths[0].Match != "~/prod/**" {
		t.Fatalf("Paths = %+v, want two rules starting with ~/prod/**", p.Paths)
	}
	if len(p.Paths[0].Deny) != 3 || p.Paths[0].Deny[0] != effects.VerbWrite {
		t.Errorf("Deny = %+v, want [write delete truncate]", p.Paths[0].Deny)
	}
	if len(p.Hosts) != 1 || p.Hosts[0].Match != "86.123.173.94" {
		t.Errorf("Hosts = %+v, want one rule for 86.123.173.94", p.Hosts)
	}
}

func TestLoadDefaultsOnErrorToAsk(t *testing.T) {
	p, err := Load([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.OnError != Ask {
		t.Errorf("OnError = %q, want ask by default", p.OnError)
	}
}

func TestLoadRejectsUnknownVerb(t *testing.T) {
	_, err := Load([]byte("version: 1\npaths:\n  - match: \"x\"\n    deny: [detonate]\n"))
	if err == nil {
		t.Fatal("Load accepted the verb \"detonate\", want an error")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	if _, err := Load([]byte("version: 99\n")); err == nil {
		t.Fatal("Load accepted version 99, want an error")
	}
}

func TestMergePutsUserRulesLast(t *testing.T) {
	repo, err := Load([]byte("version: 1\npaths:\n  - match: \"**\"\n    allow: [delete]\n"))
	if err != nil {
		t.Fatalf("Load repo: %v", err)
	}
	user, err := Load([]byte("version: 1\npaths:\n  - match: \"~/prod/**\"\n    deny: [delete]\n"))
	if err != nil {
		t.Fatalf("Load user: %v", err)
	}
	m := Merge(repo, user)
	if len(m.Paths) != 2 {
		t.Fatalf("Paths = %+v, want two", m.Paths)
	}
	if m.Paths[1].Match != "~/prod/**" {
		t.Errorf("last rule = %q, want the user rule ~/prod/** to come last", m.Paths[1].Match)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/policy/ -v
```

Expected: build failure — `undefined: Load`, `undefined: Policy`.

- [ ] **Step 3: Write the minimal implementation**

```bash
cd ~/blastradius && go get gopkg.in/yaml.v3@v3.0.1
```

```go
// internal/policy/policy.go

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

// Policy is a parsed guard.yaml.
type Policy struct {
	Version int      `yaml:"version"`
	OnError Decision `yaml:"on_error"`
	Paths   []Rule   `yaml:"paths"`
	Hosts   []Rule   `yaml:"hosts"`
	Git     GitRules `yaml:"git"`
	Audit   struct {
		Path string `yaml:"path"`
	} `yaml:"audit"`
}

var pathVerbs = map[effects.Verb]bool{
	effects.VerbRead: true, effects.VerbWrite: true,
	effects.VerbDelete: true, effects.VerbTruncate: true,
}

var hostVerbs = map[effects.Verb]bool{
	effects.VerbRead: true, effects.VerbWrite: true, effects.VerbExec: true,
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
	out.Git.ProtectedBranches = append(repo.Git.ProtectedBranches, user.Git.ProtectedBranches...)
	out.Git.Deny = append(repo.Git.Deny, user.Git.Deny...)
	out.OnError = user.OnError
	if user.Audit.Path != "" {
		out.Audit.Path = user.Audit.Path
	}
	return &out
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/policy/ -v
```

Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add go.mod go.sum internal/policy/
git commit -m "feat(policy): load, validate, and merge guard.yaml"
```

---

### Task 10: Policy evaluation

**Files:**
- Create: `internal/policy/evaluate.go`
- Test: `internal/policy/evaluate_test.go`

**Interfaces:**
- Consumes: `Policy`, `Rule`, `Decision`, `severity` (Task 9); `effects.Effects` (Task 5).
- Produces: `policy.Verdict{Decision Decision; Reason, Rule string; Radius effects.Effects}`, `policy.Evaluate(e effects.Effects, p *Policy) Verdict`.

Two rules govern the outcome. Within one (target, verb) pair, the **last** matching rule that names the verb decides. Across the whole blast radius, the **most severe** decision wins. Unmatched pairs are allowed; `Unknown` routes to `OnError`.

- [ ] **Step 1: Write the failing test**

```go
// internal/policy/evaluate_test.go
package policy

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
)

func mustLoad(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func abs(p string) paths.Path {
	return paths.Path{Raw: p, Abs: p, Resolved: true}
}

func TestBlocksDeniedDelete(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/prod/**"
    deny: [delete]
    reason: "Production data."
`)
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/srv/prod/db.sqlite")}}, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q, want block", v.Decision)
	}
	if v.Reason != "Production data." {
		t.Errorf("Reason = %q, want the rule's reason", v.Reason)
	}
	if v.Rule != "paths[0]" {
		t.Errorf("Rule = %q, want paths[0]", v.Rule)
	}
}

func TestLastMatchingRuleWins(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/**"
    deny: [delete]
  - match: "/srv/**/node_modules/**"
    allow: [delete]
`)
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/srv/app/node_modules/x")}}, p)
	if v.Decision != Allow {
		t.Errorf("Decision = %q, want allow: the later exception governs", v.Decision)
	}
}

func TestMostSevereDecisionAcrossRadiusWins(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/prod/**"
    deny: [delete]
`)
	e := effects.Effects{Deletes: []paths.Path{abs("/tmp/scratch"), abs("/srv/prod/db")}}
	if v := Evaluate(e, p); v.Decision != Block {
		t.Errorf("Decision = %q, want block: one denied path condemns the command", v.Decision)
	}
}

func TestUnmatchedPathIsAllowed(t *testing.T) {
	p := mustLoad(t, "version: 1\n")
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/tmp/x")}}, p)
	if v.Decision != Allow {
		t.Errorf("Decision = %q, want allow when no rule matches", v.Decision)
	}
}

func TestUnknownRoutesToOnError(t *testing.T) {
	p := mustLoad(t, "version: 1\non_error: block\n")
	v := Evaluate(effects.Effects{Unknown: true}, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q, want block from on_error", v.Decision)
	}
	if v.Rule != "on_error" {
		t.Errorf("Rule = %q, want on_error", v.Rule)
	}
}

func TestUnresolvedPathIsUnknown(t *testing.T) {
	p := mustLoad(t, "version: 1\non_error: ask\n")
	e := effects.Effects{Deletes: []paths.Path{{Raw: "${NOPE}", Resolved: false}}}
	if v := Evaluate(e, p); v.Decision != Ask {
		t.Errorf("Decision = %q, want ask: an unresolved path is not a safe path", v.Decision)
	}
}

func TestHostRulesApply(t *testing.T) {
	p := mustLoad(t, `
version: 1
hosts:
  - match: "*.ezweb.ro"
    ask: [write, exec]
`)
	e := effects.Effects{Remotes: []effects.Remote{{Host: "prod.ezweb.ro", Verb: effects.VerbExec}}}
	if v := Evaluate(e, p); v.Decision != Ask {
		t.Errorf("Decision = %q, want ask", v.Decision)
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/policy/ -run 'Blocks|LastMatch|MostSevere|Unmatched|Unknown|Unresolved|HostRules' -v
```

Expected: build failure — `undefined: Evaluate`, `undefined: Verdict`.

- [ ] **Step 3: Write the minimal implementation**

```bash
cd ~/blastradius && go get github.com/bmatcuk/doublestar/v4@v4.10.0
```

```go
// internal/policy/evaluate.go
package policy

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
)

// Verdict is a decision together with the rule that produced it. A verdict
// without provenance is a bug.
type Verdict struct {
	Decision Decision
	Reason   string
	Rule     string
	Radius   effects.Effects
}

// Evaluate matches a blast radius against a policy.
func Evaluate(e effects.Effects, p *Policy) Verdict {
	best := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched", Radius: e}

	consider := func(v Verdict) {
		if severity(v.Decision) > severity(best.Decision) {
			v.Radius = e
			best = v
		}
	}

	for _, pair := range pathPairs(e) {
		if !pair.path.Resolved {
			consider(Verdict{
				Decision: p.OnError,
				Rule:     "on_error",
				Reason:   "path could not be resolved: " + pair.path.Raw,
			})
			continue
		}
		consider(match(p.Paths, "paths", pair.path.Abs, pair.verb))
	}

	for _, r := range e.Remotes {
		consider(match(p.Hosts, "hosts", r.Host, r.Verb))
	}

	consider(evaluateGit(e, p))

	if e.Unknown {
		consider(Verdict{
			Decision: p.OnError,
			Rule:     "on_error",
			Reason:   "analysis could not complete",
		})
	}

	best.Radius = e
	return best
}

type pathVerb struct {
	path paths.Path
	verb effects.Verb
}

func pathPairs(e effects.Effects) []pathVerb {
	var out []pathVerb
	for _, group := range []struct {
		list []paths.Path
		verb effects.Verb
	}{
		{e.Deletes, effects.VerbDelete},
		{e.Truncates, effects.VerbTruncate},
		{e.Writes, effects.VerbWrite},
		{e.Reads, effects.VerbRead},
	} {
		for _, p := range group.list {
			out = append(out, pathVerb{path: p, verb: group.verb})
		}
	}
	return out
}

// match applies last-match-wins over ordered rules for one target and verb.
func match(rules []Rule, section, target string, verb effects.Verb) Verdict {
	out := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched"}
	for i, r := range rules {
		if !patternMatches(r.Match, target) {
			continue
		}
		d, ok := decisionFor(r, verb)
		if !ok {
			continue // this rule says nothing about this verb
		}
		reason := r.Reason
		if reason == "" {
			reason = fmt.Sprintf("%s %s on %s", d, verb, target)
		}
		out = Verdict{Decision: d, Rule: fmt.Sprintf("%s[%d]", section, i), Reason: reason}
	}
	return out
}

func decisionFor(r Rule, verb effects.Verb) (Decision, bool) {
	if containsVerb(r.Deny, verb) {
		return Block, true
	}
	if containsVerb(r.Ask, verb) {
		return Ask, true
	}
	if containsVerb(r.Allow, verb) {
		return Allow, true
	}
	return "", false
}

func containsVerb(list []effects.Verb, v effects.Verb) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// patternMatches supports doublestar globs. A leading ~ is not expanded here;
// callers resolve paths before evaluation, and init writes absolute patterns.
func patternMatches(pattern, target string) bool {
	ok, err := doublestar.Match(pattern, target)
	if err != nil {
		return false
	}
	return ok
}

// evaluateGit applies the git section to notes left by the git extractor.
func evaluateGit(e effects.Effects, p *Policy) Verdict {
	out := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched"}
	forcePushDenied := false
	for _, d := range p.Git.Deny {
		if d == "force_push" {
			forcePushDenied = true
		}
	}
	if !forcePushDenied {
		return out
	}
	var forced bool
	var branch string
	for _, n := range e.Notes {
		if n == "git:push --force" {
			forced = true
		}
		if strings.HasPrefix(n, "git:push:") {
			branch = strings.TrimPrefix(n, "git:push:")
		}
	}
	if !forced {
		return out
	}
	for _, b := range p.Git.ProtectedBranches {
		if b == branch {
			return Verdict{
				Decision: Block,
				Rule:     "git.deny",
				Reason:   "force push to protected branch " + branch,
			}
		}
	}
	return out
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./internal/policy/ -v
```

Expected: PASS for all Task 9 and Task 10 tests.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add go.mod go.sum internal/policy/
git commit -m "feat(policy): last-match-wins evaluation with rule provenance"
```

---

### Task 11: Engine wiring and the corpus harness

**Files:**
- Create: `internal/engine/engine.go`
- Create: `internal/engine/corpus_test.go`
- Create: `testdata/policies/prod.yaml`
- Create: `testdata/corpus/bypasses.yaml`

**Interfaces:**
- Consumes: `shell.Parse`, `paths.Context`, `effects.Extract`, `policy.Policy`, `policy.Evaluate`.
- Produces: `engine.Request{Command string; Ctx paths.Context; Policy *policy.Policy}`, `engine.Analyze(req Request) policy.Verdict`.

This task turns spec §8 into infrastructure: corpus cases are YAML, so a reported bypass becomes a one-line pull request rather than a Go patch.

- [ ] **Step 1: Write the failing test**

```go
// internal/engine/corpus_test.go
package engine

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

type corpusCase struct {
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
	Cwd     string `yaml:"cwd"`
	Policy  string `yaml:"policy"`
	Expect  struct {
		Verdict string   `yaml:"verdict"`
		Deletes []string `yaml:"deletes"`
	} `yaml:"expect"`
}

func TestCorpus(t *testing.T) {
	files, err := filepath.Glob("../../testdata/corpus/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files found: %v", err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var cases []corpusCase
		if err := yaml.Unmarshal(data, &cases); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, c := range cases {
			t.Run(c.Name, func(t *testing.T) {
				polData, err := os.ReadFile(filepath.Join("../../", c.Policy))
				if err != nil {
					t.Fatalf("read policy: %v", err)
				}
				pol, err := policy.Load(polData)
				if err != nil {
					t.Fatalf("load policy: %v", err)
				}
				v := Analyze(Request{
					Command: c.Command,
					Ctx: paths.Context{
						Cwd:  c.Cwd,
						Home: "/home/u",
						Env:  map[string]string{"HOME": "/home/u"},
					},
					Policy: pol,
				})
				if string(v.Decision) != c.Expect.Verdict {
					t.Errorf("verdict = %q, want %q (rule %s: %s)",
						v.Decision, c.Expect.Verdict, v.Rule, v.Reason)
				}
				for _, want := range c.Expect.Deletes {
					if !deletesInclude(v, want) {
						t.Errorf("deletes = %v, want to include %q", absList(v), want)
					}
				}
			})
		}
	}
}

func deletesInclude(v policy.Verdict, want string) bool {
	for _, p := range v.Radius.Deletes {
		if p.Abs == want {
			return true
		}
	}
	return false
}

func absList(v policy.Verdict) []string {
	var out []string
	for _, p := range v.Radius.Deletes {
		out = append(out, p.Abs)
	}
	return out
}
```

```yaml
# testdata/policies/prod.yaml
version: 1
on_error: ask
paths:
  - match: "/home/u/prod/**"
    deny: [write, delete, truncate]
    reason: "Production source; the live server is read-only by policy."
  - match: "/home/u/**/*.db"
    deny: [delete, truncate]
    reason: "Databases are add-only here."
  - match: "/home/u/**/node_modules/**"
    allow: [delete, truncate]
hosts:
  - match: "86.123.173.94"
    deny: [write, exec]
    reason: "Production server, read-only."
git:
  protected_branches: [main]
  deny: [force_push]
```

```yaml
# testdata/corpus/bypasses.yaml
# The six bypasses catalogued in spec §1, each of which a regex denylist misses.

- name: split_flags_and_variable
  command: 'rm -r -f "$HOME/prod"'
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block
    deletes: ["/home/u/prod"]

- name: find_delete
  command: "find . -name '*.db' -delete"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block

- name: git_clean
  command: "git clean -xfd"
  cwd: /home/u/prod
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block

- name: truncating_redirect
  command: ": > orders.db"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block

- name: nested_bash_c
  command: "bash -c 'rm -rf ~/prod'"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block
    deletes: ["/home/u/prod"]

- name: xargs_rm
  command: "xargs rm < filelist"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: ask

# Routine work must stay allowed, or the tool gets uninstalled within a week.

- name: node_modules_is_fair_game
  command: "rm -rf node_modules"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: allow

- name: reading_production_is_allowed
  command: "cat /home/u/prod/README.md"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: ask

- name: remote_exec_on_production_host
  command: "ssh deploy@86.123.173.94 'systemctl restart app'"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block
```

The `reading_production_is_allowed` case expects `ask`, not `allow`, because `cat` is not a registered command and therefore reports `Unknown`. That is the honest result under this policy, and the case name documents the current limit rather than hiding it. Registering read-only commands is Plan 2 work.

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./internal/engine/ -v
```

Expected: build failure — `undefined: Analyze`, `undefined: Request`.

- [ ] **Step 3: Write the minimal implementation**

```go
// internal/engine/engine.go

// Package engine wires the analysis pipeline into a single pure function.
package engine

import (
	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
	"github.com/cobrabm12/blastradius/internal/shell"
)

// Request is everything Analyze needs. It reads nothing else.
type Request struct {
	Command string
	Ctx     paths.Context
	Policy  *policy.Policy
}

// Analyze computes the blast radius of a command and evaluates it against the
// policy. A parse failure is reported as Unknown, never as permission.
func Analyze(req Request) (v policy.Verdict) {
	defer func() {
		// A panic in analysis must never become an allow.
		if r := recover(); r != nil {
			v = policy.Verdict{
				Decision: req.Policy.OnError,
				Rule:     "on_error",
				Reason:   "analysis panicked",
				Radius:   effects.Effects{Unknown: true},
			}
		}
	}()

	invs, err := shell.Parse(req.Command)
	if err != nil {
		return policy.Verdict{
			Decision: req.Policy.OnError,
			Rule:     "on_error",
			Reason:   "command could not be parsed: " + err.Error(),
			Radius:   effects.Effects{Unknown: true},
		}
	}

	var radius effects.Effects
	for _, inv := range invs {
		radius.Merge(effects.Extract(inv, req.Ctx))
	}
	return policy.Evaluate(radius, req.Policy)
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./... -v
```

Expected: PASS for every package, including all nine corpus cases.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add internal/engine/ testdata/
git commit -m "feat(engine): wire the pipeline and add the declarative corpus harness"
```

---

### Task 12: The `explain` command

**Files:**
- Create: `cmd/blastradius/main.go`
- Create: `cmd/blastradius/explain.go`
- Test: `cmd/blastradius/explain_test.go`

**Interfaces:**
- Consumes: `engine.Analyze`, `engine.Request`, `policy.Load`, `paths.Context`.
- Produces: the `blastradius explain "<command>"` CLI; `renderVerdict(v policy.Verdict, w io.Writer)`.

`explain` is the demonstration surface from spec §9 — it shows the analysis a denylist cannot perform, on a command a denylist visibly misses.

- [ ] **Step 1: Write the failing test**

```go
// cmd/blastradius/explain_test.go
package main

import (
	"strings"
	"testing"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

func TestRenderVerdictShowsRadiusAndProvenance(t *testing.T) {
	v := policy.Verdict{
		Decision: policy.Block,
		Reason:   "Production data.",
		Rule:     "paths[0]",
		Radius: effects.Effects{
			Deletes:      []paths.Path{{Raw: "$HOME/prod", Abs: "/home/u/prod", Resolved: true}},
			Irreversible: true,
		},
	}
	var sb strings.Builder
	renderVerdict(v, &sb)
	out := sb.String()

	for _, want := range []string{"BLOCK", "/home/u/prod", "delete", "paths[0]", "Production data."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderVerdictMarksUnresolvedPaths(t *testing.T) {
	v := policy.Verdict{
		Decision: policy.Ask,
		Reason:   "path could not be resolved: ${NOPE}",
		Rule:     "on_error",
		Radius: effects.Effects{
			Deletes: []paths.Path{{Raw: "${NOPE}", Resolved: false}},
		},
	}
	var sb strings.Builder
	renderVerdict(v, &sb)
	if !strings.Contains(sb.String(), "unresolved") {
		t.Errorf("output does not mark the unresolved path:\n%s", sb.String())
	}
}
```

- [ ] **Step 2: Run the test and verify it fails**

```bash
cd ~/blastradius && go test ./cmd/blastradius/ -v
```

Expected: build failure — `undefined: renderVerdict`.

- [ ] **Step 3: Write the minimal implementation**

```go
// cmd/blastradius/explain.go
package main

import (
	"fmt"
	"io"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

// renderVerdict writes a human-readable account of what a command touches and
// which rule decided its fate.
func renderVerdict(v policy.Verdict, w io.Writer) {
	fmt.Fprintf(w, "%s  (%s)\n", decisionLabel(v.Decision), v.Rule)
	fmt.Fprintf(w, "  reason: %s\n", v.Reason)

	fmt.Fprintln(w, "\n  blast radius:")
	printed := false
	for _, group := range []struct {
		verb effects.Verb
		list []paths.Path
	}{
		{effects.VerbDelete, v.Radius.Deletes},
		{effects.VerbTruncate, v.Radius.Truncates},
		{effects.VerbWrite, v.Radius.Writes},
		{effects.VerbRead, v.Radius.Reads},
	} {
		for _, p := range group.list {
			printed = true
			if p.Resolved {
				fmt.Fprintf(w, "    %-9s %s\n", group.verb, p.Abs)
			} else {
				fmt.Fprintf(w, "    %-9s %s  [unresolved]\n", group.verb, p.Raw)
			}
		}
	}
	for _, r := range v.Radius.Remotes {
		printed = true
		fmt.Fprintf(w, "    %-9s %s  [remote]\n", r.Verb, r.Host)
	}
	if !printed {
		fmt.Fprintln(w, "    (nothing detected)")
	}

	if v.Radius.Irreversible {
		fmt.Fprintln(w, "\n  irreversible: yes")
	}
	if v.Radius.Unknown {
		fmt.Fprintln(w, "  analysis incomplete: yes")
	}
	for _, n := range v.Radius.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

func decisionLabel(d policy.Decision) string {
	switch d {
	case policy.Block:
		return "BLOCK"
	case policy.Ask:
		return "ASK"
	default:
		return "ALLOW"
	}
}
```

```go
// cmd/blastradius/main.go

// Command blastradius computes what a shell command destroys and whether policy
// permits it.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cobrabm12/blastradius/internal/engine"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "explain" {
		fmt.Fprintln(os.Stderr, "usage: blastradius explain \"<command>\"")
		os.Exit(2)
	}
	if err := runExplain(os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "blastradius:", err)
		os.Exit(1)
	}
}

func runExplain(command string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	pol, err := loadPolicy(cwd)
	if err != nil {
		return err
	}

	v := engine.Analyze(engine.Request{
		Command: command,
		Ctx:     paths.Context{Cwd: cwd, Home: home, Env: environ()},
		Policy:  pol,
	})
	renderVerdict(v, os.Stdout)
	if v.Decision == policy.Block {
		os.Exit(1)
	}
	return nil
}

// loadPolicy reads guard.yaml from the working directory, falling back to a
// permissive default so that `explain` works before `init` has been run.
func loadPolicy(cwd string) (*policy.Policy, error) {
	data, err := os.ReadFile(filepath.Join(cwd, "guard.yaml"))
	if os.IsNotExist(err) {
		return policy.Load([]byte("version: 1\non_error: ask\n"))
	}
	if err != nil {
		return nil, err
	}
	return policy.Load(data)
}

func environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				env[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return env
}
```

- [ ] **Step 4: Run the test and verify it passes**

```bash
cd ~/blastradius && go test ./... && go build ./cmd/blastradius && ./blastradius explain 'rm -r -f "$HOME/prod"'
```

Expected: all tests PASS, the binary builds, and the command prints a blast radius naming `/home/u/prod` under `delete`.

- [ ] **Step 5: Commit**

```bash
cd ~/blastradius
git add cmd/
git commit -m "feat(cmd): blastradius explain renders the computed blast radius"
```

---

## After this plan

Plan 2 covers the enforcement layer from spec §6: the Claude Code `PreToolUse` adapter, shim mode with `allow-once`, `install`, `doctor`, `init`, and the JSONL audit trail. It is written after this plan is executed, so that the adapter contracts are designed against a real `Effects` shape rather than a predicted one.

Repository hygiene deliberately left for the release task in Plan 2: `README.md`, `LICENSE` (Apache-2.0), `CONTRIBUTING.md` describing the corpus workflow, CI running `go test ./...` on push, and goreleaser configuration.
