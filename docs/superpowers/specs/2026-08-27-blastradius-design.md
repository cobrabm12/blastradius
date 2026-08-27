# blastradius — Design Specification

**Date:** 2026-08-27
**Status:** Approved for planning
**Language:** Go (core), thin npm wrapper for distribution

---

## 1. Problem

Coding agents run shell commands on developer machines, and increasingly on machines
that also host production services. The existing safety layer is a collection of
regular expressions matched against the raw command string — published as hook
snippets, blog posts, and small plugin repos.

Regex denylists fail in two directions at once.

**They miss the dangerous.** A denylist that matches `rm -rf /` does not match any of:

```
rm -r -f "$HOME/project"        # split flags, variable expansion
find . -name '*.db' -delete     # deletion without `rm`
git clean -xfd                  # deletion without `rm`, again
: > production.sqlite           # truncation via redirection
bash -c 'rm -rf ~/data'         # one level of indirection
xargs rm < filelist             # argv arrives from stdin
```

**They block the harmless.** Any pattern broad enough to catch the above also blocks
`rm -rf node_modules`, and a guardrail that cries wolf gets disabled within a week.

The second limitation is scope: essentially all of this tooling targets Claude Code's
`PreToolUse` hook. Codex, opencode, cline, and Gemini CLI have no equivalent — Codex
0.149 ships `guardian_approval`, an LLM subagent that reviews approvals, which is a
different thing with different failure modes (see §11).

## 2. What blastradius does

blastradius answers a different question than the denylists do.

> Denylists ask: *does this command look dangerous?*
> blastradius asks: **what does this command destroy, and am I allowed to destroy that?**

It parses the shell command into an abstract syntax tree, resolves the concrete
filesystem paths and remote hosts each invocation touches, computes the resulting
**blast radius**, and evaluates that radius against a declarative policy file. The
decision is deterministic: same command, same policy, same cwd — same verdict, every
time.

### Non-goals

blastradius is a deterministic filter at the tool boundary. It is explicitly **not**:

- a sandbox, a container, or a substitute for either;
- a defense against an adversarial agent deliberately evading it;
- a secret scanner, a linter, or a static analyzer for the code being written;
- anything that consults a language model to reach a verdict (see §7).

These limits are stated in the README, not buried. A guardrail that oversells itself
is worse than none, because it buys unearned confidence.

## 3. Core concepts

**Invocation** — one concrete command with resolved argv, cwd, and redirections. A
single shell string can yield many invocations: pipelines, `&&` chains, subshells,
`bash -c`, `xargs`, `find -exec`.

**Effects** — what one invocation does to the world:

```go
type Effects struct {
    Deletes       []Path    // paths removed
    Writes        []Path    // paths created, overwritten, or truncated
    Reads         []Path
    RemoteTargets []Remote  // ssh/rsync/scp/docker -H/psql/mysql endpoints
    Irreversible  bool      // no undo exists (DROP TABLE, dd, force-push)
    Unknown       bool      // analysis could not complete — see §7
}
```

**Blast radius** — the union of the effects of every invocation in a command.

**Verdict** — `allow`, `ask`, or `block`, always accompanied by the specific policy
rule that produced it. A verdict without a citable reason is a bug.

## 4. Policy file

One file, `guard.yaml`, at the repo root or in `~/.config/blastradius/`.

**Verbs.** Path rules act on `read`, `write`, `delete`, `truncate`. Host rules act on
`read`, `write`, `exec`. There is no other vocabulary.

**Resolution.** Rules are ordered, and for any (target, verb) pair **the last matching
rule that names that verb decides** — the gitignore model, including its negations.
A rule states `deny:`, `ask:`, or `allow:`; `allow:` exists to carve exceptions out of
a broader earlier rule.

**Merge order.** Repository rules are evaluated first, user/machine rules last.
Combined with last-match-wins, this makes machine-wide policy authoritative: a
repository cannot relax a protection the machine's owner set.

```yaml
version: 1

on_error: ask          # verdict when analysis is incomplete: block | ask | allow

paths:
  - match: "~/restart-society-web/**"
    deny: [write, delete, truncate]
    reason: "Production source; live server is read-only by policy."

  - match: "**/*.db"
    deny: [delete, truncate]
    reason: "Databases are add-only here; back up before any destructive change."

  - match: "**/.env*"
    deny: [read, write, delete]
    reason: "Credentials. Not for agents."

  - match: "**/node_modules/**"
    allow: [delete, truncate]    # exception: keeps the tool credible on routine work

hosts:
  - match: "86.123.173.94"
    deny: [write, exec]
    reason: "Production server, read-only."

  - match: "*.ezweb.ro"
    ask: [write, exec]

git:
  protected_branches: [main, master]
  deny: [force_push, hard_reset_with_dirty_tree]

audit:
  path: ~/.local/state/blastradius/audit.jsonl
```

`blastradius init` generates a starting policy by inspecting the repository: git
remotes and default branch, `.env*` files, `docker-compose.yml` service volumes,
Prisma/Django/Rails database URLs, and any path listed in a `CLAUDE.md` or `AGENTS.md`
as protected.

## 5. Architecture

Six packages, each with one responsibility, each testable without the others.

| Package | Responsibility | Depends on |
|---|---|---|
| `internal/shell` | Bash source → `[]Invocation`. Descends into `bash -c`, `xargs`, `find -exec`, `sudo`/`env` prefixes, pipelines, subshells, redirections. | `mvdan.cc/sh/v3/syntax` |
| `internal/paths` | Resolves `~`, `$VAR`, brace expansion, globs, relative→absolute against cwd. Marks what it cannot resolve. | — |
| `internal/effects` | Per-command effect extraction via a registry: `rm`, `mv`, `cp`, `dd`, `truncate`, `tee`, `find`, `git`, `docker`, `psql`, `mysql`, `ssh`, `rsync`, `scp`, `pm2`, `systemctl`, `chmod`, `chown`. Unregistered command ⇒ `Unknown`. | `paths` |
| `internal/policy` | Loads and validates `guard.yaml`, matches effects against rules, returns `Verdict` + rule provenance. | `effects` |
| `internal/adapters` | Translates each agent's protocol to and from a `Verdict`. | `policy` |
| `internal/audit` | Append-only JSONL: command, computed effects, verdict, deciding rule, timestamp. | — |

**Data flow**

```
agent → adapter (decode) → shell → paths → effects → policy → Verdict
                                                                 ├→ adapter (encode) → agent
                                                                 └→ audit
```

One direction, no shared state, no I/O outside the adapter and audit boundaries. The
whole pipeline is a pure function of (command, cwd, env snapshot, policy) — which is
what makes the test corpus in §8 possible.

### Effect registry

The registry is the part that grows forever, so it is data-shaped rather than
code-shaped: each entry declares how to read a command's flags and which arguments
become which effects. Adding `terraform` or `kubectl` support is a table entry plus
test cases, not a new code path. An unregistered command yields `Unknown` rather than
an empty `Effects` — absence of knowledge is never evidence of safety.

## 6. Enforcement modes

Because agents differ in what they expose, blastradius supports two modes and reports
which one is active.

**Native mode** (preferred). The agent's own pre-execution hook calls
`blastradius check --agent=<name>` with the pending tool call on stdin.

Claude Code, today: a `PreToolUse` hook covering `Bash`, `Write`, and `Edit`. The hook
receives `{cwd, tool_name, tool_input, ...}` on stdin and responds with
`hookSpecificOutput.permissionDecision` of `allow` / `deny` / `ask` plus
`permissionDecisionReason`. Native mode sees every tool call, including file writes
that never pass through a shell.

**Shim mode** (fallback, agent-agnostic). `blastradius install --shim` places wrapper
executables for high-risk binaries early on the agent's `PATH`. Each shim forwards its
real argv to `blastradius check`, then `exec`s the real binary if the verdict allows.

Shim mode works today with Codex, opencode, cline, and anything else that runs
commands in a shell, at a cost stated plainly in the docs: it is bypassable by
absolute path (`/bin/rm`), and it cannot see file writes performed through an agent's
native edit tool. It is a meaningful reduction in accident surface, not a security
boundary.

**`ask` in shim mode.** A shim has no channel back to the agent's approval UI, so an
`ask` verdict cannot be answered where it arises. In shim mode `ask` therefore
degrades to `block`, and the message names the escape hatch: the human runs
`blastradius allow-once "<command>"`, which writes a single-use, command-hash-scoped,
five-minute grant to the state directory. Native mode keeps `ask` as `ask`, because
there the agent can surface the prompt properly. `doctor` reports this difference
per agent rather than leaving it to be discovered.

`blastradius doctor` reports the active mode per detected agent and names the residual
gap for each. Native adapters are added as agents ship the hooks to support them.

## 7. Failure behavior

The rule that everything else follows from: **incomplete analysis is never silent
approval.**

- An unresolvable variable, an unregistered command, or a syntax error the parser
  cannot handle sets `Unknown`, and `Unknown` routes to the policy's `on_error`
  (default `ask`).
- A hard 200 ms budget covers the whole pipeline. Exceeding it routes to `on_error`.
- A top-level `recover()` converts any panic to `Unknown`. A crash must never become
  a permission.
- No language model participates in any verdict. Determinism is the product: verdicts
  are reproducible, diffable in code review, and testable in CI. A guardrail that can
  hallucinate is a guardrail you cannot reason about.

## 8. Testing

The test corpus is also the contributor pipeline.

Cases are declarative YAML in `testdata/`, not Go code:

```yaml
- command: "find . -name '*.db' -delete"
  cwd: /home/u/app
  policy: testdata/policies/db-protected.yaml
  expect:
    verdict: block
    deletes: ["/home/u/app/**/*.db"]
    rule: "paths[1]"
```

Consequences of this shape:

- Every reported bypass converts into a one-line pull request containing a failing
  case. Someone who breaks the tool has an obvious, low-friction path to improving it.
- The corpus doubles as executable documentation of exactly what is and is not caught.
- `internal/shell` is additionally fuzzed against the parser, since malformed input
  reaching a guardrail is the expected case, not the exceptional one.

Target at v1: 200+ corpus cases, with the known-bypass catalog from §1 as the seed.

## 9. CLI surface

| Command | Purpose |
|---|---|
| `blastradius init` | Generate `guard.yaml` from repository inspection |
| `blastradius check --agent=<name>` | Hook entrypoint; tool call on stdin, verdict on stdout |
| `blastradius explain "<command>"` | Print the computed blast radius and verdict for a command |
| `blastradius install [--shim]` | Wire the tool into detected agents |
| `blastradius doctor` | Report active enforcement mode and residual gaps per agent |
| `blastradius allow-once "<cmd>"` | Grant a single-use, five-minute exception (shim mode's answer to `ask`) |
| `blastradius log` | Read the audit trail |

`explain` is the demonstration surface — it renders the analysis that the denylists
cannot perform, on a command they visibly fail to catch.

## 10. Distribution

Go core, released as static binaries via GitHub Releases (goreleaser), plus a thin npm
package that downloads the platform binary on install — the esbuild model. This gives
`npx blastradius init` with no toolchain requirement for the Claude Code audience,
while the core keeps a ~3 ms cold start suitable for the pre-execution hot path.

A Homebrew tap and a Claude Code plugin marketplace entry follow v1.

## 11. Related work

- **Regex hook collections** (`cc-safe-setup`, assorted plugin repos): same problem
  domain, string matching instead of analysis, Claude Code only. blastradius should
  ship a comparison page demonstrating both false negatives and false positives on
  real commands, since that is the clearest statement of what it adds.
- **Codex `guardian_approval`**: an LLM subagent reviewing approvals. Complementary
  rather than competing — it exercises judgment where blastradius applies rules.
  blastradius covers the cases where a nondeterministic reviewer is exactly what you
  do not want.
- **Sandboxes** (`codex sandbox`, containers, seccomp): stronger boundaries, coarser
  granularity. A sandbox cannot express "this database is append-only" or "that host
  is read-only." Different layer; blastradius composes with them rather than replacing
  them.

## 12. v1 scope

**In:** shell AST analysis for Bash; `paths` and `effects` for the registry listed in
§5; `guard.yaml` policy with path, host, and git rules; Claude Code native adapter
(Bash/Write/Edit); shim mode covering Codex and other shell-based agents; `explain`,
`init`, `install`, `doctor`, `allow-once`, `log`; JSONL audit; 200+ corpus cases.

**Out:** adapters for opencode / cline / Gemini CLI; PowerShell and Windows path
semantics; network egress control; secret-content scanning; TUI or dashboard; CI
integration.

Each excluded item is deferred on the same principle — nothing ships until there are
users asking for it, and the first release is judged on whether its analysis is
correct, not on how many agents it names in the README.
