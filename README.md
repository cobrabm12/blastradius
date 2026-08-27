# blastradius

**Deterministic guardrails for coding agents.** blastradius parses the shell command an agent is about to run, works out which files it deletes and which hosts it touches, and checks that against a policy you write. No regular expressions. No language model in the decision.

```console
$ blastradius explain 'find . -name "*.db" -delete'
BLOCK  (paths[1])
  reason: Databases are add-only here; back up before any destructive change.

  blast radius:
    delete    /home/u/app/*.db  [glob]

  irreversible: yes
```

---

## Why this exists

Coding agents run shell commands on developer machines, and increasingly on machines that also host production services. The safety layer in common use is a list of regular expressions matched against the command string.

Regex denylists fail in both directions.

**They miss the dangerous.** A denylist that catches `rm -rf /` catches none of these:

| Command | Why the regex misses it |
|---|---|
| `rm -r -f "$HOME/prod"` | flags are split, target is a variable |
| `find . -name '*.db' -delete` | deletes without invoking `rm` |
| `git clean -xfd` | deletes without invoking `rm` |
| `: > production.db` | truncates through a redirection |
| `bash -c 'rm -rf ~/data'` | one level of indirection |
| `xargs rm < filelist` | argv arrives on stdin |

**They block the harmless.** Any pattern broad enough to catch the list above also blocks `rm -rf node_modules` — and a guardrail that cries wolf gets uninstalled within a week.

blastradius asks a different question:

> Denylists ask: *does this command look dangerous?*
> blastradius asks: **what does this command destroy, and am I allowed to destroy that?**

Every command in the table above is a test case in [`testdata/corpus/`](testdata/corpus/), alongside the routine work that must keep flowing.

## How it works

```
command → shell AST → resolved paths & hosts → effects → policy → verdict
```

1. **Parse.** The command becomes an abstract syntax tree via [`mvdan.cc/sh`](https://github.com/mvdan/sh), the parser behind `shfmt`. Combined flags are split, `--` is honoured, redirections are read, and analysis descends into `bash -c`, `sudo`, `env`, `xargs`, and `find -exec`.
2. **Resolve.** Each word becomes an absolute path: tildes, `${VARS}`, brace expansion, `..` normalization. What cannot be resolved is *marked* unresolved, never assumed safe.
3. **Extract effects.** A registry maps each command to what it does — deletes, writes, truncations, reads, remote endpoints, and whether any of it is irreversible. A command with no registered extractor yields `unknown`.
4. **Evaluate.** Effects are matched against ordered rules. For any target and verb, the last matching rule wins — the gitignore model. Across the whole radius, the most severe decision wins.

The result is a verdict of `allow`, `ask`, or `block`, always naming the rule that produced it.

## Install

```bash
# Go
go install github.com/cobrabm12/blastradius/cmd/blastradius@latest

# npm (downloads the platform binary)
npx blastradius init
```

Or download a binary from [Releases](https://github.com/cobrabm12/blastradius/releases).

## Use

```bash
cd your-project
blastradius init        # generate guard.yaml from what's in the repo
blastradius install     # wire it into Claude Code's PreToolUse hook
blastradius doctor      # what is protected, and what is not
```

Then try it on something:

```bash
blastradius explain 'rm -rf $HOME/prod'
```

## Policy

One file, `guard.yaml`, in the repository root or `~/.config/blastradius/`.

```yaml
version: 1

on_error: ask          # when analysis cannot complete: block | ask | allow

paths:
  - match: "~/prod/**"
    deny: [write, delete, truncate]
    reason: "Production source; the live server is read-only by policy."

  - match: "**/*.db"
    deny: [delete, truncate]
    reason: "Databases are add-only here."

  - match: "**/.env*"
    deny: [read, write, delete]
    reason: "Credentials. Not for agents."

  - match: "**/node_modules/**"
    allow: [delete, truncate]      # exceptions keep the tool credible

hosts:
  - match: "203.0.113.10"
    deny: [write, exec]
    reason: "Production server, read-only."

  - match: "*.staging.example.com"
    ask: [write, exec]

git:
  protected_branches: [main, master]
  deny: [force_push]
```

**Verbs** are a closed vocabulary: `read`, `write`, `delete`, `truncate` for paths; `read`, `write`, `exec` for hosts.

**Rule order matters.** Rules are evaluated in order and the last one to name a given verb decides, so exceptions go below the rules they carve into. Repository rules are evaluated before machine rules, which means a project can never relax a protection the machine's owner set.

## Enforcement modes

| Mode | How | Covers | Gap |
|---|---|---|---|
| **Native** | the agent's own pre-execution hook | every tool call, including file writes that never reach a shell | only where the agent provides a hook |
| **Shim** | wrapper executables early on `PATH` | any agent that runs commands in a shell | bypassable by absolute path (`/bin/rm`); blind to edit-tool writes |

**Claude Code** supports native mode today, through `PreToolUse` over `Bash`, `Write`, and `Edit`.

**Codex, opencode, cline, and Gemini CLI** expose no pre-execution hook, so they get shim mode: `blastradius install --shim`. Codex's own `guardian_approval` is an LLM subagent reviewing approvals — a complement to this tool rather than a competitor, since it exercises judgment where blastradius applies rules.

Because a shim has no channel back to an approval prompt, `ask` degrades to `block` there, with an escape hatch:

```bash
blastradius allow-once 'rsync -av ./dist/ deploy@staging:/var/www/'
```

That grant is single-use, scoped to the hash of that exact command, and expires in five minutes.

`blastradius doctor` prints the active mode per agent and names the residual gap for each. It is meant to be read.

## What this is not

- **Not a sandbox.** It is a filter at the tool boundary. Run it alongside a sandbox, not instead of one.
- **Not a defense against an adversarial agent.** It stops accidents and misjudgements, which is what actually happens. An agent determined to evade it can.
- **Not a secret scanner or a linter.** It reasons about what commands do, not about the code being written.
- **Not powered by a model.** Verdicts are deterministic, reproducible, reviewable in a diff, and testable in CI. A guardrail that can hallucinate is a guardrail you cannot reason about.

Every one of these limits is enforced by the design, not merely documented.

## Failure behavior

Incomplete analysis is never silent approval.

- An unresolvable variable, an unregistered command, or a syntax error sets `unknown`, which routes to the policy's `on_error` (default `ask`).
- Analysis has a hard 200 ms budget; exceeding it routes to `on_error`.
- A panic in analysis is recovered and routed to `on_error`. A crash never becomes a permission.

## Contributing

**Found a way past it?** That is the most valuable contribution this project takes. Open an issue with the command, or go straight to a pull request adding a case to [`testdata/corpus/`](testdata/corpus/) — cases are declarative YAML, so a bypass report is a few lines:

```yaml
- name: your_bypass
  command: "the command that got through"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block
```

Adding support for a new command is a registry entry plus corpus cases. See [CONTRIBUTING.md](CONTRIBUTING.md).

False positives are treated as bugs of the same severity as missed bypasses. A guardrail nobody keeps installed protects nothing.

## Documentation

- [Design specification](docs/superpowers/specs/2026-08-27-blastradius-design.md) — the architecture and the reasoning behind it
- [`testdata/corpus/`](testdata/corpus/) — every behavior, as executable documentation

## License

Apache-2.0. See [LICENSE](LICENSE).
