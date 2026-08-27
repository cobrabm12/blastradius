# Contributing

## Found a way past it?

That is the most valuable contribution this project takes.

The fastest path is a pull request adding a failing case to `testdata/corpus/`.
Cases are declarative YAML, so no Go is required to report a bypass precisely:

```yaml
- name: descriptive_name
  command: "the command that got through"
  cwd: /home/u/app
  policy: testdata/policies/prod.yaml
  expect:
    verdict: block
```

Run `go test ./...` to watch it fail, then either fix it yourself or open the PR
with the failing case alone. A well-specified failing test is a complete
contribution here.

## False positives count too

A guardrail that blocks routine work gets uninstalled, and a tool nobody keeps
installed protects nothing. If blastradius blocked something it should not have,
that is a bug of the same severity as a missed bypass. Add the case to
`testdata/corpus/routine.yaml` with `verdict: allow`.

## Adding support for a command

Effects extraction is a registry, not a pile of special cases. Adding a command
means one function plus corpus cases:

1. Write the extractor in the appropriate file under `internal/effects/`
   (`fs.go` for filesystem commands, `remote.go` for anything that reaches a
   host, or a new file for a large surface such as `git`).
2. Register it in that file's `init`.
3. Add cases to `testdata/corpus/` — at least one that must block and one that
   must stay allowed.

An extractor must never guess. If it cannot determine what a command does, set
`Unknown: true` and let the policy's `on_error` decide. Silently returning empty
effects reports the command as harmless, which is the one outcome this project
exists to prevent.

## Design rules

These are not style preferences; breaking them breaks the guarantees:

- **No language model participates in a verdict.** Determinism is the product.
- **Incomplete analysis is never `allow`.** Unresolved paths, unregistered
  commands, parse failures, panics, and timeouts all route to `on_error`.
- **Every verdict names the rule that produced it.** A verdict without
  provenance is a bug.
- **The analysis pipeline is pure.** `internal/` reads no files, opens no
  sockets, and consults no clock. That is what makes the corpus possible.

## Running the tests

```bash
go test ./...          # everything, including the corpus
go vet ./...
gofmt -l .             # must print nothing
```

## Releasing

Tagging `vX.Y.Z` triggers goreleaser, which builds the binaries and creates the
GitHub release. The npm wrapper is published separately and must be kept in
step, because `install.js` downloads the release matching its own version:

```bash
cp README.md LICENSE npm/          # the npm page renders the package README
npm version --no-git-tag-version X.Y.Z --prefix npm
cd npm && npm publish
```

Publish npm only after the GitHub release exists, or `postinstall` will fetch a
URL that is not there yet.

## Commits

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`), present tense. Explain
why in the body when the what is not self-evident.
