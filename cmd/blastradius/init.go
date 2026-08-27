package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// runInit writes a starting policy inferred from the repository.
//
// The generated file is meant to be read and edited, not accepted blindly, so
// every rule carries the reason it was inferred.
func runInit(args []string) error {
	force := false
	for _, a := range args {
		if a == "--force" {
			force = true
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	target := filepath.Join(cwd, policyFileName)
	if _, err := os.Stat(target); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", policyFileName)
	}

	content := generatePolicy(cwd)
	if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n\nReview it before relying on it — the rules below were inferred,\nnot chosen by you.\n", target)
	return nil
}

func generatePolicy(cwd string) string {
	var b strings.Builder
	b.WriteString("# blastradius policy\n")
	b.WriteString("# Rules are ordered; for any target and verb, the LAST matching rule wins.\n")
	b.WriteString("# Verbs: read, write, delete, truncate (paths) — read, write, exec (hosts).\n\n")
	b.WriteString("version: 1\n\n")
	b.WriteString("# What to do when analysis cannot complete. Never silently allow.\n")
	b.WriteString("on_error: ask\n\n")
	b.WriteString("paths:\n")

	if secrets := findSecretFiles(cwd); len(secrets) > 0 {
		b.WriteString("  # Credential files found in this repository.\n")
		b.WriteString("  - match: \"" + cwd + "/**/.env*\"\n")
		b.WriteString("    deny: [read, write, delete]\n")
		b.WriteString("    reason: \"Credentials. Not for agents.\"\n\n")
	}

	if dbs := findDatabaseFiles(cwd); len(dbs) > 0 {
		b.WriteString("  # Database files found in this repository.\n")
		b.WriteString("  - match: \"" + cwd + "/**/*.{db,sqlite,sqlite3}\"\n")
		b.WriteString("    deny: [delete, truncate]\n")
		b.WriteString("    reason: \"Back up before any destructive change.\"\n\n")
	}

	b.WriteString("  # Version control metadata: losing it loses the project's history.\n")
	b.WriteString("  - match: \"" + cwd + "/.git/**\"\n")
	b.WriteString("    deny: [write, delete, truncate]\n")
	b.WriteString("    reason: \"Repository metadata.\"\n\n")

	b.WriteString("  # Build output and dependencies are disposable; say so explicitly,\n")
	b.WriteString("  # or the guardrail will nag about routine work and get uninstalled.\n")
	b.WriteString("  - match: \"" + cwd + "/**/node_modules/**\"\n")
	b.WriteString("    allow: [delete, truncate, write]\n")
	b.WriteString("  - match: \"" + cwd + "/{dist,build,target,.next,out}/**\"\n")
	b.WriteString("    allow: [delete, truncate, write]\n")

	b.WriteString("\nhosts:\n")
	remotes := gitRemoteHosts(cwd)
	if len(remotes) == 0 {
		b.WriteString("  # No remote hosts detected. Add production servers here, for example:\n")
		b.WriteString("  #  - match: \"prod.example.com\"\n")
		b.WriteString("  #    deny: [write, exec]\n")
		b.WriteString("  #    reason: \"Production server, read-only.\"\n")
	}
	for _, h := range remotes {
		b.WriteString("  - match: \"" + h + "\"\n")
		b.WriteString("    ask: [write, exec]\n")
		b.WriteString("    reason: \"Git remote for this repository.\"\n")
	}

	b.WriteString("\ngit:\n")
	branches := defaultBranches(cwd)
	b.WriteString("  protected_branches: [" + strings.Join(branches, ", ") + "]\n")
	b.WriteString("  deny: [force_push]\n")

	return b.String()
}

func findSecretFiles(cwd string) []string {
	return globShallow(cwd, []string{".env", ".env.local", ".env.production", ".env.development"})
}

func findDatabaseFiles(cwd string) []string {
	var found []string
	for _, ext := range []string{"*.db", "*.sqlite", "*.sqlite3"} {
		matches, _ := filepath.Glob(filepath.Join(cwd, ext))
		found = append(found, matches...)
	}
	return found
}

func globShallow(cwd string, names []string) []string {
	var found []string
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(cwd, n)); err == nil {
			found = append(found, n)
		}
	}
	return found
}

// gitRemoteHosts returns the hosts this repository pushes to.
func gitRemoteHosts(cwd string) []string {
	out, err := exec.Command("git", "-C", cwd, "remote", "-v").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if h := hostFromGitURL(fields[1]); h != "" && !isForge(h) {
			seen[h] = true
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// isForge reports whether a host is a code-hosting service rather than a
// deployment target. Pushing code to GitHub is not the risk this tool guards.
func isForge(host string) bool {
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht":
		return true
	}
	return false
}

func hostFromGitURL(url string) string {
	if i := strings.Index(url, "://"); i >= 0 {
		url = url[i+3:]
	}
	if i := strings.Index(url, "@"); i >= 0 {
		url = url[i+1:]
	}
	for _, sep := range []string{":", "/"} {
		if i := strings.Index(url, sep); i >= 0 {
			url = url[:i]
		}
	}
	return url
}

func defaultBranches(cwd string) []string {
	out, err := exec.Command("git", "-C", cwd, "symbolic-ref", "--short", "HEAD").Output()
	branch := strings.TrimSpace(string(out))
	if err != nil || branch == "" {
		return []string{"main", "master"}
	}
	if branch == "main" || branch == "master" {
		return []string{"main", "master"}
	}
	return []string{"main", "master", branch}
}
