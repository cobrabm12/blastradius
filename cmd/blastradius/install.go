package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// shimmedCommands are the binaries a PATH shim wraps. The list is deliberately
// short: every shim costs a process launch on every call, so it covers the
// commands that actually destroy things.
var shimmedCommands = []string{
	"rm", "mv", "dd", "truncate", "shred", "find", "git", "rsync", "scp",
	"ssh", "psql", "mysql", "docker", "pm2", "chmod", "chown", "sed",
}

func runInstall(args []string) error {
	shim := false
	for _, a := range args {
		if a == "--shim" {
			shim = true
		}
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	self, err = filepath.Abs(self)
	if err != nil {
		return err
	}

	if shim {
		return installShims(self)
	}
	return installClaudeCodeHook(self)
}

// installClaudeCodeHook registers a PreToolUse hook in the user's settings.
//
// The existing settings are read, modified, and written back, so unrelated
// configuration survives. A hook already pointing at blastradius is replaced
// rather than duplicated.
func installClaudeCodeHook(self string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	settings := map[string]any{}
	if data, err := os.ReadFile(settingsPath); err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("%s is not valid JSON: %w", settingsPath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	entry := map[string]any{
		"matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": self + " check --agent=claude-code",
		}},
	}

	existing, _ := hooks["PreToolUse"].([]any)
	kept := make([]any, 0, len(existing)+1)
	for _, e := range existing {
		if !mentionsBlastradius(e) {
			kept = append(kept, e)
		}
	}
	hooks["PreToolUse"] = append(kept, entry)
	settings["hooks"] = hooks

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return err
	}
	if err := backup(settingsPath); err != nil {
		return err
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(settingsPath, append(out, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("installed the Claude Code PreToolUse hook in %s\n", settingsPath)
	fmt.Println("run `blastradius doctor` to confirm, and restart Claude Code to pick it up.")
	return nil
}

func mentionsBlastradius(entry any) bool {
	data, err := json.Marshal(entry)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), "blastradius")
}

// backup copies a file next to itself before it is rewritten. Nothing this tool
// does to a user's configuration should be unrecoverable.
func backup(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return os.WriteFile(path+".blastradius-backup", data, 0o644)
}

// installShims writes wrapper executables that consult the policy and then exec
// the real binary.
func installShims(self string) error {
	dir := filepath.Join(stateDir(), "shims")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	for _, name := range shimmedCommands {
		script := fmt.Sprintf(`#!/bin/sh
# blastradius shim for %[2]s — generated, safe to delete.
# Removing this file disables the check for %[2]s.
%[1]s check --agent=shim -- %[2]s "$@" || exit $?
exec %[3]s "$@"
`, shellQuote(self), name, realBinaryLookup(name))
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			return err
		}
	}

	fmt.Printf("wrote %d shims to %s\n\n", len(shimmedCommands), dir)
	fmt.Println("Add them to the agent's PATH, ahead of the real binaries:")
	fmt.Printf("\n    export PATH=%q:$PATH\n\n", dir)
	fmt.Println("Shim mode is a reduction in accident surface, not a security boundary:")
	fmt.Println("an absolute path such as /bin/rm bypasses it, and file writes made")
	fmt.Println("through an agent's own edit tool never reach a shell at all.")
	fmt.Println("Prefer a native hook where the agent offers one — see `blastradius doctor`.")
	return nil
}

// realBinaryLookup renders the shell expression a shim uses to find the binary
// it wraps, skipping the shim directory itself.
func realBinaryLookup(name string) string {
	return fmt.Sprintf(`"$(PATH="$(echo "$PATH" | sed "s|%s:||")" command -v %s)"`,
		filepath.Join(stateDir(), "shims"), name)
}

// shellQuote wraps a string in single quotes for safe use in generated scripts.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
