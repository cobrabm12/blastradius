package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/cobrabm12/blastradius/internal/audit"
	"github.com/cobrabm12/blastradius/internal/effects"
)

// runDoctor reports what is actually protected, and — more importantly — what
// is not. A guardrail that hides its gaps is worse than none.
func runDoctor(_ []string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	fmt.Println("blastradius", version)
	fmt.Println()

	// Policy
	fmt.Println("policy")
	if p := repoPolicyPath(cwd); p != "" {
		fmt.Printf("  repository:  %s\n", p)
	} else {
		fmt.Printf("  repository:  none — run `blastradius init`\n")
	}
	if p := userPolicyPath(); p != "" {
		if _, err := os.Stat(p); err == nil {
			fmt.Printf("  machine:     %s\n", p)
		} else {
			fmt.Printf("  machine:     none (%s)\n", p)
		}
	}
	pol, err := loadPolicy(cwd)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  rules:       %d path, %d host\n", len(pol.Paths), len(pol.Hosts))
		fmt.Printf("  on_error:    %s\n", pol.OnError)
	}
	fmt.Println()

	// Agents
	fmt.Println("agents")
	reportClaudeCode()
	reportShims()
	reportCodex()
	fmt.Println()

	// Coverage
	registered := effects.Registered()
	sort.Strings(registered)
	fmt.Println("coverage")
	fmt.Printf("  commands analyzed: %d\n", len(registered))
	fmt.Printf("  %s\n", strings.Join(registered, " "))
	fmt.Println("  any command not listed above resolves to on_error, never to allow.")
	fmt.Println()

	// Audit
	path := audit.DefaultPath()
	if pol != nil && pol.Audit.Path != "" {
		path = pol.Audit.Path
	}
	fmt.Println("audit")
	if n, err := countLines(path); err == nil {
		fmt.Printf("  %s (%d decisions)\n", path, n)
	} else {
		fmt.Printf("  %s (not written yet)\n", path)
	}

	return nil
}

func reportClaudeCode() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		fmt.Println("  claude-code: not detected")
		return
	}
	if strings.Contains(string(data), "blastradius") {
		fmt.Println("  claude-code: NATIVE (PreToolUse hook installed)")
		fmt.Println("               covers Bash, Write, and Edit — including writes")
		fmt.Println("               that never pass through a shell.")
		return
	}
	var settings map[string]any
	if json.Unmarshal(data, &settings) == nil {
		fmt.Println("  claude-code: detected, NOT protected")
		fmt.Println("               run `blastradius install`")
	}
}

func reportShims() {
	dir := filepath.Join(stateDir(), "shims")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		fmt.Println("  shims:       not installed")
		return
	}
	onPath := strings.Contains(os.Getenv("PATH"), dir)
	fmt.Printf("  shims:       %d installed in %s\n", len(entries), dir)
	if onPath {
		fmt.Println("               ACTIVE on this shell's PATH")
	} else {
		fmt.Println("               present but NOT on this shell's PATH — inactive here")
	}
	fmt.Println("               gap: absolute paths such as /bin/rm bypass a shim,")
	fmt.Println("               and edit-tool writes never reach a shell.")
}

func reportCodex() {
	if _, err := exec.LookPath("codex"); err != nil {
		fmt.Println("  codex:       not detected")
		return
	}
	fmt.Println("  codex:       detected — SHIM MODE ONLY")
	fmt.Println("               Codex exposes no pre-execution hook, so native mode")
	fmt.Println("               is unavailable. Run `blastradius install --shim`.")
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		n++
	}
	return n, s.Err()
}

// runLog prints the tail of the audit trail.
func runLog(args []string) error {
	n := 20
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" && i+1 < len(args) {
			if parsed, err := strconv.Atoi(args[i+1]); err == nil {
				n = parsed
			}
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	path := audit.DefaultPath()
	if pol, err := loadPolicy(cwd); err == nil && pol.Audit.Path != "" {
		path = pol.Audit.Path
	}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		fmt.Printf("no audit log yet at %s\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	if err := s.Err(); err != nil {
		return err
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	for _, line := range lines {
		var e audit.Entry
		if json.Unmarshal([]byte(line), &e) != nil {
			continue
		}
		fmt.Printf("%s  %-5s  %-12s  %s\n",
			e.Time.Format("2006-01-02 15:04:05"),
			strings.ToUpper(e.Decision), e.Rule, e.Command)
	}
	return nil
}
