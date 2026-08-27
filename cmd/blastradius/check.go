package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cobrabm12/blastradius/internal/adapters"
	"github.com/cobrabm12/blastradius/internal/audit"
	"github.com/cobrabm12/blastradius/internal/engine"
	"github.com/cobrabm12/blastradius/internal/policy"
)

// grantTTL is how long a single-use exception stays valid.
const grantTTL = 5 * time.Minute

func runCheck(args []string) error {
	agent := "shim"
	var shimArgv []string
	for i := 0; i < len(args); i++ {
		switch {
		case strings.HasPrefix(args[i], "--agent="):
			agent = strings.TrimPrefix(args[i], "--agent=")
		case args[i] == "--":
			shimArgv = args[i+1:]
			i = len(args)
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	pol, err := loadPolicy(cwd)
	if err != nil {
		return err
	}

	switch agent {
	case "claude-code":
		return checkClaudeCode(cwd, pol)
	case "shim":
		return checkShim(cwd, pol, shimArgv)
	default:
		return fmt.Errorf("unknown agent %q; supported: claude-code, shim", agent)
	}
}

// checkClaudeCode answers a PreToolUse hook. Native mode can express `ask`,
// because the agent has a way to put the question to the user.
func checkClaudeCode(cwd string, pol *policy.Policy) error {
	req, err := adapters.DecodeClaudeCode(os.Stdin)
	if err != nil {
		// A malformed payload is not a licence to proceed, but neither should a
		// protocol change brick the user's agent: defer to on_error.
		return adapters.EncodeClaudeCode(os.Stdout, policy.Verdict{
			Decision: pol.OnError,
			Rule:     "on_error",
			Reason:   "hook payload could not be decoded: " + err.Error(),
		})
	}

	command, ok := req.CommandFor()
	if !ok {
		return adapters.EncodeClaudeCode(os.Stdout, policy.Verdict{
			Decision: policy.Allow,
			Rule:     "default",
			Reason:   "tool touches no filesystem or host target",
		})
	}

	if req.Cwd != "" {
		cwd = req.Cwd
	}
	v := engine.Analyze(engine.Request{Command: command, Ctx: context(cwd), Policy: pol})
	_ = audit.Append(pol.Audit.Path, "claude-code", command, cwd, v)
	return adapters.EncodeClaudeCode(os.Stdout, v)
}

// checkShim answers a PATH shim. A shim has no channel back to an approval UI,
// so `ask` degrades to a block that names the escape hatch.
func checkShim(cwd string, pol *policy.Policy, argv []string) error {
	if len(argv) == 0 {
		return errors.New("usage: blastradius check --agent=shim -- <command> [args...]")
	}
	command := strings.Join(argv, " ")
	v := engine.Analyze(engine.Request{Command: command, Ctx: context(cwd), Policy: pol})
	_ = audit.Append(pol.Audit.Path, "shim", command, cwd, v)

	switch v.Decision {
	case policy.Allow:
		return nil
	case policy.Ask:
		if consumeGrant(command) {
			return nil
		}
		fmt.Fprintf(os.Stderr, "blastradius: %s\n", adapters.Reason(v))
		fmt.Fprintf(os.Stderr, "  this needs your confirmation, and a shim cannot ask.\n")
		fmt.Fprintf(os.Stderr, "  to permit it once:  blastradius allow-once %q\n", command)
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "blastradius: blocked — %s\n", adapters.Reason(v))
		os.Exit(1)
	}
	return nil
}

// grantPath is where a single-use exception is recorded, keyed by the hash of
// the exact command it covers.
func grantPath(command string) string {
	sum := sha256.Sum256([]byte(command))
	return filepath.Join(stateDir(), "grants", hex.EncodeToString(sum[:])+".grant")
}

func runAllowOnce(args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: blastradius allow-once "<command>"`)
	}
	path := grantPath(args[0])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
		return err
	}
	fmt.Printf("granted once, valid for %s:\n  %s\n", grantTTL, args[0])
	return nil
}

// consumeGrant reports whether a valid single-use exception exists, removing it
// either way: a grant is spent when it is examined, and an expired one is
// cleaned up rather than left to rot.
func consumeGrant(command string) bool {
	path := grantPath(command)
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_ = os.Remove(path)
	issued, err := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}
	return time.Since(issued) <= grantTTL
}
