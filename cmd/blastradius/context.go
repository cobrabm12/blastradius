package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

// policyFileName is the policy document's name in a repository.
const policyFileName = "guard.yaml"

// loadPolicy assembles the effective policy for a working directory.
//
// The repository's policy is read first and the user's machine policy second,
// because evaluation is last-match-wins: rules the machine's owner wrote must
// be able to override anything a repository ships.
func loadPolicy(cwd string) (*policy.Policy, error) {
	repo, err := readPolicyFile(repoPolicyPath(cwd))
	if err != nil {
		return nil, err
	}
	user, err := readPolicyFile(userPolicyPath())
	if err != nil {
		return nil, err
	}
	merged := policy.Merge(repo, user)
	if merged == nil {
		// Nothing configured yet: analyze, and ask about anything unclear.
		return policy.Load([]byte("version: 1\non_error: ask\n"))
	}
	return merged, nil
}

func readPolicyFile(path string) (*policy.Policy, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p, err := policy.Load(data)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// repoPolicyPath walks up from cwd looking for a policy file, so that the tool
// works from any subdirectory of a project.
func repoPolicyPath(cwd string) string {
	dir := cwd
	for {
		candidate := filepath.Join(dir, policyFileName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func userPolicyPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "blastradius", policyFileName)
}

// context builds the environment description the analysis runs against.
func context(cwd string) paths.Context {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return paths.Context{Cwd: cwd, Home: home, Env: environ()}
}

func environ() map[string]string {
	env := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i > 0 {
			env[kv[:i]] = kv[i+1:]
		}
	}
	return env
}

func stateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".blastradius"
	}
	return filepath.Join(home, ".local", "state", "blastradius")
}
