// Package audit appends decisions to a JSON Lines log.
//
// The log is what makes a guardrail reviewable after the fact: every verdict
// records what was asked, what the analysis computed, and which rule decided.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/cobrabm12/blastradius/internal/policy"
)

// Entry is one line of the audit log.
type Entry struct {
	Time      time.Time `json:"time"`
	Agent     string    `json:"agent"`
	Command   string    `json:"command"`
	Cwd       string    `json:"cwd"`
	Decision  string    `json:"decision"`
	Rule      string    `json:"rule"`
	Reason    string    `json:"reason"`
	Deletes   []string  `json:"deletes,omitempty"`
	Truncates []string  `json:"truncates,omitempty"`
	Writes    []string  `json:"writes,omitempty"`
	Remotes   []string  `json:"remotes,omitempty"`
	Unknown   bool      `json:"unknown,omitempty"`
}

// DefaultPath is where the log lives when the policy does not say otherwise.
func DefaultPath() string {
	if dir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(dir, ".local", "state", "blastradius", "audit.jsonl")
	}
	return "blastradius-audit.jsonl"
}

// Append writes one verdict to the log. Logging is best-effort: a failure to
// record must never change what the agent is allowed to do, so the error is
// returned for reporting but callers may ignore it.
func Append(path, agent, command, cwd string, v policy.Verdict) error {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	e := Entry{
		Time:     time.Now().UTC(),
		Agent:    agent,
		Command:  command,
		Cwd:      cwd,
		Decision: string(v.Decision),
		Rule:     v.Rule,
		Reason:   v.Reason,
		Unknown:  v.Radius.Unknown,
	}
	for _, p := range v.Radius.Deletes {
		e.Deletes = append(e.Deletes, p.Abs)
	}
	for _, p := range v.Radius.Truncates {
		e.Truncates = append(e.Truncates, p.Abs)
	}
	for _, p := range v.Radius.Writes {
		e.Writes = append(e.Writes, p.Abs)
	}
	for _, r := range v.Radius.Remotes {
		e.Remotes = append(e.Remotes, string(r.Verb)+" "+r.Host)
	}

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}
