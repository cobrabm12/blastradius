// Package adapters translates each agent's pre-execution protocol to and from
// a policy verdict.
package adapters

import (
	"encoding/json"
	"io"

	"github.com/cobrabm12/blastradius/internal/policy"
)

// ClaudeCodeRequest is the PreToolUse payload Claude Code writes to a hook's
// standard input. Only the fields blastradius reads are declared.
type ClaudeCodeRequest struct {
	SessionID string `json:"session_id"`
	Cwd       string `json:"cwd"`
	EventName string `json:"hook_event_name"`
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		// Bash
		Command string `json:"command"`
		// Write, Edit
		FilePath string `json:"file_path"`
		// Edit
		OldString string `json:"old_string"`
		NewString string `json:"new_string"`
	} `json:"tool_input"`
}

// ClaudeCodeResponse is the JSON a PreToolUse hook writes to standard output.
type ClaudeCodeResponse struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// DecodeClaudeCode reads a PreToolUse request.
func DecodeClaudeCode(r io.Reader) (ClaudeCodeRequest, error) {
	var req ClaudeCodeRequest
	err := json.NewDecoder(r).Decode(&req)
	return req, err
}

// CommandFor renders the tool call as a shell command for analysis.
//
// Write and Edit never reach a shell, so they are expressed as the equivalent
// filesystem effect: a write to the target path. This is why native mode covers
// more ground than a PATH shim can.
func (r ClaudeCodeRequest) CommandFor() (command string, ok bool) {
	switch r.ToolName {
	case "Bash":
		if r.ToolInput.Command == "" {
			return "", false
		}
		return r.ToolInput.Command, true
	case "Write", "Edit", "NotebookEdit", "MultiEdit":
		if r.ToolInput.FilePath == "" {
			return "", false
		}
		return "touch " + shellQuote(r.ToolInput.FilePath), true
	default:
		return "", false
	}
}

// EncodeClaudeCode writes the verdict in the shape Claude Code expects.
func EncodeClaudeCode(w io.Writer, v policy.Verdict) error {
	var resp ClaudeCodeResponse
	resp.HookSpecificOutput.HookEventName = "PreToolUse"
	resp.HookSpecificOutput.PermissionDecision = claudeDecision(v.Decision)
	resp.HookSpecificOutput.PermissionDecisionReason = Reason(v)
	return json.NewEncoder(w).Encode(resp)
}

func claudeDecision(d policy.Decision) string {
	switch d {
	case policy.Block:
		return "deny"
	case policy.Ask:
		return "ask"
	default:
		return "allow"
	}
}

// Reason renders a verdict's justification for an agent to read. It names the
// rule, so the agent can tell the user which line of policy stopped it.
func Reason(v policy.Verdict) string {
	if v.Rule == "" || v.Rule == "default" {
		return v.Reason
	}
	return v.Reason + " [blastradius " + v.Rule + "]"
}

// shellQuote wraps a path in single quotes for safe re-parsing.
func shellQuote(s string) string {
	out := make([]byte, 0, len(s)+2)
	out = append(out, '\'')
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(append(out, '\''))
}
