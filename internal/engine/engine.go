// Package engine wires the analysis pipeline into a single pure function.
package engine

import (
	"time"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
	"github.com/cobrabm12/blastradius/internal/shell"
)

// Budget bounds how long analysis may take before the policy's on_error
// behavior takes over. A guardrail that stalls the agent gets uninstalled.
const Budget = 200 * time.Millisecond

// Request is everything Analyze needs. It reads nothing else.
type Request struct {
	Command string
	Ctx     paths.Context
	Policy  *policy.Policy
}

// Analyze computes the blast radius of a command and evaluates it against the
// policy.
//
// Every failure path — a parse error, a panic, an exhausted time budget —
// resolves to the policy's on_error decision. None of them resolves to allow on
// their own.
func Analyze(req Request) policy.Verdict {
	type result struct{ v policy.Verdict }
	done := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- result{onError(req, "analysis panicked")}
			}
		}()
		done <- result{analyze(req)}
	}()

	select {
	case r := <-done:
		return r.v
	case <-time.After(Budget):
		return onError(req, "analysis exceeded its time budget")
	}
}

func analyze(req Request) policy.Verdict {
	invs, err := shell.Parse(req.Command)
	if err != nil {
		return onError(req, "command could not be parsed: "+err.Error())
	}
	var radius effects.Effects
	for _, inv := range invs {
		radius.Merge(effects.Extract(inv, req.Ctx))
	}
	return policy.Evaluate(radius, req.Policy)
}

func onError(req Request, reason string) policy.Verdict {
	return policy.Verdict{
		Decision: req.Policy.OnError,
		Rule:     "on_error",
		Reason:   reason,
		Radius:   effects.Effects{Unknown: true, Notes: []string{reason}},
	}
}
