package rules

import (
	"bytes"
	"context"
	"strings"

	"github.com/afterdarksys/betterproxy/pkg/cloud"
	"go.starlark.net/starlark"
)

// cloudBuiltins exposes the betterspam/betterphish cloud to policy scripts.
//
//	betterspam_check(user_id="", score=True) -> dict
//	betterphish_submit() -> bool   (async feed enrichment; True if dispatched)
//	cloud_available() -> bool
//
// When no cloud is configured the builtins degrade gracefully: betterspam_check
// returns a CLEAN, cloud_ok=False verdict so policies fail open.
func (e *scriptEnv) cloudBuiltins() starlark.StringDict {
	return starlark.StringDict{
		"betterspam_check":   starlark.NewBuiltin("betterspam_check", e.betterspamCheck),
		"betterphish_submit": starlark.NewBuiltin("betterphish_submit", e.betterphishSubmit),
		"cloud_available":    starlark.NewBuiltin("cloud_available", e.cloudAvailable),
	}
}

func (e *scriptEnv) cloudAvailable(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cloud_available", args, kwargs); err != nil {
		return nil, err
	}
	return starlark.Bool(e.opts.Cloud != nil), nil
}

func (e *scriptEnv) betterspamCheck(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var userID string
	score := true
	if err := starlark.UnpackArgs("betterspam_check", args, kwargs, "user_id?", &userID, "score?", &score); err != nil {
		return nil, err
	}
	if e.opts.Cloud == nil {
		return cloudVerdictDict(cloud.CheckResult{
			Verdict:  cloud.VerdictClean,
			Action:   "pass",
			Degraded: true,
			Reason:   "cloud not configured",
		}, false), nil
	}
	res := e.opts.Cloud.Check(context.Background(), e.cloudRequest(userID))
	if score && res.SpamScore != 0 {
		e.msg.AddScore(res.SpamScore, "betterspam:"+string(res.Verdict))
	}
	return cloudVerdictDict(res, true), nil
}

func (e *scriptEnv) betterphishSubmit(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("betterphish_submit", args, kwargs); err != nil {
		return nil, err
	}
	if e.opts.Cloud == nil {
		return starlark.Bool(false), nil
	}
	e.opts.Cloud.SubmitAsync(e.cloudRequest(""))
	return starlark.Bool(true), nil
}

// cloudVerdictDict renders a CheckResult as the Starlark dict policies read.
func cloudVerdictDict(res cloud.CheckResult, configured bool) *starlark.Dict {
	return dictOf(
		"configured", configured,
		"verdict", string(res.Verdict),
		"is_spam", res.IsSpam,
		"is_phishing", res.IsPhishing,
		"spam_score", res.SpamScore,
		"max_score", res.MaxScore,
		"action", res.Action,
		"confidence", res.Confidence,
		"cloud_ok", !res.Degraded,
		"reason", res.Reason,
	)
}

// cloudRequest assembles a cloud.CheckRequest from the message context.
func (e *scriptEnv) cloudRequest(userID string) cloud.CheckRequest {
	m := e.msg
	recipient := ""
	if len(m.EnvelopeTo) > 0 {
		recipient = m.EnvelopeTo[0]
	}
	body := m.TextBody
	if body == "" {
		body = m.Body
	}
	return cloud.CheckRequest{
		Raw:            messageRaw(m),
		RawHeaderBlock: m.RawHeaderBlock,
		From:           m.Get("From"),
		Subject:        m.Get("Subject"),
		TextBody:       body,
		Recipient:      recipient,
		NextHop:        recipientDomain(recipient),
		UserID:         userID,
	}
}

// messageRaw returns the full original message bytes, preferring the preserved
// raw header block + body, and falling back to reconstruction from the parsed
// header list when the raw form was not retained.
func messageRaw(m *MessageContext) []byte {
	if len(m.RawHeaderBlock) > 0 {
		return cloud.AssembleRaw(m.RawHeaderBlock, m.RawBody)
	}
	var b bytes.Buffer
	for _, h := range m.HeaderList {
		if h.Raw != "" {
			b.WriteString(h.Raw)
		} else {
			b.WriteString(h.Name)
			b.WriteString(": ")
			b.WriteString(h.Value)
		}
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(m.Body)
	return b.Bytes()
}

func recipientDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return strings.Trim(addr[i+1:], "<> ")
	}
	return ""
}
