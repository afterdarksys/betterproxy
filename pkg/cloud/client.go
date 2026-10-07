// Package cloud integrates betterproxy with the betterspam/betterphish cloud:
// a synchronous spam/phish verdict (betterspam /api/v1/mail/check) consumed
// inline during the SMTP transaction, and best-effort asynchronous feed
// enrichment (betterphish /api/v1/submit/email).
//
// The HTTP client is SSRF-hardened (refuses redirects and, by default, private
// / loopback / link-local destinations), mirroring pkg/authverify/transport.go.
// Every cloud failure is turned into a "degraded" result so the caller can fail
// OPEN and fall back to local scoring — a cloud outage must never stall mail.
package cloud

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds a single cloud call. Kept short: it runs inside the
// SMTP transaction window.
const DefaultTimeout = 4 * time.Second

// maxResponseBytes caps the verdict response we will read.
const maxResponseBytes = 1 << 20 // 1 MiB

// Privacy modes govern how much of a message leaves the proxy.
const (
	// PrivacyFull sends the full raw message plus parsed from/subject/body —
	// maximum detection (spam scoring + phishing URL extraction).
	PrivacyFull = "full"
	// PrivacyHeaders sends only the header block (no body). Phishing URL
	// extraction is skipped cloud-side because no body is supplied.
	PrivacyHeaders = "headers"
	// PrivacyHash sends no content. The current betterspam endpoint has no
	// hash-only lookup, so Check is skipped and the caller fails open. Reserved
	// for a future reputation-by-hash endpoint.
	PrivacyHash = "hash"
)

// Verdict is the combined spam/phish classification.
type Verdict string

const (
	VerdictClean Verdict = "CLEAN"
	VerdictSpam  Verdict = "SPAM"
	VerdictPhish Verdict = "PHISH"
	VerdictBoth  Verdict = "BOTH"
)

// Config configures a Client. CheckURL is required; SubmitURL is optional
// (enrichment is disabled when empty).
type Config struct {
	CheckURL          string        // betterspam POST .../api/v1/mail/check
	SubmitURL         string        // betterphish POST .../api/v1/submit/email
	APIKey            string        // sent as X-API-Key
	Timeout           time.Duration // per-call budget; DefaultTimeout when <= 0
	PrivacyMode       string        // full | headers | hash
	AllowPrivateHosts bool          // permit loopback/private targets (dev/testing)
}

// maxInFlightSubmits bounds concurrent async feed enrichments so a slow or hung
// betterphish endpoint cannot accumulate unbounded goroutines (each holding a
// full message copy) decoupled from the proxy's own session limiter.
const maxInFlightSubmits = 64

// Client talks to the betterspam/betterphish cloud.
type Client struct {
	cfg  Config
	http *http.Client
	sem  chan struct{} // bounds SubmitAsync fan-out
}

// New validates cfg and builds an SSRF-hardened Client.
func New(cfg Config) (*Client, error) {
	if cfg.CheckURL == "" {
		return nil, errors.New("cloud: CheckURL is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	switch cfg.PrivacyMode {
	case "":
		cfg.PrivacyMode = PrivacyFull
	case PrivacyFull, PrivacyHeaders, PrivacyHash:
	default:
		return nil, fmt.Errorf("cloud: unknown privacy mode %q", cfg.PrivacyMode)
	}
	return &Client{
		cfg:  cfg,
		http: newHardenedClient(cfg.Timeout, cfg.AllowPrivateHosts),
		sem:  make(chan struct{}, maxInFlightSubmits),
	}, nil
}

// PrivacyMode reports the configured privacy mode.
func (c *Client) PrivacyMode() string { return c.cfg.PrivacyMode }

// newHardenedClient refuses redirects and (unless allowPrivate) refuses to dial
// private/loopback/link-local/unspecified addresses, defeating SSRF to internal
// services via a hostile DNS answer.
func newHardenedClient(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ipAddr := range ips {
				ip := ipAddr.IP
				if !allowPrivate && (ip.IsPrivate() || ip.IsLoopback() ||
					ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()) {
					continue
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
			return nil, fmt.Errorf("cloud: host %q resolved only to disallowed addresses", host)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("cloud: redirects are not permitted")
		},
	}
}

// CheckRequest carries the message facts a verdict needs. Raw is the full
// original message bytes; RawHeaderBlock is the header block alone (used in
// headers privacy mode).
type CheckRequest struct {
	Raw            []byte
	RawHeaderBlock []byte
	From           string
	Subject        string
	TextBody       string
	Recipient      string
	NextHop        string
	UserID         string
}

// CheckResult is the normalized verdict. Degraded is true when the cloud could
// not be consulted (error, timeout, or hash mode); callers should fail open.
type CheckResult struct {
	Verdict    Verdict
	IsSpam     bool
	IsPhishing bool
	SpamScore  float64
	MaxScore   float64
	Action     string // pass | quarantine | reject
	Confidence float64
	Degraded   bool
	Reason     string
}

// checkResponse mirrors the betterspam /mail/check response summary.
type checkResponse struct {
	Summary struct {
		IsSpam     bool    `json:"is_spam"`
		IsPhishing bool    `json:"is_phishing"`
		SpamScore  float64 `json:"spam_score"`
		MaxScore   float64 `json:"max_score"`
		Action     string  `json:"action"`
		Confidence float64 `json:"confidence"`
	} `json:"summary"`
}

// Check returns a verdict for req. It never returns an error: any failure is
// reported as a Degraded result so the caller fails open.
func (c *Client) Check(ctx context.Context, req CheckRequest) CheckResult {
	if c.cfg.PrivacyMode == PrivacyHash {
		return CheckResult{
			Verdict:  VerdictClean,
			Action:   "pass",
			Degraded: true,
			Reason:   "privacy=hash: content withheld, cloud check skipped",
		}
	}

	payload := map[string]interface{}{
		"from":    req.From,
		"subject": req.Subject,
	}
	switch c.cfg.PrivacyMode {
	case PrivacyHeaders:
		payload["message_base64"] = base64.StdEncoding.EncodeToString(req.RawHeaderBlock)
		// body intentionally omitted
	default: // PrivacyFull
		payload["message_base64"] = base64.StdEncoding.EncodeToString(req.Raw)
		payload["body"] = req.TextBody
	}
	if req.UserID != "" {
		payload["user_id"] = req.UserID
	}

	var resp checkResponse
	if err := c.postJSON(ctx, c.cfg.CheckURL, payload, &resp); err != nil {
		return CheckResult{Verdict: VerdictClean, Action: "pass", Degraded: true, Reason: err.Error()}
	}
	s := resp.Summary
	return CheckResult{
		Verdict:    verdictFor(s.IsSpam, s.IsPhishing),
		IsSpam:     s.IsSpam,
		IsPhishing: s.IsPhishing,
		SpamScore:  s.SpamScore,
		MaxScore:   s.MaxScore,
		Action:     normalizeAction(s.Action),
		Confidence: s.Confidence,
	}
}

// Submit posts a raw message to the betterphish feed for asynchronous
// validation. Best-effort: used by SubmitAsync.
func (c *Client) Submit(ctx context.Context, req CheckRequest) error {
	if c.cfg.SubmitURL == "" {
		return errors.New("cloud: SubmitURL not configured")
	}
	if c.cfg.PrivacyMode == PrivacyHash {
		return errors.New("cloud: privacy=hash: enrichment submit skipped")
	}
	payload := map[string]interface{}{
		"email_base64": base64.StdEncoding.EncodeToString(req.Raw),
		"source":       "betterproxy",
		"recipient":    req.Recipient,
		"nexthop":      req.NextHop,
	}
	return c.postJSON(ctx, c.cfg.SubmitURL, payload, nil)
}

// SubmitAsync fires Submit in the background with its own timeout. It never
// blocks and swallows errors — feed enrichment is best-effort and must not
// affect mail flow.
func (c *Client) SubmitAsync(req CheckRequest) {
	if c.cfg.SubmitURL == "" || c.cfg.PrivacyMode == PrivacyHash {
		return
	}
	select {
	case c.sem <- struct{}{}:
	default:
		return // at capacity: shed enrichment rather than pile up goroutines
	}
	go func() {
		defer func() { <-c.sem }()
		// A panic in this detached goroutine would otherwise crash the whole
		// process (and every SMTP connection) — the worst fail-open violation.
		defer func() { _ = recover() }()
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout)
		defer cancel()
		_ = c.Submit(ctx, req)
	}()
}

func (c *Client) postJSON(ctx context.Context, url string, body, out interface{}) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("cloud: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("cloud: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "betterproxy")
	if c.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", c.cfg.APIKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloud: request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("cloud: read body: %w", err)
	}
	if int64(len(data)) > maxResponseBytes {
		return fmt.Errorf("cloud: response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloud: status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("cloud: decode: %w", err)
		}
	}
	return nil
}

func verdictFor(spam, phish bool) Verdict {
	switch {
	case spam && phish:
		return VerdictBoth
	case spam:
		return VerdictSpam
	case phish:
		return VerdictPhish
	default:
		return VerdictClean
	}
}

// normalizeAction clamps the cloud action to the known set, defaulting to pass.
func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "reject":
		return "reject"
	case "quarantine":
		return "quarantine"
	default:
		return "pass"
	}
}

// RawSHA256 returns the hex SHA-256 of raw, for logging/correlation and future
// hash-based lookups.
func RawSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// AssembleRaw rejoins a header block and body with exactly one blank-line
// separator. It always normalizes the separator to CRLF, so for an LF-only
// source message the result is not byte-identical to the wire form. This only
// affects the cloud payload (hashing/correlation); delivered mail is never
// rebuilt from this, so DKIM on pass-through is unaffected. Do not rely on
// cloud-side signature re-verification over these bytes.
func AssembleRaw(headerBlock, body []byte) []byte {
	out := append([]byte{}, headerBlock...)
	switch {
	case bytes.HasSuffix(headerBlock, []byte("\r\n\r\n")):
	case bytes.HasSuffix(headerBlock, []byte("\r\n")):
		out = append(out, '\r', '\n')
	default:
		out = append(out, '\r', '\n', '\r', '\n')
	}
	return append(out, body...)
}
