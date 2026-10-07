package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	cfg.AllowPrivateHosts = true // httptest binds loopback
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestCheckVerdictMapping(t *testing.T) {
	cases := []struct {
		name        string
		spam, phish bool
		want        Verdict
	}{
		{"clean", false, false, VerdictClean},
		{"spam", true, false, VerdictSpam},
		{"phish", false, true, VerdictPhish},
		{"both", true, true, VerdictBoth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				resp := map[string]interface{}{"summary": map[string]interface{}{
					"is_spam": tc.spam, "is_phishing": tc.phish,
					"spam_score": 12.5, "max_score": 15.0,
					"action": "reject", "confidence": 0.8,
				}}
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()

			c := testClient(t, Config{CheckURL: srv.URL})
			res := c.Check(context.Background(), CheckRequest{Raw: []byte("x")})
			if res.Degraded {
				t.Fatalf("unexpected degraded: %s", res.Reason)
			}
			if res.Verdict != tc.want {
				t.Errorf("verdict = %s, want %s", res.Verdict, tc.want)
			}
			if res.SpamScore != 12.5 || res.Action != "reject" {
				t.Errorf("score/action = %v/%s", res.SpamScore, res.Action)
			}
		})
	}
}

func TestCheckSendsParsedFieldsAndBase64(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			t.Errorf("missing/wrong api key: %q", r.Header.Get("X-API-Key"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"summary":{"action":"pass"}}`))
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL, APIKey: "secret"})
	raw := []byte("Subject: hi\r\n\r\nvisit http://evil.example")
	c.Check(context.Background(), CheckRequest{
		Raw: raw, From: "a@b.com", Subject: "hi", TextBody: "visit http://evil.example",
	})
	if got["from"] != "a@b.com" || got["subject"] != "hi" {
		t.Errorf("parsed fields not forwarded: %#v", got)
	}
	if got["body"] != "visit http://evil.example" {
		t.Errorf("body not forwarded in full mode: %#v", got["body"])
	}
	b64, _ := got["message_base64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || string(decoded) != string(raw) {
		t.Errorf("message_base64 mismatch: err=%v decoded=%q", err, decoded)
	}
}

func TestHeadersPrivacyModeOmitsBody(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		_, _ = w.Write([]byte(`{"summary":{"action":"pass"}}`))
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL, PrivacyMode: PrivacyHeaders})
	c.Check(context.Background(), CheckRequest{
		Raw:            []byte("full"),
		RawHeaderBlock: []byte("Subject: hi\r\n"),
		TextBody:       "secret body",
	})
	if _, ok := got["body"]; ok {
		t.Errorf("headers mode must not send body: %#v", got)
	}
	b64, _ := got["message_base64"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(b64)
	if string(decoded) != "Subject: hi\r\n" {
		t.Errorf("headers mode should send header block only, got %q", decoded)
	}
}

func TestHashPrivacyModeSkipsCloud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("hash mode must not call the cloud")
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL, PrivacyMode: PrivacyHash})
	res := c.Check(context.Background(), CheckRequest{Raw: []byte("x")})
	if !res.Degraded || res.Verdict != VerdictClean {
		t.Errorf("hash mode should fail open clean+degraded, got %+v", res)
	}
}

func TestCheckFailsOpenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL})
	res := c.Check(context.Background(), CheckRequest{Raw: []byte("x")})
	if !res.Degraded {
		t.Errorf("5xx should produce degraded result, got %+v", res)
	}
	if res.Verdict != VerdictClean || res.Action != "pass" {
		t.Errorf("fail-open must be clean/pass, got %+v", res)
	}
}

func TestCheckFailsOpenOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"summary":{}}`))
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL, Timeout: 20 * time.Millisecond})
	res := c.Check(context.Background(), CheckRequest{Raw: []byte("x")})
	if !res.Degraded {
		t.Errorf("timeout should produce degraded result, got %+v", res)
	}
}

func TestRedirectsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	c := testClient(t, Config{CheckURL: srv.URL})
	res := c.Check(context.Background(), CheckRequest{Raw: []byte("x")})
	if !res.Degraded || !strings.Contains(res.Reason, "redirect") {
		t.Errorf("redirect should be refused and degrade, got %+v", res)
	}
}

func TestNewRejectsBadPrivacyMode(t *testing.T) {
	if _, err := New(Config{CheckURL: "https://x", PrivacyMode: "bogus"}); err == nil {
		t.Error("expected error for unknown privacy mode")
	}
	if _, err := New(Config{}); err == nil {
		t.Error("expected error for missing CheckURL")
	}
}

func TestAssembleRaw(t *testing.T) {
	cases := []struct{ hdr, body, want string }{
		{"A: 1\r\n\r\n", "body", "A: 1\r\n\r\nbody"},
		{"A: 1\r\n", "body", "A: 1\r\n\r\nbody"},
		{"A: 1", "body", "A: 1\r\n\r\nbody"},
	}
	for _, tc := range cases {
		if got := string(AssembleRaw([]byte(tc.hdr), []byte(tc.body))); got != tc.want {
			t.Errorf("AssembleRaw(%q,%q) = %q, want %q", tc.hdr, tc.body, got, tc.want)
		}
	}
}
