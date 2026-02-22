package operatorsdk

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportStep struct {
	status int
	body   map[string]any
	err    error
}

type recordingTransport struct {
	steps []transportStep
	calls []*http.Request
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls = append(rt.calls, req)
	idx := len(rt.calls) - 1
	if idx >= len(rt.steps) {
		idx = len(rt.steps) - 1
	}
	step := rt.steps[idx]
	if step.err != nil {
		return nil, step.err
	}
	payload, _ := json.Marshal(step.body)
	return &http.Response{
		StatusCode: step.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(payload))),
		Request:    req,
	}, nil
}

func newClientForTransport(t *testing.T, tr *recordingTransport, opts ...func(*ClientOptions)) *Client {
	t.Helper()
	co := ClientOptions{
		BaseURL:    "https://example.test",
		HTTPClient: &http.Client{Transport: tr},
	}
	for _, opt := range opts {
		opt(&co)
	}
	c, err := NewClient(co)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func TestSignupInjectsIdempotencyAndChallenge(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{{status: 201, body: map[string]any{"request_id": "req_1"}}}}
	client := newClientForTransport(t, tr,
		func(o *ClientOptions) {
			o.IdempotencyKeyGenerate = func() string { return "idem_test" }
			o.ChallengeHeaders = func(ctx context.Context, input ChallengeHeaderInput) (map[string]string, error) {
				return map[string]string{"X-Signup-Challenge": "abc"}, nil
			}
		},
	)

	_, err := client.Public.Signup.Start(context.Background(), SignupStartRequest{Email: "a@example.com", OrgName: "Acme"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	if len(tr.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(tr.calls))
	}
	req := tr.calls[0]
	if req.Header.Get("Idempotency-Key") != "idem_test" {
		t.Fatalf("expected idempotency key")
	}
	if req.Header.Get("X-Signup-Challenge") != "abc" {
		t.Fatalf("expected signup challenge header")
	}
}

func TestRequestHeadersOverrideChallengeProvider(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{{status: 201, body: map[string]any{"request_id": "req_ovr"}}}}
	client := newClientForTransport(t, tr,
		func(o *ClientOptions) {
			o.ChallengeHeaders = func(ctx context.Context, input ChallengeHeaderInput) (map[string]string, error) {
				return map[string]string{
					"X-Signup-Challenge":         "provider-signup",
					"X-Operator-Challenge":       "provider-proof",
					"X-Operator-Challenge-Token": "provider-token",
				}, nil
			}
			o.IdempotencyKeyGenerate = func() string { return "idem_test" }
		},
	)

	_, err := client.Public.Signup.Start(
		context.Background(),
		SignupStartRequest{Email: "a@example.com", OrgName: "Acme"},
		WithHeaders(map[string]string{
			"X-Signup-Challenge":         "request-signup",
			"X-Operator-Challenge":       "request-proof",
			"X-Operator-Challenge-Token": "request-token",
		}),
	)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	req := tr.calls[0]
	if got := req.Header.Get("X-Signup-Challenge"); got != "request-signup" {
		t.Fatalf("expected request override for signup challenge, got %s", got)
	}
	if got := req.Header.Get("X-Operator-Challenge"); got != "request-proof" {
		t.Fatalf("expected request override for operator challenge, got %s", got)
	}
	if got := req.Header.Get("X-Operator-Challenge-Token"); got != "request-token" {
		t.Fatalf("expected request override for operator challenge token, got %s", got)
	}
}

func TestSessionAuthInjection(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{{status: 200, body: map[string]any{"request_id": "req_2", "session": map[string]any{}}}}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) { o.SessionToken = "session_tok" })

	_, err := client.Public.Auth.Session(context.Background())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if got := tr.calls[0].Header.Get("Authorization"); got != "Bearer session_tok" {
		t.Fatalf("unexpected auth header: %s", got)
	}
}

func TestGatewayOperatorAuthNoIdempotency(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{{status: 200, body: map[string]any{"request_id": "req_3"}}}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) { o.OperatorToken = "operator_tok" })

	_, err := client.Gateway.CEL.CreateContract(context.Background(), map[string]any{"contract": "x"})
	if err != nil {
		t.Fatalf("gateway create: %v", err)
	}
	if got := tr.calls[0].Header.Get("Authorization"); got != "Bearer operator_tok" {
		t.Fatalf("unexpected auth: %s", got)
	}
	if got := tr.calls[0].Header.Get("Idempotency-Key"); got != "" {
		t.Fatalf("expected no idempotency for gateway, got %s", got)
	}
}

func TestErrorMapping(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{{status: 400, body: map[string]any{"request_id": "req_err", "code": "BAD_REQUEST", "message": "invalid"}}}}
	client := newClientForTransport(t, tr)

	_, err := client.Public.Auth.MagicLinkStart(context.Background(), MagicLinkStartRequest{Email: "x@example.com"})
	if err == nil {
		t.Fatalf("expected error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if apiErr.Status != 400 || apiErr.Code != "BAD_REQUEST" || apiErr.RequestID != "req_err" {
		t.Fatalf("unexpected api error: %+v", apiErr)
	}
}

func TestRetrySafeGet(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{
		{status: 500, body: map[string]any{"request_id": "req_fail", "code": "INTERNAL_ERROR", "message": "bad"}},
		{status: 200, body: map[string]any{"request_id": "req_ok", "session": map[string]any{}}},
	}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) {
		o.SessionToken = "session"
		o.Retry = RetryOptions{MaxRetries: 1, BaseDelayMs: 1}
	})

	res, err := client.Public.Auth.Session(context.Background())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if res.Meta.RequestID != "req_ok" {
		t.Fatalf("unexpected request id: %s", res.Meta.RequestID)
	}
	if len(tr.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(tr.calls))
	}
}

func TestRetryIdempotentMutationWithAutoKey(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{
		{status: 500, body: map[string]any{"request_id": "req_fail", "code": "INTERNAL_ERROR", "message": "bad"}},
		{status: 201, body: map[string]any{"request_id": "req_ok", "org": map[string]any{}}},
	}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) {
		o.SessionToken = "session"
		o.Retry = RetryOptions{MaxRetries: 1, BaseDelayMs: 1}
	})

	_, err := client.Operator.Admin.CreateOrg(context.Background(), CreateOrgRequest{Name: "Acme", AdminEmail: "owner@example.com"})
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if len(tr.calls) != 2 {
		t.Fatalf("expected mutation retry with auto idempotency key, got %d calls", len(tr.calls))
	}
}

func TestNoRetryGatewayMutation(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{
		{status: 502, body: map[string]any{"request_id": "req_up", "code": "UPSTREAM_ERROR", "message": "bad upstream"}},
		{status: 200, body: map[string]any{"request_id": "req_should_not_happen"}},
	}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) {
		o.OperatorToken = "operator"
		o.Retry = RetryOptions{MaxRetries: 2, BaseDelayMs: 1}
	})

	_, err := client.Gateway.CEL.CreateContract(context.Background(), map[string]any{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if len(tr.calls) != 1 {
		t.Fatalf("expected one call for gateway mutation, got %d", len(tr.calls))
	}
}

func TestHistoryListAll(t *testing.T) {
	tr := &recordingTransport{steps: []transportStep{
		{status: 200, body: map[string]any{"request_id": "req_1", "history": []any{map[string]any{"envelope_id": "env_1"}}, "next_page_token": "nxt"}},
		{status: 200, body: map[string]any{"request_id": "req_2", "history": []any{map[string]any{"envelope_id": "env_2"}}}},
	}}
	client := newClientForTransport(t, tr, func(o *ClientOptions) { o.SessionToken = "session" })

	var ids []string
	err := client.Operator.History.ListAll(context.Background(), HistoryListQuery{PageSize: 1}, func(item JSONMap) error {
		if v, ok := item["envelope_id"].(string); ok {
			ids = append(ids, v)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(ids) != 2 || ids[0] != "env_1" || ids[1] != "env_2" {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}

func TestGroupCoverageSmoke(t *testing.T) {
	steps := []transportStep{}
	for i := 0; i < 10; i++ {
		steps = append(steps, transportStep{status: 200, body: map[string]any{"request_id": "req" + itoa(i)}})
	}
	tr := &recordingTransport{steps: steps}
	client := newClientForTransport(t, tr, func(o *ClientOptions) {
		o.SessionToken = "session"
		o.OperatorToken = "operator"
	})

	_, _ = client.Public.Invites.Accept(context.Background(), InviteAcceptRequest{InviteToken: "tok", Email: "x@example.com"})
	_, _ = client.Public.AgentEnrollment.Get(context.Background(), "age_1")
	_, _ = client.Operator.Admin.ListActors(context.Background(), "prj_1")
	_, _ = client.Operator.Security.ListAbuseEvents(context.Background(), 10)
	_, _ = client.Operator.Templates.List(context.Background(), ListTemplatesQuery{})
	_, _ = client.Operator.History.Get(context.Background(), "env_1")
	_, _ = client.Public.SharedHistory.Get(context.Background(), "share_tok")
	_, _ = client.Gateway.CEL.ProofBundle(context.Background(), "ctr_1")
	_, _ = client.Public.Auth.Sessions(context.Background())

	if len(tr.calls) != 9 {
		t.Fatalf("expected 9 calls, got %d", len(tr.calls))
	}
}
