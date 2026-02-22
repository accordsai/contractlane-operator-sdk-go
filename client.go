package operatorsdk

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ClientOptions struct {
	BaseURL                string
	HTTPClient             *http.Client
	Timeout                time.Duration
	Retry                  RetryOptions
	SessionToken           string
	SessionTokenProvider   TokenProvider
	OperatorToken          string
	OperatorTokenProvider  TokenProvider
	ChallengeHeaders       ChallengeHeaderProvider
	IdempotencyKeyGenerate func() string
	DefaultHeaders         map[string]string
}

type Client struct {
	baseURL         string
	httpClient      *http.Client
	timeout         time.Duration
	retry           RetryOptions
	sessionToken    string
	sessionProvider TokenProvider
	operatorToken   string
	operatorProv    TokenProvider
	challengeProv   ChallengeHeaderProvider
	idempotencyFn   func() string
	defaultHeaders  map[string]string

	Public   *PublicClient
	Operator *OperatorClient
	Gateway  *GatewayClient
}

type requestSpec struct {
	Method     string
	Path       string
	Auth       AuthMode
	Idempotent bool
	Challenge  bool
	Retryable  bool
}

func NewClient(opts ClientOptions) (*Client, error) {
	base := strings.TrimSpace(opts.BaseURL)
	if base == "" {
		return nil, errors.New("base url is required")
	}
	base = strings.TrimRight(base, "/")

	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	retry := opts.Retry
	if retry.MaxRetries < 0 {
		retry.MaxRetries = 0
	}
	if retry.BaseDelayMs <= 0 {
		retry.BaseDelayMs = 100
	}

	idFn := opts.IdempotencyKeyGenerate
	if idFn == nil {
		idFn = func() string {
			b := make([]byte, 16)
			if _, err := crand.Read(b); err != nil {
				return "idem_" + strings.ReplaceAll(time.Now().UTC().Format("20060102T150405.000000000"), ".", "")
			}
			// RFC 4122 version/variant bits.
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			encoded := hex.EncodeToString(b)
			uuid := encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
			return "idem_" + uuid
		}
	}

	c := &Client{
		baseURL:         base,
		httpClient:      hc,
		timeout:         timeout,
		retry:           retry,
		sessionToken:    opts.SessionToken,
		sessionProvider: opts.SessionTokenProvider,
		operatorToken:   opts.OperatorToken,
		operatorProv:    opts.OperatorTokenProvider,
		challengeProv:   opts.ChallengeHeaders,
		idempotencyFn:   idFn,
		defaultHeaders:  normalizeHeaderMap(opts.DefaultHeaders),
	}

	c.Public = newPublicClient(c)
	c.Operator = newOperatorClient(c)
	c.Gateway = newGatewayClient(c)
	return c, nil
}

func (c *Client) resolveAuthToken(ctx context.Context, auth AuthMode) (string, error) {
	switch auth {
	case AuthModeNone:
		return "", nil
	case AuthModeSession:
		if c.sessionProvider != nil {
			return c.sessionProvider(ctx)
		}
		return c.sessionToken, nil
	case AuthModeOperator:
		if c.operatorProv != nil {
			return c.operatorProv(ctx)
		}
		return c.operatorToken, nil
	default:
		return "", nil
	}
}

func normalizeHeaderMap(input map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range input {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

func (c *Client) request(ctx context.Context, spec requestSpec, query map[string]string, body any, opts ...RequestOption) (*Result[JSONMap], error) {
	ro := buildRequestOptions(opts...)
	retry := c.retry
	if ro.Retry != nil {
		retry = *ro.Retry
		if retry.MaxRetries < 0 {
			retry.MaxRetries = 0
		}
		if retry.BaseDelayMs <= 0 {
			retry.BaseDelayMs = 100
		}
	}

	attempt := 0
	for {
		attempt++
		res, err := c.requestOnce(ctx, spec, query, body, ro)
		if err == nil {
			return res, nil
		}
		if !c.shouldRetry(spec, ro, err) || attempt > retry.MaxRetries+1 {
			return nil, err
		}
		time.Sleep(time.Duration(retry.BaseDelayMs*attempt+mrand.Intn(20)) * time.Millisecond)
	}
}

func (c *Client) shouldRetry(spec requestSpec, ro RequestOptions, err error) bool {
	if !spec.Retryable {
		return false
	}
	safeMethod := spec.Method == http.MethodGet || spec.Method == http.MethodHead
	hasIdempotency := spec.Idempotent
	if strings.TrimSpace(ro.IdempotencyKey) != "" {
		hasIdempotency = true
	}
	if ro.Headers != nil {
		if v, ok := ro.Headers["Idempotency-Key"]; ok && strings.TrimSpace(v) != "" {
			hasIdempotency = true
		}
		if v, ok := ro.Headers["idempotency-key"]; ok && strings.TrimSpace(v) != "" {
			hasIdempotency = true
		}
	}
	safeMutation := (spec.Method == http.MethodPost || spec.Method == http.MethodPut || spec.Method == http.MethodDelete) && spec.Idempotent && hasIdempotency
	if !(safeMethod || safeMutation) {
		return false
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status >= 500 && apiErr.Status <= 599
	}
	return true
}

func (c *Client) requestOnce(ctx context.Context, spec requestSpec, query map[string]string, body any, ro RequestOptions) (*Result[JSONMap], error) {
	auth := spec.Auth
	if ro.AuthOverride != nil {
		auth = *ro.AuthOverride
	}

	headers := map[string]string{"content-type": "application/json"}
	for k, v := range c.defaultHeaders {
		headers[k] = v
	}

	token, err := c.resolveAuthToken(ctx, auth)
	if err != nil {
		return nil, err
	}
	if auth != AuthModeNone && strings.TrimSpace(token) == "" {
		return nil, &APIError{Status: 0, Code: "AUTH_TOKEN_MISSING", Message: "missing auth token provider"}
	}
	if strings.TrimSpace(token) != "" {
		headers["authorization"] = "Bearer " + token
	}

	if spec.Challenge && c.challengeProv != nil {
		challengeHeaders, err := c.challengeProv(ctx, ChallengeHeaderInput{Method: spec.Method, Path: spec.Path, Auth: auth, Body: body})
		if err != nil {
			return nil, err
		}
		for k, v := range normalizeHeaderMap(challengeHeaders) {
			headers[k] = v
		}
	}

	for k, v := range normalizeHeaderMap(ro.Headers) {
		headers[k] = v
	}

	if (spec.Method == http.MethodPost || spec.Method == http.MethodPut || spec.Method == http.MethodDelete) && spec.Idempotent {
		if strings.TrimSpace(ro.IdempotencyKey) != "" {
			headers["idempotency-key"] = ro.IdempotencyKey
		} else if strings.TrimSpace(headers["idempotency-key"]) == "" {
			headers["idempotency-key"] = c.idempotencyFn()
		}
	}

	u, err := url.Parse(c.baseURL + spec.Path)
	if err != nil {
		return nil, err
	}
	if len(query) > 0 {
		q := u.Query()
		for k, v := range query {
			if strings.TrimSpace(v) == "" {
				continue
			}
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	hc := *c.httpClient
	if ro.Timeout > 0 {
		hc.Timeout = ro.Timeout
	} else if c.timeout > 0 {
		hc.Timeout = c.timeout
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	rawBody := string(raw)
	payload := JSONMap{}
	if strings.TrimSpace(rawBody) != "" {
		if err := json.Unmarshal(raw, &payload); err != nil {
			payload = JSONMap{"raw": rawBody}
		}
	}

	meta := ResponseMeta{Status: resp.StatusCode, Headers: map[string]string{}}
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			meta.Headers[strings.ToLower(k)] = vals[0]
		}
	}
	if rid, ok := payload["request_id"].(string); ok {
		meta.RequestID = rid
	}

	if resp.StatusCode >= 400 {
		apiErr := &APIError{Status: resp.StatusCode, RawBody: rawBody, RequestID: meta.RequestID}
		if code, ok := payload["code"].(string); ok {
			apiErr.Code = code
		}
		if msg, ok := payload["message"].(string); ok && strings.TrimSpace(msg) != "" {
			apiErr.Message = msg
		} else {
			apiErr.Message = "request failed with status " + itoa(resp.StatusCode)
		}
		if metaObj, ok := payload["meta"].(map[string]any); ok {
			apiErr.Meta = metaObj
		}
		return nil, apiErr
	}

	return &Result[JSONMap]{Data: payload, Meta: meta}, nil
}
