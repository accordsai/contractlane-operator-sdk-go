package operatorsdk

import (
	"context"
	"time"
)

type JSONMap map[string]any

type AuthMode string

const (
	AuthModeNone     AuthMode = "none"
	AuthModeSession  AuthMode = "session"
	AuthModeOperator AuthMode = "operator"
)

type RetryOptions struct {
	MaxRetries  int
	BaseDelayMs int
}

type ResponseMeta struct {
	RequestID string
	Status    int
	Headers   map[string]string
}

type Result[T any] struct {
	Data T
	Meta ResponseMeta
}

type APIError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
	Meta      map[string]any
	RawBody   string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}
	msg := "status=" + itoa(e.Status)
	if e.Code != "" {
		msg += " code=" + e.Code
	}
	if e.RequestID != "" {
		msg += " request_id=" + e.RequestID
	}
	if e.Message != "" {
		msg += " message=" + e.Message
	}
	return msg
}

type TokenProvider func(ctx context.Context) (string, error)

type ChallengeHeaderInput struct {
	Method string
	Path   string
	Auth   AuthMode
	Body   any
}

type ChallengeHeaderProvider func(ctx context.Context, input ChallengeHeaderInput) (map[string]string, error)

type RequestOptions struct {
	Headers        map[string]string
	Timeout        time.Duration
	IdempotencyKey string
	AuthOverride   *AuthMode
	Retry          *RetryOptions
}

type RequestOption func(*RequestOptions)

func WithHeaders(headers map[string]string) RequestOption {
	return func(o *RequestOptions) {
		if len(headers) == 0 {
			return
		}
		if o.Headers == nil {
			o.Headers = map[string]string{}
		}
		for k, v := range headers {
			o.Headers[k] = v
		}
	}
}

func WithTimeout(timeout time.Duration) RequestOption {
	return func(o *RequestOptions) {
		o.Timeout = timeout
	}
}

func WithIdempotencyKey(key string) RequestOption {
	return func(o *RequestOptions) {
		o.IdempotencyKey = key
	}
}

func WithAuth(mode AuthMode) RequestOption {
	return func(o *RequestOptions) {
		o.AuthOverride = &mode
	}
}

func WithRetry(retry RetryOptions) RequestOption {
	return func(o *RequestOptions) {
		o.Retry = &retry
	}
}

func buildRequestOptions(opts ...RequestOption) RequestOptions {
	ro := RequestOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&ro)
		}
	}
	return ro
}

// request payloads

type SignupStartRequest struct {
	Email   string `json:"email"`
	OrgName string `json:"org_name"`
}

type SignupVerifyRequest struct {
	SessionID        string `json:"session_id"`
	VerificationCode string `json:"verification_code"`
}

type SignupCompleteRequest struct {
	SessionID    string   `json:"session_id"`
	Jurisdiction string   `json:"jurisdiction,omitempty"`
	Timezone     string   `json:"timezone,omitempty"`
	ProjectName  string   `json:"project_name,omitempty"`
	AgentName    string   `json:"agent_name,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

type MagicLinkStartRequest struct {
	Email string `json:"email"`
	OrgID string `json:"org_id,omitempty"`
}

type MagicLinkVerifyRequest struct {
	LinkID string `json:"link_id"`
	Token  string `json:"token"`
}

type OIDCExchangeRequest struct {
	AccessToken string `json:"access_token"`
	OrgID       string `json:"org_id,omitempty"`
}

type SwitchOrgRequest struct {
	OrgID string `json:"org_id"`
}

type AgentEnrollChallengeRequest struct {
	PublicKeyJWK         map[string]any `json:"public_key_jwk"`
	PublicKeyFingerprint string         `json:"public_key_fingerprint,omitempty"`
}

type AgentEnrollStartRequest struct {
	ChallengeID     string   `json:"challenge_id"`
	Signature       string   `json:"signature"`
	SponsorEmail    string   `json:"sponsor_email"`
	OrgName         string   `json:"org_name,omitempty"`
	ProjectName     string   `json:"project_name,omitempty"`
	AgentName       string   `json:"agent_name,omitempty"`
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	OrgID           string   `json:"org_id,omitempty"`
}

type AgentEnrollApproveRequest struct {
	ApprovalToken  string   `json:"approval_token"`
	ApprovedScopes []string `json:"approved_scopes,omitempty"`
	ProjectName    string   `json:"project_name,omitempty"`
	AgentName      string   `json:"agent_name,omitempty"`
}

type AgentEnrollRejectRequest struct {
	ApprovalToken string `json:"approval_token"`
}

type AgentEnrollFinalizeRequest struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

type InviteAcceptRequest struct {
	InviteToken string `json:"invite_token"`
	Email       string `json:"email"`
}

type CreateOrgRequest struct {
	Name       string `json:"name"`
	AdminEmail string `json:"admin_email"`
}

type CreateProjectRequest struct {
	Name         string `json:"name"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
	Timezone     string `json:"timezone,omitempty"`
}

type CreateActorRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

type ScopePolicyUpsertRequest struct {
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	DeniedScopes  []string `json:"denied_scopes,omitempty"`
}

type CredentialIssueRequest struct {
	ActorID       string   `json:"actor_id"`
	Scopes        []string `json:"scopes,omitempty"`
	UpstreamToken string   `json:"upstream_token"`
	TTLMinutes    int      `json:"ttl_minutes,omitempty"`
}

type CreateInviteRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

type MembershipRoleRequest struct {
	Role string `json:"role"`
}

type HistoryListQuery struct {
	From          string
	To            string
	SenderName    string
	RecipientName string
	Status        string
	ContractID    string
	EnvelopeID    string
	SortBy        string
	SortOrder     string
	PageSize      int
	PageToken     string
}

type HistoryShareTokenCreateRequest struct {
	OneTimeUse bool   `json:"one_time_use,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

type HistoryRecordRequest struct {
	OrgID         string         `json:"org_id"`
	ProjectID     string         `json:"project_id,omitempty"`
	PrincipalID   string         `json:"principal_id,omitempty"`
	ActorID       string         `json:"actor_id,omitempty"`
	ContractID    string         `json:"contract_id,omitempty"`
	EnvelopeID    string         `json:"envelope_id"`
	SenderName    string         `json:"sender_name,omitempty"`
	RecipientName string         `json:"recipient_name,omitempty"`
	Status        string         `json:"status"`
	CompletedAt   string         `json:"completed_at,omitempty"`
	CELPayload    map[string]any `json:"cel_payload,omitempty"`
	ProofBundle   map[string]any `json:"proof_bundle,omitempty"`
	Visibility    string         `json:"visibility,omitempty"`
}

type SecurityPolicyUpsertRequest struct {
	MaxShareTokenTTLHours           *int     `json:"max_share_token_ttl_hours,omitempty"`
	MaxActiveShareTokensPerEnvelope *int     `json:"max_active_share_tokens_per_envelope,omitempty"`
	MaxActiveShareTokensPerOrg      *int     `json:"max_active_share_tokens_per_org,omitempty"`
	AllowNonExpiringShareTokens     *bool    `json:"allow_non_expiring_share_tokens,omitempty"`
	AllowOneTimeShareTokens         *bool    `json:"allow_one_time_share_tokens,omitempty"`
	ShareTokenIPAllowlist           []string `json:"share_token_ip_allowlist,omitempty"`
	ShareTokenAutoRevokeBurst       *int     `json:"share_token_auto_revoke_burst,omitempty"`
	ChallengeRequiredPublic         *bool    `json:"challenge_required_public,omitempty"`
	AbuseChallengeThreshold         *int     `json:"abuse_challenge_threshold,omitempty"`
	AbuseBlockThreshold             *int     `json:"abuse_block_threshold,omitempty"`
	AbuseDecaySeconds               *int     `json:"abuse_decay_seconds,omitempty"`
	AbuseTempBlockSeconds           *int     `json:"abuse_temp_block_seconds,omitempty"`
}

type AbuseRuleRequest struct {
	SubjectType  string `json:"subject_type"`
	SubjectValue string `json:"subject_value"`
	Reason       string `json:"reason,omitempty"`
	TTLSeconds   int    `json:"ttl_seconds,omitempty"`
}

type AbuseClearRequest struct {
	SubjectValue string `json:"subject_value"`
}

type ListTemplatesQuery struct {
	Status           string
	Visibility       string
	OwnerPrincipalID string
	ContractType     string
	Jurisdiction     string
}

type TemplateShareRequest struct {
	PrincipalID string `json:"principal_id"`
}

type TemplateEnableRequest struct {
	EnabledByActorID string            `json:"enabled_by_actor_id,omitempty"`
	OverrideGates    map[string]string `json:"override_gates,omitempty"`
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
