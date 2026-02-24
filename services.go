package operatorsdk

import (
	"context"
	"net/http"
	"strings"
)

type PublicClient struct {
	Signup          *PublicSignupService
	Auth            *PublicAuthService
	AgentEnrollment *PublicAgentEnrollmentService
	Invites         *PublicInvitesService
	SharedHistory   *PublicSharedHistoryService
	Signing         *PublicSigningService
}

type OperatorClient struct {
	Admin     *OperatorAdminService
	ActorKeys *OperatorActorKeysService
	Envelopes *OperatorEnvelopesService
	History   *OperatorHistoryService
	Security  *OperatorSecurityService
	Templates *OperatorTemplatesService
}

type GatewayClient struct {
	CEL *GatewayCELService
}

type PublicSignupService struct{ c *Client }
type PublicAuthService struct{ c *Client }
type PublicAgentEnrollmentService struct{ c *Client }
type PublicInvitesService struct{ c *Client }
type PublicSharedHistoryService struct{ c *Client }
type PublicSigningService struct{ c *Client }

type OperatorAdminService struct{ c *Client }
type OperatorActorKeysService struct{ c *Client }
type OperatorEnvelopesService struct{ c *Client }
type OperatorHistoryService struct{ c *Client }
type OperatorSecurityService struct{ c *Client }
type OperatorTemplatesService struct{ c *Client }

type GatewayCELService struct{ c *Client }

func newPublicClient(c *Client) *PublicClient {
	return &PublicClient{
		Signup:          &PublicSignupService{c: c},
		Auth:            &PublicAuthService{c: c},
		AgentEnrollment: &PublicAgentEnrollmentService{c: c},
		Invites:         &PublicInvitesService{c: c},
		SharedHistory:   &PublicSharedHistoryService{c: c},
		Signing:         &PublicSigningService{c: c},
	}
}

func newOperatorClient(c *Client) *OperatorClient {
	return &OperatorClient{
		Admin:     &OperatorAdminService{c: c},
		ActorKeys: &OperatorActorKeysService{c: c},
		Envelopes: &OperatorEnvelopesService{c: c},
		History:   &OperatorHistoryService{c: c},
		Security:  &OperatorSecurityService{c: c},
		Templates: &OperatorTemplatesService{c: c},
	}
}

func newGatewayClient(c *Client) *GatewayClient {
	return &GatewayClient{CEL: &GatewayCELService{c: c}}
}

// Public signup

func (s *PublicSignupService) Start(ctx context.Context, req SignupStartRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/signup/start", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicSignupService) Verify(ctx context.Context, req SignupVerifyRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/signup/verify", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicSignupService) Get(ctx context.Context, sessionID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/signup/" + urlEscape(sessionID), Auth: AuthModeNone, Retryable: true}, nil, nil, opts...)
}

func (s *PublicSignupService) Complete(ctx context.Context, req SignupCompleteRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/signup/complete", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

// Public auth/session

func (s *PublicAuthService) MagicLinkStart(ctx context.Context, req MagicLinkStartRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/magic-link/start", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAuthService) MagicLinkVerify(ctx context.Context, req MagicLinkVerifyRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/magic-link/verify", Auth: AuthModeNone, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAuthService) OIDCExchange(ctx context.Context, req OIDCExchangeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/oidc/exchange", Auth: AuthModeNone, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAuthService) SwitchOrg(ctx context.Context, req SwitchOrgRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/session:switch-org", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAuthService) Session(ctx context.Context, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/auth/session", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *PublicAuthService) Logout(ctx context.Context, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/logout", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *PublicAuthService) Sessions(ctx context.Context, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/auth/sessions", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *PublicAuthService) RevokeSession(ctx context.Context, sessionID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/auth/sessions/" + urlEscape(sessionID) + ":revoke", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

// Public agent enrollment

func (s *PublicAgentEnrollmentService) Challenge(ctx context.Context, req AgentEnrollChallengeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/agent-enroll/challenge", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAgentEnrollmentService) Start(ctx context.Context, req AgentEnrollStartRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/agent-enroll/start", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAgentEnrollmentService) Get(ctx context.Context, enrollmentID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/agent-enroll/" + urlEscape(enrollmentID), Auth: AuthModeNone, Retryable: true}, nil, nil, opts...)
}

func (s *PublicAgentEnrollmentService) Approve(ctx context.Context, enrollmentID string, req AgentEnrollApproveRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/agent-enroll/" + urlEscape(enrollmentID) + "/approve", Auth: AuthModeNone, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAgentEnrollmentService) Reject(ctx context.Context, enrollmentID string, req AgentEnrollRejectRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/agent-enroll/" + urlEscape(enrollmentID) + "/reject", Auth: AuthModeNone, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicAgentEnrollmentService) Finalize(ctx context.Context, enrollmentID string, req AgentEnrollFinalizeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/agent-enroll/" + urlEscape(enrollmentID) + "/finalize", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

// Public invites / shared history

func (s *PublicInvitesService) Accept(ctx context.Context, req InviteAcceptRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/invites/accept", Auth: AuthModeNone, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicSharedHistoryService) Get(ctx context.Context, token string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/shared-history/" + urlEscape(token), Auth: AuthModeNone, Retryable: true}, nil, nil, opts...)
}

func (s *PublicSigningService) Resolve(ctx context.Context, token string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/public/v1/signing/" + urlEscape(token), Auth: AuthModeNone, Retryable: true}, nil, nil, opts...)
}

func (s *PublicSigningService) Accept(ctx context.Context, token string, req SigningAcceptRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/signing/" + urlEscape(token) + "/accept", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

func (s *PublicSigningService) Reject(ctx context.Context, token string, req SigningRejectRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/public/v1/signing/" + urlEscape(token) + "/reject", Auth: AuthModeNone, Idempotent: true, Challenge: true, Retryable: true}, nil, req, opts...)
}

// Operator admin

func (s *OperatorAdminService) CreateOrg(ctx context.Context, req CreateOrgRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/orgs", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) CreateProject(ctx context.Context, orgID string, req CreateProjectRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/orgs/" + urlEscape(orgID) + "/projects", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) CreateActor(ctx context.Context, projectID string, req CreateActorRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/projects/" + urlEscape(projectID) + "/actors", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) ListActors(ctx context.Context, projectID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/projects/" + urlEscape(projectID) + "/actors", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) ListActorsCompat(ctx context.Context, projectID string, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if strings.TrimSpace(projectID) != "" {
		q["project_id"] = projectID
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/actors", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorAdminService) DisableActor(ctx context.Context, actorID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/actors/" + urlEscape(actorID) + ":disable", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorActorKeysService) Challenge(ctx context.Context, actorID string, req ActorKeyChallengeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/actors/" + urlEscape(actorID) + "/keys/challenge", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorActorKeysService) Register(ctx context.Context, actorID string, req ActorKeyRegisterRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/actors/" + urlEscape(actorID) + "/keys", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorActorKeysService) List(ctx context.Context, actorID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/actors/" + urlEscape(actorID) + "/keys", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorActorKeysService) Revoke(ctx context.Context, actorID, fingerprint string, req ActorKeyRevokeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/actors/" + urlEscape(actorID) + "/keys/" + urlEscape(fingerprint) + ":revoke", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) UpsertScopePolicy(ctx context.Context, principalID string, req ScopePolicyUpsertRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPut, Path: "/operator/v1/principals/" + urlEscape(principalID) + "/scope-policy", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) GetScopePolicy(ctx context.Context, principalID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/principals/" + urlEscape(principalID) + "/scope-policy", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) IssueCredential(ctx context.Context, req CredentialIssueRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/credentials:issue", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) RotateCredential(ctx context.Context, credentialID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/credentials/" + urlEscape(credentialID) + ":rotate", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) RevokeCredential(ctx context.Context, credentialID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/credentials/" + urlEscape(credentialID) + ":revoke", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) ListCredentials(ctx context.Context, actorID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/credentials", Auth: AuthModeSession, Retryable: true}, map[string]string{"actor_id": actorID}, nil, opts...)
}

func (s *OperatorAdminService) CreateInvite(ctx context.Context, orgID string, req CreateInviteRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/orgs/" + urlEscape(orgID) + "/invites", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) ListInvites(ctx context.Context, orgID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/orgs/" + urlEscape(orgID) + "/invites", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) CancelInvite(ctx context.Context, inviteID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/invites/" + urlEscape(inviteID) + ":cancel", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) ChangeMembershipRole(ctx context.Context, orgID, userID string, req MembershipRoleRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/memberships/" + urlEscape(orgID) + "/" + urlEscape(userID) + ":role", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorAdminService) SuspendMembership(ctx context.Context, orgID, userID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/memberships/" + urlEscape(orgID) + "/" + urlEscape(userID) + ":suspend", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorAdminService) ReactivateMembership(ctx context.Context, orgID, userID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/memberships/" + urlEscape(orgID) + "/" + urlEscape(userID) + ":reactivate", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

// Operator envelopes (active read model)

func (s *OperatorEnvelopesService) List(ctx context.Context, query EnvelopeListQuery, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if strings.TrimSpace(query.ProjectID) != "" {
		q["project_id"] = query.ProjectID
	}
	if strings.TrimSpace(query.ActorID) != "" {
		q["actor_id"] = query.ActorID
	}
	if strings.TrimSpace(query.TemplateID) != "" {
		q["template_id"] = query.TemplateID
	}
	if strings.TrimSpace(query.State) != "" {
		q["state"] = query.State
	}
	if strings.TrimSpace(query.Status) != "" {
		q["status"] = query.Status
	}
	if strings.TrimSpace(query.UpdatedFrom) != "" {
		q["updated_from"] = query.UpdatedFrom
	}
	if strings.TrimSpace(query.UpdatedTo) != "" {
		q["updated_to"] = query.UpdatedTo
	}
	if query.IncludeTerminal != nil {
		if *query.IncludeTerminal {
			q["include_terminal"] = "true"
		} else {
			q["include_terminal"] = "false"
		}
	}
	if strings.TrimSpace(query.SortBy) != "" {
		q["sort_by"] = query.SortBy
	}
	if strings.TrimSpace(query.SortOrder) != "" {
		q["sort_order"] = query.SortOrder
	}
	if query.PageSize > 0 {
		q["page_size"] = itoa(query.PageSize)
	}
	if strings.TrimSpace(query.PageToken) != "" {
		q["page_token"] = query.PageToken
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/envelopes", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorEnvelopesService) Get(ctx context.Context, contractID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/envelopes/" + urlEscape(contractID), Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorEnvelopesService) GetByEnvelopeID(ctx context.Context, envelopeID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/envelopes/by-envelope/" + urlEscape(envelopeID), Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

// Operator history

func (s *OperatorHistoryService) List(ctx context.Context, query HistoryListQuery, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if strings.TrimSpace(query.From) != "" {
		q["from"] = query.From
	}
	if strings.TrimSpace(query.To) != "" {
		q["to"] = query.To
	}
	if strings.TrimSpace(query.SenderName) != "" {
		q["sender_name"] = query.SenderName
	}
	if strings.TrimSpace(query.RecipientName) != "" {
		q["recipient_name"] = query.RecipientName
	}
	if strings.TrimSpace(query.Status) != "" {
		q["status"] = query.Status
	}
	if strings.TrimSpace(query.ContractID) != "" {
		q["contract_id"] = query.ContractID
	}
	if strings.TrimSpace(query.EnvelopeID) != "" {
		q["envelope_id"] = query.EnvelopeID
	}
	if strings.TrimSpace(query.SortBy) != "" {
		q["sort_by"] = query.SortBy
	}
	if strings.TrimSpace(query.SortOrder) != "" {
		q["sort_order"] = query.SortOrder
	}
	if query.PageSize > 0 {
		q["page_size"] = itoa(query.PageSize)
	}
	if strings.TrimSpace(query.PageToken) != "" {
		q["page_token"] = query.PageToken
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/history", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorHistoryService) Get(ctx context.Context, envelopeID string, opts ...RequestOption) (*Result[JSONMap], error) {
	res, err := s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/history/" + urlEscape(envelopeID), Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
	if err != nil {
		return nil, err
	}
	if _, ok := res.Data["history"]; !ok {
		res.Data["history"] = map[string]any{
			"envelope_id": envelopeID,
			"status":      "PENDING",
			"events":      []any{},
		}
	}
	return res, nil
}

func (s *OperatorHistoryService) CreateShareToken(ctx context.Context, envelopeID string, req HistoryShareTokenCreateRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/history/" + urlEscape(envelopeID) + "/share-tokens", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorHistoryService) ListShareTokens(ctx context.Context, envelopeID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/history/" + urlEscape(envelopeID) + "/share-tokens", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorHistoryService) RevokeShareToken(ctx context.Context, tokenID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/history/share-tokens/" + urlEscape(tokenID) + ":revoke", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorHistoryService) RecordInternal(ctx context.Context, req HistoryRecordRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/history:record", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorHistoryService) ListAll(ctx context.Context, query HistoryListQuery, cb func(JSONMap) error, opts ...RequestOption) error {
	if cb == nil {
		return nil
	}
	q := query
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		resp, err := s.List(ctx, q, opts...)
		if err != nil {
			return err
		}
		historyItems, _ := resp.Data["history"].([]any)
		for _, item := range historyItems {
			if err := ctx.Err(); err != nil {
				return err
			}
			row, _ := item.(map[string]any)
			if row == nil {
				continue
			}
			if err := cb(row); err != nil {
				return err
			}
		}
		nextToken, _ := resp.Data["next_page_token"].(string)
		if strings.TrimSpace(nextToken) == "" {
			return nil
		}
		q.PageToken = nextToken
	}
}

// Operator security

func (s *OperatorSecurityService) GetPolicy(ctx context.Context, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/security/policy", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorSecurityService) UpsertPolicy(ctx context.Context, orgID string, req SecurityPolicyUpsertRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPut, Path: "/operator/v1/orgs/" + urlEscape(orgID) + "/security/policy", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorSecurityService) ListAbuseEvents(ctx context.Context, limit int, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if limit > 0 {
		q["limit"] = itoa(limit)
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/security/abuse/events", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorSecurityService) AllowAbuse(ctx context.Context, req AbuseRuleRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/security/abuse/allow", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorSecurityService) BlockAbuse(ctx context.Context, req AbuseRuleRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/security/abuse/block", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorSecurityService) ClearAbuse(ctx context.Context, subject string, req AbuseClearRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/security/abuse/" + urlEscape(subject) + ":clear", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorSecurityService) ListPruneRuns(ctx context.Context, limit int, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if limit > 0 {
		q["limit"] = itoa(limit)
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/history/prune/runs", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorSecurityService) DryRunPrune(ctx context.Context, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/history/prune:dry-run", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

// Templates

func (s *OperatorTemplatesService) CreateForProject(ctx context.Context, projectID string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/projects/" + urlEscape(projectID) + "/templates", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorTemplatesService) Update(ctx context.Context, templateID string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPut, Path: "/operator/v1/templates/" + urlEscape(templateID), Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorTemplatesService) Publish(ctx context.Context, templateID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/templates/" + urlEscape(templateID) + ":publish", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorTemplatesService) Archive(ctx context.Context, templateID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/templates/" + urlEscape(templateID) + ":archive", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorTemplatesService) Clone(ctx context.Context, templateID string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/templates/" + urlEscape(templateID) + ":clone", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorTemplatesService) List(ctx context.Context, query ListTemplatesQuery, opts ...RequestOption) (*Result[JSONMap], error) {
	q := map[string]string{}
	if query.Status != "" {
		q["status"] = query.Status
	}
	if query.Visibility != "" {
		q["visibility"] = query.Visibility
	}
	if query.OwnerPrincipalID != "" {
		q["owner_principal_id"] = query.OwnerPrincipalID
	}
	if query.ContractType != "" {
		q["contract_type"] = query.ContractType
	}
	if query.Jurisdiction != "" {
		q["jurisdiction"] = query.Jurisdiction
	}
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/templates", Auth: AuthModeSession, Retryable: true}, q, nil, opts...)
}

func (s *OperatorTemplatesService) Get(ctx context.Context, templateID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/templates/" + urlEscape(templateID), Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorTemplatesService) ListShares(ctx context.Context, templateID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/operator/v1/templates/" + urlEscape(templateID) + "/shares", Auth: AuthModeSession, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorTemplatesService) AddShare(ctx context.Context, templateID string, req TemplateShareRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/templates/" + urlEscape(templateID) + "/shares", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

func (s *OperatorTemplatesService) RemoveShare(ctx context.Context, templateID, principalID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodDelete, Path: "/operator/v1/templates/" + urlEscape(templateID) + "/shares/" + urlEscape(principalID), Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, nil, opts...)
}

func (s *OperatorTemplatesService) EnableForProject(ctx context.Context, projectID, templateID string, req TemplateEnableRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/operator/v1/projects/" + urlEscape(projectID) + "/templates/" + urlEscape(templateID) + ":enable", Auth: AuthModeSession, Idempotent: true, Retryable: true}, nil, req, opts...)
}

// Gateway

func (s *GatewayCELService) CreateContract(ctx context.Context, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/gateway/v1/cel/contracts", Auth: AuthModeOperator, Retryable: false}, nil, req, opts...)
}

func (s *GatewayCELService) CreateEnvelope(ctx context.Context, req CreateEnvelopeRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	safe := map[string]any{
		"template_id": req.TemplateID,
	}
	if req.Variables != nil {
		safe["variables"] = req.Variables
	}
	if req.Counterparty != nil {
		counterparty := map[string]any{}
		if strings.TrimSpace(req.Counterparty.Email) != "" {
			counterparty["email"] = req.Counterparty.Email
		}
		if strings.TrimSpace(req.Counterparty.Name) != "" {
			counterparty["name"] = req.Counterparty.Name
		}
		safe["counterparty"] = counterparty
	}
	return s.CreateContract(ctx, safe, opts...)
}

func (s *GatewayCELService) ContractAction(ctx context.Context, contractID, action string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/gateway/v1/cel/contracts/" + urlEscape(contractID) + "/actions/" + urlEscape(action), Auth: AuthModeOperator, Retryable: false}, nil, req, opts...)
}

func (s *GatewayCELService) AdvancedAction(ctx context.Context, contractID, action string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.ContractAction(ctx, contractID, action, req, opts...)
}

func (s *GatewayCELService) SetCounterparty(ctx context.Context, contractID string, req SetCounterpartyRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	counterparty := map[string]any{}
	if strings.TrimSpace(req.Email) != "" {
		counterparty["email"] = req.Email
	}
	if strings.TrimSpace(req.Name) != "" {
		counterparty["name"] = req.Name
	}
	return s.ContractAction(ctx, contractID, "counterparties", map[string]any{"counterparty": counterparty}, opts...)
}

// Deprecated: use SetCounterparty for canonical singular counterparty action payloads.
func (s *GatewayCELService) SetCounterparties(ctx context.Context, contractID string, req SetCounterpartiesRequest, opts ...RequestOption) (*Result[JSONMap], error) {
	first := map[string]any{}
	if len(req.Counterparties) > 0 {
		first = req.Counterparties[0]
	} else if len(req.Participants) > 0 {
		first = req.Participants[0]
	} else if req.Policy != nil {
		if stages, ok := req.Policy["stages"].([]any); ok && len(stages) > 0 {
			if stage0, ok := stages[0].(map[string]any); ok {
				if participants, ok := stage0["participants"].([]any); ok && len(participants) > 0 {
					if p0, ok := participants[0].(map[string]any); ok {
						first = p0
					}
				}
			}
		}
	}
	body := map[string]any{}
	if len(first) > 0 {
		body["counterparty"] = first
	}
	return s.ContractAction(ctx, contractID, "counterparties", body, opts...)
}

func (s *GatewayCELService) DecideApproval(ctx context.Context, approvalRequestID string, req map[string]any, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodPost, Path: "/gateway/v1/cel/approvals/" + urlEscape(approvalRequestID) + ":decide", Auth: AuthModeOperator, Retryable: false}, nil, req, opts...)
}

func (s *GatewayCELService) ProofBundle(ctx context.Context, contractID string, opts ...RequestOption) (*Result[JSONMap], error) {
	return s.c.request(ctx, requestSpec{Method: http.MethodGet, Path: "/gateway/v1/cel/contracts/" + urlEscape(contractID) + "/proof-bundle", Auth: AuthModeOperator, Retryable: false}, nil, nil, opts...)
}
