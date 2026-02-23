//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	operatorsdk "github.com/contractlane/contractlane-sdk/sdk-go"
)

type flowState struct {
	signupEmail  string
	sessionToken string
	sessionOrgID string
	agentToken   string
	contractID   string
	adminAuth    string
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		t.Fatalf("missing required env: %s", key)
	}
	return v
}

func challengeHeaders(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"X-Signup-Challenge":         requireEnv(t, "TEST_CHALLENGE_SIGNUP"),
		"X-Operator-Challenge":       requireEnv(t, "TEST_CHALLENGE_OPERATOR"),
		"X-Operator-Challenge-Token": requireEnv(t, "TEST_CHALLENGE_OPERATOR_TOKEN"),
	}
}

func newClient(t *testing.T, baseURL string, opts ...func(*operatorsdk.ClientOptions)) *operatorsdk.Client {
	t.Helper()
	co := operatorsdk.ClientOptions{
		BaseURL: baseURL,
		HTTPClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
		},
	}
	for _, opt := range opts {
		opt(&co)
	}
	c, err := operatorsdk.NewClient(co)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func requestID(t *testing.T, res *operatorsdk.Result[operatorsdk.JSONMap]) string {
	t.Helper()
	if res == nil {
		t.Fatalf("nil result")
	}
	if strings.TrimSpace(res.Meta.RequestID) != "" {
		return res.Meta.RequestID
	}
	if rid, _ := res.Data["request_id"].(string); strings.TrimSpace(rid) != "" {
		return rid
	}
	t.Fatalf("missing request_id")
	return ""
}

func signAgent(challengeID, nonce string, privateKey ed25519.PrivateKey) string {
	sig := ed25519.Sign(privateKey, []byte(challengeID+":"+nonce))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func TestOperatorSDKIntegrationFlows(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	baseURL := requireEnv(t, "OPERATOR_BASE_URL")
	state := &flowState{}

	t.Run("signup-auth-flow", func(t *testing.T) {
		email := strings.Replace(requireEnv(t, "TEST_USER_EMAIL"), "@", fmt.Sprintf("+go-%d@", time.Now().UnixMilli()), 1)
		state.signupEmail = email

		client := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) {
			o.ChallengeHeaders = func(ctx context.Context, input operatorsdk.ChallengeHeaderInput) (map[string]string, error) {
				return challengeHeaders(t), nil
			}
		})

		start, err := client.Public.Signup.Start(ctx, operatorsdk.SignupStartRequest{Email: email, OrgName: "SDK GO Org"})
		if err != nil {
			t.Fatalf("signup start: %v", err)
		}
		_ = requestID(t, start)
		signupSession, _ := start.Data["signup_session"].(map[string]any)
		sessionID, _ := signupSession["session_id"].(string)
		if strings.TrimSpace(sessionID) == "" {
			t.Fatalf("missing signup session id: %#v", start.Data)
		}

		_, err = client.Public.Signup.Verify(ctx, operatorsdk.SignupVerifyRequest{SessionID: sessionID, VerificationCode: "000000"})
		if err == nil {
			t.Fatalf("expected invalid verify to fail")
		}

		var verifyCode string
		if ch, ok := start.Data["challenge"].(map[string]any); ok {
			verifyCode, _ = ch["verification_code"].(string)
		}
		if strings.TrimSpace(verifyCode) == "" {
			verifyCode = strings.TrimSpace(os.Getenv("TEST_SIGNUP_VERIFICATION_CODE"))
		}
		if strings.TrimSpace(verifyCode) == "" {
			t.Fatalf("missing verification code. set TEST_SIGNUP_VERIFICATION_CODE when APP_ENV hides codes")
		}

		verify, err := client.Public.Signup.Verify(ctx, operatorsdk.SignupVerifyRequest{SessionID: sessionID, VerificationCode: verifyCode})
		if err != nil {
			t.Fatalf("signup verify: %v", err)
		}
		_ = requestID(t, verify)

		complete, err := client.Public.Signup.Complete(ctx, operatorsdk.SignupCompleteRequest{
			SessionID:   sessionID,
			ProjectName: "SDK GO Project",
			AgentName:   "SDK GO Agent",
			Scopes:      []string{"cel.contracts:write", "cel.approvals:decide", "cel.proof:read"},
		})
		if err != nil {
			t.Fatalf("signup complete: %v", err)
		}
		_ = requestID(t, complete)
		if org, ok := complete.Data["org"].(map[string]any); ok {
			if orgID, _ := org["org_id"].(string); strings.TrimSpace(orgID) != "" {
				state.sessionOrgID = orgID
			}
		}

		noChallenge := newClient(t, baseURL)
		if _, err := noChallenge.Public.Signup.Start(ctx, operatorsdk.SignupStartRequest{Email: fmt.Sprintf("%d-nochallenge@example.com", time.Now().UnixMilli()), OrgName: "No Challenge"}); err == nil {
			t.Fatalf("expected missing challenge header failure")
		}

		magicStart, err := client.Public.Auth.MagicLinkStart(ctx, operatorsdk.MagicLinkStartRequest{Email: email})
		if err != nil {
			t.Fatalf("magic-link start: %v", err)
		}
		magicLink, _ := magicStart.Data["magic_link"].(map[string]any)
		linkID, _ := magicLink["link_id"].(string)
		token, _ := magicLink["token"].(string)
		if strings.TrimSpace(token) == "" {
			token = strings.TrimSpace(os.Getenv("TEST_MAGIC_LINK_TOKEN"))
		}
		if strings.TrimSpace(linkID) == "" || strings.TrimSpace(token) == "" {
			t.Fatalf("missing link_id/token; set TEST_MAGIC_LINK_TOKEN when token is hidden")
		}

		magicVerify, err := client.Public.Auth.MagicLinkVerify(ctx, operatorsdk.MagicLinkVerifyRequest{LinkID: linkID, Token: token})
		if err != nil {
			t.Fatalf("magic-link verify: %v", err)
		}
		session, _ := magicVerify.Data["session"].(map[string]any)
		sessionToken, _ := session["token"].(string)
		if strings.TrimSpace(sessionToken) == "" {
			t.Fatalf("missing session token in verify response")
		}
		switchOrgID := state.sessionOrgID
		if strings.TrimSpace(switchOrgID) == "" {
			if orgID, _ := session["org_id"].(string); strings.TrimSpace(orgID) != "" {
				switchOrgID = orgID
			}
		}
		if strings.TrimSpace(switchOrgID) != "" {
			scopedClient := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.SessionToken = sessionToken })
			switched, err := scopedClient.Public.Auth.SwitchOrg(ctx, operatorsdk.SwitchOrgRequest{OrgID: switchOrgID})
			if err != nil {
				t.Fatalf("switch org: %v", err)
			}
			if switchedSession, ok := switched.Data["session"].(map[string]any); ok {
				if switchedToken, _ := switchedSession["token"].(string); strings.TrimSpace(switchedToken) != "" {
					sessionToken = switchedToken
				}
			}
		}
		state.sessionToken = sessionToken

		sessionClient := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.SessionToken = state.sessionToken })
		res, err := sessionClient.Public.Auth.Session(ctx)
		if err != nil {
			t.Fatalf("auth session: %v", err)
		}
		_ = requestID(t, res)
	})

	t.Run("admin-actor-credential-flow", func(t *testing.T) {
		strictAdmin := strings.TrimSpace(os.Getenv("TEST_ADMIN_STRICT_SUCCESS")) == "1"
		if strings.TrimSpace(state.sessionToken) == "" {
			t.Fatalf("session token not initialized")
		}
		client := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.SessionToken = state.sessionToken })
		bootstrapToken := strings.TrimSpace(os.Getenv("TEST_BOOTSTRAP_TOKEN"))
		if bootstrapToken == "" {
			bootstrapToken = strings.TrimSpace(os.Getenv("TEST_UPSTREAM_TOKEN"))
		}
		bootstrapUserEmail := state.signupEmail
		if strings.TrimSpace(bootstrapUserEmail) == "" {
			bootstrapUserEmail = requireEnv(t, "TEST_USER_EMAIL")
		}

		org, err := client.Operator.Admin.CreateOrg(ctx, operatorsdk.CreateOrgRequest{Name: fmt.Sprintf("SDK GO Admin Org %d", time.Now().UnixMilli()), AdminEmail: state.signupEmail})
		if err != nil {
			var apiErr *operatorsdk.APIError
			if !errors.As(err, &apiErr) || apiErr.Status != 401 || strings.TrimSpace(bootstrapToken) == "" {
				t.Fatalf("create org: %v", err)
			}
			bootstrapClient := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.SessionToken = bootstrapToken })
			org, err = bootstrapClient.Operator.Admin.CreateOrg(
				ctx,
				operatorsdk.CreateOrgRequest{Name: fmt.Sprintf("SDK GO Admin Org %d", time.Now().UnixMilli()), AdminEmail: state.signupEmail},
				operatorsdk.WithHeaders(map[string]string{"X-Operator-User-Email": bootstrapUserEmail}),
			)
			if err != nil {
				var bootstrapErr *operatorsdk.APIError
				if errors.As(err, &bootstrapErr) && bootstrapErr.Status == 401 && !strictAdmin {
					return
				}
				t.Fatalf("create org bootstrap fallback: %v", err)
			}
			client = bootstrapClient
			state.adminAuth = "bootstrap"
		} else {
			state.adminAuth = "session"
		}
		orgObj, _ := org.Data["org"].(map[string]any)
		orgID, _ := orgObj["org_id"].(string)
		if strings.TrimSpace(orgID) == "" {
			t.Fatalf("missing org_id")
		}
		if state.adminAuth == "session" {
			switched, err := client.Public.Auth.SwitchOrg(ctx, operatorsdk.SwitchOrgRequest{OrgID: orgID})
			if err != nil {
				t.Fatalf("switch org for admin flow: %v", err)
			}
			if switchedSession, ok := switched.Data["session"].(map[string]any); ok {
				if switchedToken, _ := switchedSession["token"].(string); strings.TrimSpace(switchedToken) != "" {
					state.sessionToken = switchedToken
					client = newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.SessionToken = state.sessionToken })
				}
			}
		}
		var orgScopedOpt operatorsdk.RequestOption = func(o *operatorsdk.RequestOptions) {}
		if state.adminAuth == "bootstrap" {
			orgScopedOpt = operatorsdk.WithHeaders(map[string]string{
				"X-Operator-User-Email": bootstrapUserEmail,
				"X-Operator-Org-Id":     orgID,
			})
		}

		project, err := client.Operator.Admin.CreateProject(ctx, orgID, operatorsdk.CreateProjectRequest{Name: fmt.Sprintf("SDK GO Project %d", time.Now().UnixMilli()), Jurisdiction: "US", Timezone: "UTC"}, orgScopedOpt)
		if err != nil {
			t.Fatalf("create project: %v", err)
		}
		projObj, _ := project.Data["project"].(map[string]any)
		projectID, _ := projObj["project_id"].(string)
		if strings.TrimSpace(projectID) == "" {
			t.Fatalf("missing project_id")
		}

		actor, err := client.Operator.Admin.CreateActor(ctx, projectID, operatorsdk.CreateActorRequest{Name: fmt.Sprintf("SDK GO Actor %d", time.Now().UnixMilli()), Scopes: []string{"cel.contracts:write", "cel.approvals:decide", "cel.proof:read"}}, orgScopedOpt)
		if err != nil {
			t.Fatalf("create actor: %v", err)
		}
		actorObj, _ := actor.Data["actor"].(map[string]any)
		actorID, _ := actorObj["actor_id"].(string)
		if strings.TrimSpace(actorID) == "" {
			t.Fatalf("missing actor_id")
		}

		upstreamToken := requireEnv(t, "TEST_UPSTREAM_TOKEN")
		if _, err := client.Operator.Admin.IssueCredential(ctx, operatorsdk.CredentialIssueRequest{ActorID: actorID, UpstreamToken: upstreamToken, Scopes: []string{"cel.contracts:write"}, TTLMinutes: 15}, orgScopedOpt); err != nil {
			t.Fatalf("issue credential: %v", err)
		}

		listed, err := client.Operator.Admin.ListCredentials(ctx, actorID, orgScopedOpt)
		if err != nil {
			t.Fatalf("list credentials: %v", err)
		}
		_ = requestID(t, listed)
	})

	t.Run("agent-enrollment-flow", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		client := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) {
			o.ChallengeHeaders = func(ctx context.Context, input operatorsdk.ChallengeHeaderInput) (map[string]string, error) {
				return challengeHeaders(t), nil
			}
		})

		challenge, err := client.Public.AgentEnrollment.Challenge(ctx, operatorsdk.AgentEnrollChallengeRequest{PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}})
		if err != nil {
			t.Fatalf("agent challenge: %v", err)
		}
		chObj, _ := challenge.Data["challenge"].(map[string]any)
		challengeID, _ := chObj["challenge_id"].(string)
		nonce, _ := chObj["nonce"].(string)
		if strings.TrimSpace(challengeID) == "" || strings.TrimSpace(nonce) == "" {
			t.Fatalf("missing challenge_id or nonce")
		}

		if _, err := client.Public.AgentEnrollment.Start(ctx, operatorsdk.AgentEnrollStartRequest{ChallengeID: challengeID, Signature: "invalid", SponsorEmail: state.signupEmail, OrgName: fmt.Sprintf("SDK GO Agent Org %d", time.Now().UnixMilli())}); err == nil {
			t.Fatalf("expected invalid signature start failure")
		}

		start, err := client.Public.AgentEnrollment.Start(ctx, operatorsdk.AgentEnrollStartRequest{
			ChallengeID:     challengeID,
			Signature:       signAgent(challengeID, nonce, priv),
			SponsorEmail:    state.signupEmail,
			OrgName:         fmt.Sprintf("SDK GO Agent Org %d", time.Now().UnixMilli()),
			RequestedScopes: []string{"cel.contracts:write", "cel.approvals:decide", "cel.proof:read"},
		})
		if err != nil {
			t.Fatalf("agent start: %v", err)
		}

		enrollment, _ := start.Data["enrollment"].(map[string]any)
		enrollmentID, _ := enrollment["enrollment_id"].(string)
		approvalToken, _ := enrollment["approval_token"].(string)
		if strings.TrimSpace(approvalToken) == "" {
			approvalToken = strings.TrimSpace(os.Getenv("TEST_AGENT_APPROVAL_TOKEN"))
		}
		if strings.TrimSpace(enrollmentID) == "" || strings.TrimSpace(approvalToken) == "" {
			t.Fatalf("missing enrollment_id/approval_token")
		}

		if _, err := client.Public.AgentEnrollment.Approve(ctx, enrollmentID, operatorsdk.AgentEnrollApproveRequest{ApprovalToken: approvalToken}); err != nil {
			t.Fatalf("agent approve: %v", err)
		}

		finalChallenge, err := client.Public.AgentEnrollment.Challenge(ctx, operatorsdk.AgentEnrollChallengeRequest{PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}})
		if err != nil {
			t.Fatalf("agent final challenge: %v", err)
		}
		fObj, _ := finalChallenge.Data["challenge"].(map[string]any)
		fID, _ := fObj["challenge_id"].(string)
		fNonce, _ := fObj["nonce"].(string)

		finalize, err := client.Public.AgentEnrollment.Finalize(ctx, enrollmentID, operatorsdk.AgentEnrollFinalizeRequest{ChallengeID: fID, Signature: signAgent(fID, fNonce, priv)})
		if err != nil {
			t.Fatalf("agent finalize: %v", err)
		}
		cred, _ := finalize.Data["credential"].(map[string]any)
		agentToken, _ := cred["token"].(string)
		if strings.TrimSpace(agentToken) == "" {
			t.Fatalf("missing agent token")
		}
		state.agentToken = agentToken

		rejChallenge, err := client.Public.AgentEnrollment.Challenge(ctx, operatorsdk.AgentEnrollChallengeRequest{PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}})
		if err != nil {
			t.Fatalf("reject challenge: %v", err)
		}
		rejChObj, _ := rejChallenge.Data["challenge"].(map[string]any)
		rejCID, _ := rejChObj["challenge_id"].(string)
		rejNonce, _ := rejChObj["nonce"].(string)

		rejectStart, err := client.Public.AgentEnrollment.Start(ctx, operatorsdk.AgentEnrollStartRequest{
			ChallengeID:     rejCID,
			Signature:       signAgent(rejCID, rejNonce, priv),
			SponsorEmail:    state.signupEmail,
			OrgName:         fmt.Sprintf("SDK GO Reject Org %d", time.Now().UnixMilli()),
			RequestedScopes: []string{"cel.contracts:write"},
		})
		if err != nil {
			t.Fatalf("reject start: %v", err)
		}
		rejEnrollment, _ := rejectStart.Data["enrollment"].(map[string]any)
		rejID, _ := rejEnrollment["enrollment_id"].(string)
		rejApprovalToken, _ := rejEnrollment["approval_token"].(string)
		if strings.TrimSpace(rejApprovalToken) == "" {
			rejApprovalToken = strings.TrimSpace(os.Getenv("TEST_AGENT_APPROVAL_TOKEN"))
		}
		if _, err := client.Public.AgentEnrollment.Reject(ctx, rejID, operatorsdk.AgentEnrollRejectRequest{ApprovalToken: rejApprovalToken}); err != nil {
			t.Fatalf("reject enrollment: %v", err)
		}

		if _, err := client.Public.AgentEnrollment.Finalize(ctx, rejID, operatorsdk.AgentEnrollFinalizeRequest{ChallengeID: rejCID, Signature: signAgent(rejCID, rejNonce, priv)}); err == nil {
			t.Fatalf("expected finalize failure after reject")
		}
	})

	t.Run("gateway-contract-flow", func(t *testing.T) {
		if strings.TrimSpace(state.agentToken) == "" {
			t.Fatalf("agent token not initialized")
		}
		client := newClient(t, baseURL, func(o *operatorsdk.ClientOptions) { o.OperatorToken = state.agentToken })

		createBody := map[string]any{}
		if raw := strings.TrimSpace(os.Getenv("TEST_GATEWAY_CREATE_BODY")); raw != "" {
			if err := json.Unmarshal([]byte(raw), &createBody); err != nil {
				t.Fatalf("invalid TEST_GATEWAY_CREATE_BODY: %v", err)
			}
		}
		strictGateway := strings.TrimSpace(os.Getenv("TEST_GATEWAY_STRICT_SUCCESS")) == "1"
		created, err := client.Gateway.CEL.CreateContract(ctx, createBody)
		if err != nil {
			var apiErr *operatorsdk.APIError
			if !errors.As(err, &apiErr) || strictGateway || apiErr.Status != 404 {
				t.Fatalf("gateway create contract: %v", err)
			}
			return
		}
		_ = requestID(t, created)

		contractID, _ := created.Data["contract_id"].(string)
		if strings.TrimSpace(contractID) == "" {
			if cObj, ok := created.Data["contract"].(map[string]any); ok {
				contractID, _ = cObj["contract_id"].(string)
			}
		}
		if strings.TrimSpace(contractID) == "" {
			contractID = strings.TrimSpace(os.Getenv("TEST_GATEWAY_CONTRACT_ID"))
		}
		if strings.TrimSpace(contractID) == "" {
			t.Fatalf("missing contract_id from create response and TEST_GATEWAY_CONTRACT_ID not set")
		}

		action := strings.TrimSpace(os.Getenv("TEST_GATEWAY_ACTION"))
		if action == "" {
			action = "send"
		}
		actionBody := map[string]any{}
		if raw := strings.TrimSpace(os.Getenv("TEST_GATEWAY_ACTION_BODY")); raw != "" {
			if err := json.Unmarshal([]byte(raw), &actionBody); err != nil {
				t.Fatalf("invalid TEST_GATEWAY_ACTION_BODY: %v", err)
			}
		}
		actResp, err := client.Gateway.CEL.ContractAction(ctx, contractID, action, actionBody)
		if err != nil {
			var apiErr *operatorsdk.APIError
			if !errors.As(err, &apiErr) || strictGateway || apiErr.Status != 404 {
				t.Fatalf("gateway contract action: %v", err)
			}
		} else {
			_ = requestID(t, actResp)
		}

		proof, err := client.Gateway.CEL.ProofBundle(ctx, contractID)
		if err != nil {
			var apiErr *operatorsdk.APIError
			if errors.As(err, &apiErr) {
				if strictGateway || apiErr.Status != 404 {
					t.Fatalf("gateway proof bundle API error: status=%d code=%s request_id=%s", apiErr.Status, apiErr.Code, apiErr.RequestID)
				}
				return
			}
			t.Fatalf("gateway proof bundle: %v", err)
		}
		_ = requestID(t, proof)
	})
}
