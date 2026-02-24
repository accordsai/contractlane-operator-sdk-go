# sdk-go (Contract Lane Operator)

Go SDK for the Contract Lane Operator API.

## Install
```bash
go get github.com/acordsai/contractlane-operator-sdk-go
```

## Quickstart
```go
client, err := operatorsdk.NewClient(operatorsdk.ClientOptions{
    BaseURL:      "https://localhost",
    SessionToken: "session-token",
    OperatorToken: "operator-token",
    ChallengeHeaders: func(ctx context.Context, in operatorsdk.ChallengeHeaderInput) (map[string]string, error) {
        return map[string]string{
            "X-Signup-Challenge": "signup-challenge-token",
            "X-Operator-Challenge": "proof-challenge",
            "X-Operator-Challenge-Token": "challenge-provider-token",
        }, nil
    },
})
if err != nil {
    panic(err)
}
```

### 1) Human signup/auth
```go
start, _ := client.Public.Signup.Start(ctx, operatorsdk.SignupStartRequest{Email: "owner@example.com", OrgName: "Acme"})
sessionID := start.Data["signup_session"].(map[string]any)["session_id"].(string)

_, _ = client.Public.Signup.Verify(ctx, operatorsdk.SignupVerifyRequest{SessionID: sessionID, VerificationCode: "123456"})
_, _ = client.Public.Signup.Complete(ctx, operatorsdk.SignupCompleteRequest{SessionID: sessionID, ProjectName: "Default", AgentName: "Primary"})
```

### 2) Admin actor + credential issue
```go
org, _ := client.Operator.Admin.CreateOrg(ctx, operatorsdk.CreateOrgRequest{Name: "Acme", AdminEmail: "owner@example.com"})
orgID := org.Data["org"].(map[string]any)["org_id"].(string)
project, _ := client.Operator.Admin.CreateProject(ctx, orgID, operatorsdk.CreateProjectRequest{Name: "Project A"})
projectID := project.Data["project"].(map[string]any)["project_id"].(string)
actor, _ := client.Operator.Admin.CreateActor(ctx, projectID, operatorsdk.CreateActorRequest{Name: "Bot", Scopes: []string{"cel.contracts:write"}})
actorID := actor.Data["actor"].(map[string]any)["actor_id"].(string)
_, _ = client.Operator.Admin.IssueCredential(ctx, operatorsdk.CredentialIssueRequest{ActorID: actorID, UpstreamToken: "upstream-token"})
```

### 3) Agent-first enrollment
```go
challenge, _ := client.Public.AgentEnrollment.Challenge(ctx, operatorsdk.AgentEnrollChallengeRequest{PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "..."}})
challengeID := challenge.Data["challenge"].(map[string]any)["challenge_id"].(string)
_, _ = client.Public.AgentEnrollment.Start(ctx, operatorsdk.AgentEnrollStartRequest{
    ChallengeID: challengeID,
    Signature: "base64url-signature",
    SponsorEmail: "owner@example.com",
    RequestedScopes: []string{"cel.contracts:write"},
})
```

### 4) Gateway contract + counterparty action
```go
_, _ = client.Gateway.CEL.CreateEnvelope(ctx, operatorsdk.CreateEnvelopeRequest{
    TemplateID: "tpl_123",
    Variables: map[string]any{"amount": "100.00"},
    Counterparty: &operatorsdk.CreateEnvelopeCounterparty{
        Email: "counterparty@example.com",
    },
})
_, _ = client.Gateway.CEL.SetCounterparty(ctx, "ctr_123", operatorsdk.SetCounterpartyRequest{
    Email: "counterparty@example.com",
})
_, _ = client.Gateway.CEL.AdvancedAction(ctx, "ctr_123", "SEND_FOR_SIGNATURE", map[string]any{})
```

### 5) Public signing + actor key lifecycle
```go
_, _ = client.Public.Signing.Resolve(ctx, "sign_tok")
_, _ = client.Public.Signing.Accept(ctx, "sign_tok", operatorsdk.SigningAcceptRequest{
    ChallengeID: "chal_123",
    Signature:   "base64url-signature",
})

_, _ = client.Operator.ActorKeys.Challenge(ctx, "act_123", operatorsdk.ActorKeyChallengeRequest{
    PublicKeyJWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "..."},
})
_, _ = client.Operator.ActorKeys.List(ctx, "act_123")
_, _ = client.Operator.Admin.ListActorsCompat(ctx, "prj_123")
```

### 6) Active envelopes
```go
includeTerminal := false
_, _ = client.Operator.Envelopes.List(ctx, operatorsdk.EnvelopeListQuery{
    IncludeTerminal: &includeTerminal, // active only
    PageSize:        20,
})
includeAll := true
_, _ = client.Operator.Envelopes.List(ctx, operatorsdk.EnvelopeListQuery{
    IncludeTerminal: &includeAll, // active + terminal
    SortBy:          "updated_at",
    SortOrder:       "desc",
})
_, _ = client.Operator.Envelopes.Get(ctx, "ctr_123")
_, _ = client.Operator.Envelopes.GetByEnvelopeID(ctx, "env_123")
```

## Notes
- Mutating operator/public endpoints auto-inject `Idempotency-Key`.
- `request_id` is in `result.Meta.RequestID`.
- Challenge hooks can provide `X-Signup-Challenge`, `X-Operator-Challenge`, and `X-Operator-Challenge-Token`; per-request headers can override hook values.
- Failures return `*APIError` with status/code/message/request_id/meta/raw_body.
- Template enable accepts optional `enabled_by_actor_id`; if provided it must be an active actor id in the project.
- `Operator.History.Get(envelopeID)` normalizes missing history records to a pending shape.
- `Operator.Envelopes.*` reads active lifecycle index state (in-flight + optional terminal).
- `Operator.History.*` remains finalized/indexed audit feed.
- Prefer `Gateway.CEL.SetCounterparty()` over deprecated plural/staged compatibility wrapper `SetCounterparties()`.

See `SDK_BEHAVIOR_MATRIX.md` for canonical/deprecated method parity and backend-behavior notes.

## Integration Tests
Run against a live operator stack:
```bash
go test -tags=integration ./integration -v
```

Strictness controls:
- `TEST_ADMIN_STRICT_SUCCESS=1`: require admin flow success; otherwise unauthorized admin environments are treated as non-blocking.
- `TEST_GATEWAY_STRICT_SUCCESS=1`: require gateway create/action/proof success; otherwise `404` is treated as environment limitation.

## Release (standalone public repo)
For the standalone module `github.com/acordsai/contractlane-operator-sdk-go`, publish using semantic tags:
```bash
git tag v0.1.0
git push origin v0.1.0
```
