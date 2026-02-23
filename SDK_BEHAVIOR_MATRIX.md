# SDK Behavior Matrix (Go)

## Canonical Methods
- Create contract/envelope: `Gateway.CEL.CreateEnvelope(...)`
- Set counterparty: `Gateway.CEL.SetCounterparty(ctx, contractID, SetCounterpartyRequest{...})`
- Raw action escape hatch: `Gateway.CEL.AdvancedAction(...)`

## Deprecated Aliases
- `Gateway.CEL.SetCounterparties(...)` is deprecated and mapped to singular counterparty payload.

## Error Code Parity
- `TEMPLATE_NOT_ENABLED_FOR_PROJECT`
- `BAD_JSON`
- `UPSTREAM_ERROR`
- `NOT_FOUND`
- `UNKNOWN_ERROR`

## Behavior Notes
- History pending: `Operator.History.Get(envelopeID)` returns a normalized pending shape when backend omits `history`.
- Template enable: `enabled_by_actor_id` is optional; if set, it must be an active actor id.
- Counterparty action drift: prefer singular helper. Use `AdvancedAction` for backend-specific payloads.
