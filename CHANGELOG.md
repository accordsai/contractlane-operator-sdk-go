# Changelog

## v0.1.1
- Added public signing client methods:
  - `Public.Signing.Resolve`
  - `Public.Signing.Accept`
  - `Public.Signing.Reject`
- Added actor key lifecycle client methods:
  - `Operator.ActorKeys.Challenge`
  - `Operator.ActorKeys.Register`
  - `Operator.ActorKeys.List`
  - `Operator.ActorKeys.Revoke`
- Added actor compatibility listing helper:
  - `Operator.Admin.ListActorsCompat` (`GET /operator/v1/actors?project_id=...`)
- Updated tests and README examples for new coverage.
