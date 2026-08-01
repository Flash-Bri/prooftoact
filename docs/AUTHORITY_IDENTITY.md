# Authority identity contract

Status: `FROZEN_CONTRACT_RUNTIME_MIGRATION_PENDING`

This contract fixes the identity layers that Tideproof will use before the
database and AWS authority paths are migrated. It is a source-level boundary,
not evidence that the current runtime or a live provider enforces it.
Credentialed database bootstrap, Gate Two deployment, and provider evidence
acceptance remain blocked until the dependent database and runtime controls
pass their negative tests.

## Identity layers

1. `tideproof.authority.logical-action.v1` names the business effect. Its
   fields are tenant, incident, resource, agency, action kind, and payload
   digest. It deliberately excludes run, retrieval, caller, attempt, lease,
   race, and source-build identifiers.
2. `tideproof.authority.dvi-proposal-identity.v1` binds one exact DVI snapshot,
   selected rank, evidence-binding digest, policy, and logical action. A new
   retrieval changes the proposal identity but does not create a new logical
   action or authority key.
3. `tideproof.authority.logical-authority-key.v1` binds the logical-action
   digest to one positive database-owned authorization epoch. Only an explicit
   durable database transition may create a later epoch.
4. `tideproof.authority.authorization-binding.v1` binds the proposal identity
   to that logical-authority key. Operation IDs and other attempt identifiers
   remain outside this identity and may only describe retries or contenders.

## Frozen invariants

- Changing `operationId`, `agentId`, `intentNonce`, `effectKey`, `leaseMs`,
  `raceId`, or caller identity cannot create a new logical action or logical
  authority key.
- Changing run, retrieval, DVI evidence binding, policy, rank, or snapshot time
  creates a different proposal identity, not a fresh authority epoch.
- Changing a logical effect field creates a different logical-action digest.
- Repeating the same logical action at the same authorization epoch produces
  the same logical-authority key, regardless of caller or attempt identity.
- A later epoch is valid only after a separate durable database authorization
  transition. Client input cannot select, increment, or reset the epoch.
- Every durable proposal, request, decision, outbox intent, recovery record,
  audit record, and drill receipt must carry the applicable identity digests
  once the runtime migration lands.

The executable contract is `src/cloud/authority-identity.js`; focused tests
lock canonical encoding, strict schemas, field separation, and epoch behavior.
The current authority tables and AWS race remain pre-migration candidates and
must not be treated as satisfying this contract.
