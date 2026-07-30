# AWS Gate Two

## Current status

Gate Two is a locally tested deployment candidate. It is not yet evidence of
live AWS behavior.

The candidate deliberately keeps Amazon Bedrock outside the authority
boundary:

- API Gateway accepts only an AWS IAM-signed `POST /advisory` request.
- Boundary Lambda binds the API request ID and a hash of the authenticated
  principal to the receipt.
- Agent Lambda invokes only `amazon.nova-micro-v1:0` over one exact,
  Gate-One-digest-bound synthetic fixture.
- The model may return only a proposal requesting fresh authorization.
- Boundary Lambda independently validates the proposal and recomputes its
  digest.
- Signer Lambda signs one exact advisory-receipt schema with one KMS P-256 key.
- Boundary Lambda checks the exact receipt echo, recomputes its digest,
  validates the signing-key ARN and envelope, and locally verifies the P-256
  signature before returning success.
- Authority Lambda is an isolated fail-closed placeholder with no model,
  database, MCP, secret, signing, or external-effect capability.

The strongest current claim is that this software and generated
CloudFormation passed local review. Do not claim live Bedrock inference,
KMS-backed evidence, IAM denial, API authentication, or CockroachDB-to-AWS
handoff until their cloud receipts exist.

## Build boundary

`npm run generate:gate2` regenerates reviewed CloudFormation while the source
tree is under development. It emits no Lambda artifact and labels its receipt
unbound.

`npm run build:gate2` refuses to create artifacts unless Git is clean. On a
clean commit it bundles each runtime role separately and records:

- Git commit and tree;
- package-lock digest;
- source SHA-256;
- ZIP SHA-256 in hexadecimal and base64;
- immutable S3 key recommendation;
- template formatted and canonical digests.

Each Lambda Version uses CloudFormation `CodeSha256`, so a version cannot be
published when the deployed code hash differs from the reviewed artifact.

## Live acceptance sequence

1. Re-run all local tests, syntax checks, dependency audit, secret scan,
   CloudFormation lint, and generated-template equality.
2. Commit the accepted local candidate.
3. Build from that clean commit.
4. Create the private, encrypted, versioned S3 artifact bucket.
5. Upload each artifact once and record its exact S3 version ID and both
   digests.
6. Hash the full effective nonsecret deployment configuration.
7. Deploy the main stack with temporary same-role capability probes enabled.
8. Verify every Lambda version's reported `CodeSha256` and alias target.
9. Prove the exact allowed capability and all required denials for every role.
10. Invoke the IAM-signed boundary and preserve the model, KMS, request,
    signature, source, artifact, configuration, token, and latency bindings.
11. Re-run Gate One state hashes to prove Bedrock changed no authority,
    outbox, fence, or protected-effect state.
12. Update the stack with probes disabled, recompute the configuration digest,
    and reverify final aliases and roles.

Any ambiguous, malformed, unsigned, over-budget, or unavailable state returns
`UNKNOWN_DO_NOT_ACT`.

## Stop conditions

Stop instead of weakening the proof if:

- the new AWS account cannot create a required service safely;
- Nova Micro is unavailable in the reviewed region or request schema;
- a runtime role obtains an undeclared capability;
- a public or unsigned path reaches a receipt;
- a Lambda version's code hash differs;
- a model response can introduce an operation ID, fencing token, effect key,
  or authority-bearing field;
- live cost approaches the approved AWS or total-project ceiling.

## Teardown

Capability probes are temporary and must be removed after evidence capture.
CloudFormation owns Gate Two resources. The artifact bucket is intentionally
retained to prevent accidental evidence loss; its exact object versions must
be inventoried before any later deletion decision.
