# Gate Two local predeployment acceptance — `9aa7f2e`

## Claim boundary

This receipt clears exact commit
`9aa7f2e7409e4eedb8e386ec9c18440670505fa6` for a controlled live AWS
deployment attempt. It is not evidence of live CloudFormation, IAM, Lambda,
API Gateway, CloudWatch Logs, KMS, Bedrock, or AWS Budgets behavior.

- Source tree:
  `bdfd51fcdf9fa9d59effaa095c0418234cc33cc3`
- Deployment method: private versioned S3 `TemplateURL`
- Probe default: disabled
- Local acceptance date: 2026-07-30

## Independent acceptance

Two isolated, read-only reviews reached the same bounded verdict:

- Security: clear for a controlled live deployment attempt; the former
  envelope-supplied-key substitution weakness is closed by independent exact
  KMS public-key retrieval and signed key bindings.
- Build integrity: clear; the former timezone-dependent ZIP and stale-generated
  template receipt weaknesses are closed.

Neither review used AWS credentials or changed a cloud resource.

## Verification performed

- Exact-commit test suite: 47 of 47 passed.
- QA repeated the complete suite ten consecutive times.
- All 43 JavaScript/CommonJS files passed syntax checks.
- Generated templates exactly matched their builders.
- `cfn-lint 1.53.3` passed both generated templates from an isolated temporary
  environment that was removed after the check.
- `npm ls --all` was valid and `npm audit` reported zero known
  vulnerabilities.
- A tracked-file credential-pattern scan found no likely AWS access key,
  private key, or OpenAI secret.
- SDK-fake integration exercised the actual Agent, Boundary, and Signer
  handlers across success, rejected Bedrock output, and unavailable KMS
  public-key paths.
- The four-role probe matrix, static IAM/API checks, generated-template
  references, and intrinsic structure passed.
- A synthetic stale-template commit was rejected before artifact creation.
- Template-only mode remained explicitly unbound and created no artifact.

Provider advisory freshness and cross-operating-system reproducibility remain
outside this receipt.

## Bound templates

| Template | SHA-256 | Canonical SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `infra/aws/bootstrap-template.json` | `63b7fdb71319df83dfae2b14eeb3df5f77d386a5c8a6166f7cad3e4a3443c95c` | `e5f5edf08f91a0199e39ae9703b769cc7952faaf69e25047dd91153024d7c231` | 5,508 |
| `infra/aws/gate2-template.json` | `d43bd84723894a3540e105426bc7491afb8eab62afb4ccf400ced205cb549b08` | `5b2e904074f37021df03f893cc3dba902ac106c5f3a14dd16a5bde8aa0dcd04e` | 69,048 |

The pretty Gate Two template exceeds CloudFormation's 51,200-byte inline
limit. Ad hoc minification is not the accepted evidence path.

## Clean-build artifacts

The `tideproof.gate2-build.v2` receipt reported
`CLEAN_ARTIFACT_BUILD`, `workingTreeClean: true`, and
`workingTreeCleanBeforeGeneration: true`.

| Role | ZIP SHA-256 | Lambda `CodeSha256` | Bytes |
| --- | --- | --- | ---: |
| Agent | `ff25d9779163c722efc9809ba42ed96e77028a76e8893433babed92add2c797d` | `/yXZd5FjxyLvyYCbpC7ZbncCinboiTQzur7ZKt0seX0=` | 1,149,839 |
| Authority | `af46779e2e488850b3d09d7830ad8496991920b9ace5ac416bdf33a80a5ac719` | `r0Z3ni5IiFCz0J14MK2ElpkZILms5axBa98zqApaxxk=` | 984 |
| Boundary | `6b3d8f872f7900ef78e31dc6c021dadcb2ea515c51688549b945d97a5553d26b` | `az2Phy95AO944x3GwCHa3LLqUVxRaIVJuUXZelVT0ms=` | 1,384,367 |
| Probe | `0b27a7501241135fc8d8c46c4bef0d9621481eeeb455dfed095845ef29bdf5ae` | `CyenUBJBE1/I2MRsS+8NliFIHu60Vd/tCVhF7ym99a4=` | 1,569,870 |
| Signer | `97bda026444d57431cf59306b5a38a3038da4eabb811e72b10afe44824b41804` | `l72gJkRNV0Mc9ZMGtaOKMDjaTqu4EecrEK/kSCS0GAQ=` | 1,130,986 |

The full receipt and every artifact byte were identical under `TZ=UTC`,
`TZ=America/New_York`, and `TZ=America/Los_Angeles`. Every ZIP passed
`unzip -t`, contained only stored `index.js`, used fixed
`2026-07-30 00:00:00` metadata, and recorded mode `0644`. A separate offline
clean install reproduced the bytes.

The disposable validation worktrees and temporary validator environment were
removed after their results were captured.

## Remaining live gates

Live acceptance still requires:

1. AWS service-side template validation and stack creation from the exact
   versioned template object.
2. Reported Lambda `CodeSha256`, alias, role, concurrency, and configuration
   reconciliation.
3. Exact-role IAM allow/deny probes and verified probe teardown.
4. A dedicated caller-role API invocation, denied direct Lambda invocations,
   and one unambiguous private access-log match.
5. KMS key/public-key/signature verification and one bounded Nova Micro
   proposal.
6. Post-run Gate One state hashes proving no authority, fence, outbox, or
   protected synthetic-effect change.

A missing log, missing receipt, timeout, malformed result, or unavailable
dependency means `UNKNOWN_DO_NOT_ACT`. External-service tail latency can
produce a transport timeout before a structured signed failure receipt.
Budgets and alarms are notifications, not automatic shutdown.
