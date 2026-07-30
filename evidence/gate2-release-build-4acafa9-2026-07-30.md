# Gate Two release build and live handoff — `4acafa9`

## Claim boundary

This receipt binds exact clean commit
`4acafa99f4b7908f4cc05216bcb05c5d06cd0158` to a fresh reproducible Gate Two
build. It is not evidence of a main AWS stack, artifact upload, Bedrock
inference, KMS signing, IAM denial, API traversal, or current AWS spend.

- Build observed: `2026-07-30T18:28:06Z`
- Source tree: `c63d27433dabd59656da3d1a5f36ecce070409de`
- Package-lock SHA-256:
  `fe1e765145a7bb2e0ee0cadce2e646b7d792c447aee37f010d40453405fd08d9`
- Build receipt mode: `CLEAN_ARTIFACT_BUILD`
- Clean before and after template generation: `true`

The Gate Two implementation, generator, lockfile, and associated tests are
byte-unchanged from the independently accepted `9aa7f2e` candidate. The
fresh build produced the same template and artifact bytes while binding the
new source commit and tree.

## Verification

- Exact-head test suite: 47 of 47 passed.
- `npm run build:gate2` accepted the clean tree.
- All five ZIPs passed `unzip -tq` independently.
- The tracked tree remained clean after generation and build.
- Gate Two formatted template SHA-256:
  `d43bd84723894a3540e105426bc7491afb8eab62afb4ccf400ced205cb549b08`
- Gate Two canonical template SHA-256:
  `5b2e904074f37021df03f893cc3dba902ac106c5f3a14dd16a5bde8aa0dcd04e`

An initial multi-argument `unzip` invocation returned exit 11 because `unzip`
treated the later archive paths as member filters for the first archive. It
did not produce an integrity verdict. The required check was then rerun one
archive at a time, and every archive passed.

| Role | ZIP SHA-256 | Lambda `CodeSha256` | Bytes |
| --- | --- | --- | ---: |
| Agent | `ff25d9779163c722efc9809ba42ed96e77028a76e8893433babed92add2c797d` | `/yXZd5FjxyLvyYCbpC7ZbncCinboiTQzur7ZKt0seX0=` | 1,149,839 |
| Authority | `af46779e2e488850b3d09d7830ad8496991920b9ace5ac416bdf33a80a5ac719` | `r0Z3ni5IiFCz0J14MK2ElpkZILms5axBa98zqApaxxk=` | 984 |
| Boundary | `6b3d8f872f7900ef78e31dc6c021dadcb2ea515c51688549b945d97a5553d26b` | `az2Phy95AO944x3GwCHa3LLqUVxRaIVJuUXZelVT0ms=` | 1,384,367 |
| Probe | `0b27a7501241135fc8d8c46c4bef0d9621481eeeb455dfed095845ef29bdf5ae` | `CyenUBJBE1/I2MRsS+8NliFIHu60Vd/tCVhF7ym99a4=` | 1,569,870 |
| Signer | `97bda026444d57431cf59306b5a38a3038da4eabb811e72b10afe44824b41804` | `l72gJkRNV0Mc9ZMGtaOKMDjaTqu4EecrEK/kSCS0GAQ=` | 1,130,986 |

## Live AWS observation

A read-only, signed-in AWS Console check in `us-east-1` showed:

- the existing Tideproof bootstrap stack at `UPDATE_COMPLETE`;
- no main Gate Two stack in the stack list;
- AWS CloudShell refusing to create an environment because account
  verification remains in progress, with AWS advising that new-account
  verification may take up to two days.

The isolated runtime had no configured programmatic AWS credential. No
credential was created, extracted, pasted, or reused, and no AWS resource was
mutated during this check. The current budget values and Bedrock model
availability were therefore not revalidated and remain mandatory predeployment
checks.

## Handoff gate

Do not upload or deploy until AWS account verification is complete and a
project-specific authenticated deployment lane can:

1. revalidate the `$15` budget, `$1`/`$5`/`$10` actual alerts, `$15` forecast
   alert, and current spend;
2. revalidate Nova Micro availability and price in `us-east-1`;
3. upload these exact bytes once to the private versioned bucket;
4. preserve every S3 version ID and recompute the effective nonsecret
   configuration digest; and
5. execute the full live acceptance sequence in `docs/AWS_GATE2.md`.

Missing verification or unavailable access remains `UNKNOWN_DO_NOT_ACT`.
