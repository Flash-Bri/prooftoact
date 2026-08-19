# Locked dependency inventory

**Status: CURRENT LOCK + AUTOMATED RELEASE PROVENANCE CONTROL — final deployed-bundle audit pending**

This inventory is generated deterministically from `package.json` and
`package-lock.json`. It records the complete locked npm package set,
dependency class, package-lock license identifier, optional-package state,
and install-script flag. The verifier rejects ranges in direct declarations,
non-registry sources, missing SHA-512 integrity, deprecated packages, and
licenses outside the explicitly reviewed identifier set.

This is a provenance and review control, not legal advice or an independent
verification of every upstream copyright statement. The exact package union
and normalized license texts present in the Gate Two bundles are controlled by
`THIRD_PARTY_NOTICES.txt` and `npm run licenses:verify`. On official `main`,
`npm run release:provenance` additionally rejects shallow or replaced history,
an unexpected clean-room root, tracked symlinks or submodules, and installed
package identities that differ from the lock. The final release must rerun the
combined control and bind its clean vulnerability report, uploaded object
versions, and deployed Lambda `CodeSha256` values before submission.

## Bound source

- Package lock SHA-256: `6a96582e5e9fd3a488c41b729878345933ec57e9a5b90814d4c19016bb5ef58d`
- Direct runtime declarations: **11**
- Direct development declarations: **2**
- Complete locked package records: **82**
- Runtime package records: **54**
- Development-only package records: **28**
- Optional platform package records: **27**
- Packages declaring an install script: **1**
- Reviewed package-lock license identifiers: 0BSD: 1; Apache-2.0: 36; ISC: 2; MIT: 42; MPL-2.0: 1
- CI install boundary: `npm ci --ignore-scripts`; the deterministic Gate Two
  build separately proves the exact bundled artifacts and embeds the verified
  third-party notice file in every ZIP.

## Direct declarations

| Package | Declared | Locked | Use | License |
| --- | --- | --- | --- | --- |
| `@aws-sdk/client-apigatewayv2` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-bedrock-runtime` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-cloudformation` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-dynamodb` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-iam` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-kms` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-lambda` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-secrets-manager` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@aws-sdk/client-sts` | `3.1098.0` | `3.1098.0` | runtime | `Apache-2.0` |
| `@smithy/node-http-handler` | `4.9.13` | `4.9.13` | runtime | `Apache-2.0` |
| `axe-core` | `4.12.1` | `4.12.1` | development-only | `MPL-2.0` |
| `esbuild` | `0.28.1` | `0.28.1` | development-only | `MIT` |
| `pg` | `8.22.0` | `8.22.0` | runtime | `MIT` |

## Complete locked package set

| Package | Version | Lock path | Use | Optional | Install script | License |
| --- | --- | --- | --- | --- | --- | --- |
| `@aws-sdk/client-apigatewayv2` | `3.1098.0` | `node_modules/@aws-sdk/client-apigatewayv2` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-bedrock-runtime` | `3.1098.0` | `node_modules/@aws-sdk/client-bedrock-runtime` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-cloudformation` | `3.1098.0` | `node_modules/@aws-sdk/client-cloudformation` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-dynamodb` | `3.1098.0` | `node_modules/@aws-sdk/client-dynamodb` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-iam` | `3.1098.0` | `node_modules/@aws-sdk/client-iam` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-kms` | `3.1098.0` | `node_modules/@aws-sdk/client-kms` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-lambda` | `3.1098.0` | `node_modules/@aws-sdk/client-lambda` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-secrets-manager` | `3.1098.0` | `node_modules/@aws-sdk/client-secrets-manager` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/client-sts` | `3.1098.0` | `node_modules/@aws-sdk/client-sts` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/core` | `3.977.8` | `node_modules/@aws-sdk/core` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-env` | `3.972.64` | `node_modules/@aws-sdk/credential-provider-env` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-http` | `3.972.66` | `node_modules/@aws-sdk/credential-provider-http` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-ini` | `3.973.9` | `node_modules/@aws-sdk/credential-provider-ini` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-login` | `3.972.71` | `node_modules/@aws-sdk/credential-provider-login` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-node` | `3.972.75` | `node_modules/@aws-sdk/credential-provider-node` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-process` | `3.972.64` | `node_modules/@aws-sdk/credential-provider-process` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-sso` | `3.973.8` | `node_modules/@aws-sdk/credential-provider-sso` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/credential-provider-web-identity` | `3.972.70` | `node_modules/@aws-sdk/credential-provider-web-identity` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/dynamodb-codec` | `3.973.43` | `node_modules/@aws-sdk/dynamodb-codec` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/endpoint-cache` | `3.972.11` | `node_modules/@aws-sdk/endpoint-cache` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/eventstream-handler-node` | `3.972.31` | `node_modules/@aws-sdk/eventstream-handler-node` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/middleware-endpoint-discovery` | `3.972.29` | `node_modules/@aws-sdk/middleware-endpoint-discovery` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/middleware-eventstream` | `3.972.26` | `node_modules/@aws-sdk/middleware-eventstream` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/middleware-websocket` | `3.972.46` | `node_modules/@aws-sdk/middleware-websocket` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/nested-clients` | `3.997.38` | `node_modules/@aws-sdk/nested-clients` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/signature-v4-multi-region` | `3.996.43` | `node_modules/@aws-sdk/signature-v4-multi-region` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/token-providers` | `3.1098.0` | `node_modules/@aws-sdk/token-providers` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/types` | `3.974.4` | `node_modules/@aws-sdk/types` | runtime | no | no | `Apache-2.0` |
| `@aws-sdk/xml-builder` | `3.972.39` | `node_modules/@aws-sdk/xml-builder` | runtime | no | no | `Apache-2.0` |
| `@aws/lambda-invoke-store` | `0.3.0` | `node_modules/@aws/lambda-invoke-store` | runtime | no | no | `Apache-2.0` |
| `@esbuild/aix-ppc64` | `0.28.1` | `node_modules/@esbuild/aix-ppc64` | development-only | yes | no | `MIT` |
| `@esbuild/android-arm` | `0.28.1` | `node_modules/@esbuild/android-arm` | development-only | yes | no | `MIT` |
| `@esbuild/android-arm64` | `0.28.1` | `node_modules/@esbuild/android-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/android-x64` | `0.28.1` | `node_modules/@esbuild/android-x64` | development-only | yes | no | `MIT` |
| `@esbuild/darwin-arm64` | `0.28.1` | `node_modules/@esbuild/darwin-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/darwin-x64` | `0.28.1` | `node_modules/@esbuild/darwin-x64` | development-only | yes | no | `MIT` |
| `@esbuild/freebsd-arm64` | `0.28.1` | `node_modules/@esbuild/freebsd-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/freebsd-x64` | `0.28.1` | `node_modules/@esbuild/freebsd-x64` | development-only | yes | no | `MIT` |
| `@esbuild/linux-arm` | `0.28.1` | `node_modules/@esbuild/linux-arm` | development-only | yes | no | `MIT` |
| `@esbuild/linux-arm64` | `0.28.1` | `node_modules/@esbuild/linux-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/linux-ia32` | `0.28.1` | `node_modules/@esbuild/linux-ia32` | development-only | yes | no | `MIT` |
| `@esbuild/linux-loong64` | `0.28.1` | `node_modules/@esbuild/linux-loong64` | development-only | yes | no | `MIT` |
| `@esbuild/linux-mips64el` | `0.28.1` | `node_modules/@esbuild/linux-mips64el` | development-only | yes | no | `MIT` |
| `@esbuild/linux-ppc64` | `0.28.1` | `node_modules/@esbuild/linux-ppc64` | development-only | yes | no | `MIT` |
| `@esbuild/linux-riscv64` | `0.28.1` | `node_modules/@esbuild/linux-riscv64` | development-only | yes | no | `MIT` |
| `@esbuild/linux-s390x` | `0.28.1` | `node_modules/@esbuild/linux-s390x` | development-only | yes | no | `MIT` |
| `@esbuild/linux-x64` | `0.28.1` | `node_modules/@esbuild/linux-x64` | development-only | yes | no | `MIT` |
| `@esbuild/netbsd-arm64` | `0.28.1` | `node_modules/@esbuild/netbsd-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/netbsd-x64` | `0.28.1` | `node_modules/@esbuild/netbsd-x64` | development-only | yes | no | `MIT` |
| `@esbuild/openbsd-arm64` | `0.28.1` | `node_modules/@esbuild/openbsd-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/openbsd-x64` | `0.28.1` | `node_modules/@esbuild/openbsd-x64` | development-only | yes | no | `MIT` |
| `@esbuild/openharmony-arm64` | `0.28.1` | `node_modules/@esbuild/openharmony-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/sunos-x64` | `0.28.1` | `node_modules/@esbuild/sunos-x64` | development-only | yes | no | `MIT` |
| `@esbuild/win32-arm64` | `0.28.1` | `node_modules/@esbuild/win32-arm64` | development-only | yes | no | `MIT` |
| `@esbuild/win32-ia32` | `0.28.1` | `node_modules/@esbuild/win32-ia32` | development-only | yes | no | `MIT` |
| `@esbuild/win32-x64` | `0.28.1` | `node_modules/@esbuild/win32-x64` | development-only | yes | no | `MIT` |
| `@smithy/core` | `3.31.1` | `node_modules/@smithy/core` | runtime | no | no | `Apache-2.0` |
| `@smithy/credential-provider-imds` | `4.4.16` | `node_modules/@smithy/credential-provider-imds` | runtime | no | no | `Apache-2.0` |
| `@smithy/fetch-http-handler` | `5.6.13` | `node_modules/@smithy/fetch-http-handler` | runtime | no | no | `Apache-2.0` |
| `@smithy/node-http-handler` | `4.9.13` | `node_modules/@smithy/node-http-handler` | runtime | no | no | `Apache-2.0` |
| `@smithy/signature-v4` | `5.6.12` | `node_modules/@smithy/signature-v4` | runtime | no | no | `Apache-2.0` |
| `@smithy/types` | `4.16.1` | `node_modules/@smithy/types` | runtime | no | no | `Apache-2.0` |
| `axe-core` | `4.12.1` | `node_modules/axe-core` | development-only | no | no | `MPL-2.0` |
| `bowser` | `2.14.1` | `node_modules/bowser` | runtime | no | no | `MIT` |
| `esbuild` | `0.28.1` | `node_modules/esbuild` | development-only | no | yes | `MIT` |
| `mnemonist` | `0.38.3` | `node_modules/mnemonist` | runtime | no | no | `MIT` |
| `obliterator` | `1.6.1` | `node_modules/obliterator` | runtime | no | no | `MIT` |
| `pg` | `8.22.0` | `node_modules/pg` | runtime | no | no | `MIT` |
| `pg-cloudflare` | `1.4.0` | `node_modules/pg-cloudflare` | runtime | yes | no | `MIT` |
| `pg-connection-string` | `2.14.0` | `node_modules/pg-connection-string` | runtime | no | no | `MIT` |
| `pg-int8` | `1.0.1` | `node_modules/pg-int8` | runtime | no | no | `ISC` |
| `pg-pool` | `3.14.0` | `node_modules/pg-pool` | runtime | no | no | `MIT` |
| `pg-protocol` | `1.15.0` | `node_modules/pg-protocol` | runtime | no | no | `MIT` |
| `pg-types` | `2.2.0` | `node_modules/pg-types` | runtime | no | no | `MIT` |
| `pgpass` | `1.0.5` | `node_modules/pgpass` | runtime | no | no | `MIT` |
| `postgres-array` | `2.0.0` | `node_modules/postgres-array` | runtime | no | no | `MIT` |
| `postgres-bytea` | `1.0.1` | `node_modules/postgres-bytea` | runtime | no | no | `MIT` |
| `postgres-date` | `1.0.7` | `node_modules/postgres-date` | runtime | no | no | `MIT` |
| `postgres-interval` | `1.2.0` | `node_modules/postgres-interval` | runtime | no | no | `MIT` |
| `split2` | `4.2.0` | `node_modules/split2` | runtime | no | no | `ISC` |
| `tslib` | `2.8.1` | `node_modules/tslib` | runtime | no | no | `0BSD` |
| `xtend` | `4.0.2` | `node_modules/xtend` | runtime | no | no | `MIT` |
