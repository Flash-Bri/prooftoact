import assert from "node:assert/strict";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { buildGate2Template } from "../src/cloud/aws-gate2-template.js";
import {
  RELEASE_SECURITY_SURFACE_COUNT,
  __test,
  validateManifest,
  validateReleaseSecurityReceipt,
  verifyReleaseSecurity
} from "../scripts/verify-release-security.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const HEX = "a".repeat(64);

function fixtureManifest(overrides = {}) {
  return {
    schema: __test.MANIFEST_SCHEMA,
    status: __test.MANIFEST_STATUS,
    reviewedOn: "2026-07-31",
    claimBoundary: "Fixture static security boundary.",
    finalReleaseRequirements: [
      ...__test.EXPECTED_FINAL_RELEASE_REQUIREMENTS
    ],
    surfaces: Object.entries(__test.EXPECTED_SURFACES).map(
      ([id, surface]) => ({
        id,
        path: surface.path,
        role: surface.role,
        sha256: HEX
      })
    ),
    finalReleaseReady: false,
    ...overrides
  };
}

test("current source security and abuse boundaries match reviewed state", () => {
  const receipt = verifyReleaseSecurity({ rootDir: ROOT });
  assert.equal(receipt.status, "CURRENT_SOURCE_SECURITY_PASS");
  assert.equal(receipt.finalReleaseReady, false);
  assert.equal(receipt.surfaceCount, RELEASE_SECURITY_SURFACE_COUNT);
  assert.equal(receipt.publicPathCount, 10);
  assert.equal(receipt.securityHeaderCount, 9);
  assert.equal(receipt.negativeProbeCount, 6);
  assert.equal(receipt.publicRouteCount, 10);
  assert.equal(receipt.iamRoleCount, 9);
  assert.equal(receipt.lambdaPermissionCount, 3);
  assert.equal(receipt.boundedFunctionCount, 5);
  assert.equal(receipt.logGroupCount, 11);
  assert.equal(
    Object.values(receipt.checks).every((value) => value === true),
    true
  );
});

test("security receipt contract is shared and rejects stale surface counts", () => {
  const receipt = verifyReleaseSecurity({ rootDir: ROOT });
  assert.equal(validateReleaseSecurityReceipt(receipt), receipt);
  for (const offset of [-1, 1]) {
    const stale = structuredClone(receipt);
    stale.surfaceCount = RELEASE_SECURITY_SURFACE_COUNT + offset;
    assert.throws(
      () => validateReleaseSecurityReceipt(stale),
      /RELEASE_SECURITY_RECEIPT_CONTRACT/
    );
  }
});

test("security manifest binds every AWS provider runtime and template-security control", () => {
  const surfaces = __test.EXPECTED_SURFACES;
  for (const [id, path] of [
    ["aws-provider-bundle-entry", "scripts/lib/aws-provider-bundle-entry.js"],
    ["aws-provider-runtime", "scripts/lib/aws-provider-runtime.js"],
    [
      "aws-provider-runtime-loader",
      "scripts/lib/aws-provider-runtime-loader.js"
    ],
    ["aws-provider-clients-tests", "test/aws-provider-clients.test.js"],
    [
      "aws-template-security-tests",
      "test/aws-gate2-template-security.test.js"
    ]
  ]) {
    assert.equal(surfaces[id]?.path, path);
    assert.equal(__test.SOURCE_MARKERS[id]?.length > 0, true);
  }
});

test("security manifest binds local evidence generation and verification code", () => {
  const surfaces = __test.EXPECTED_SURFACES;
  for (const [id, path] of [
    ["local-full-drill-harness", "src/local-full-drill.js"],
    [
      "local-full-drill-receipt-verifier",
      "scripts/verify-local-full-drill-receipt.js"
    ],
    ["local-full-drill-runner", "scripts/run-local-full-drills.js"],
    ["local-full-drill-tests", "test/local-full-drill.test.js"],
    ["proof-manifest-tests", "test/proof-manifest.test.js"],
    ["proof-manifest-verifier", "scripts/verify-proof-manifest.js"]
  ]) {
    assert.equal(surfaces[id]?.path, path);
    assert.equal(__test.SOURCE_MARKERS[id]?.length > 0, true);
  }
});

test("security manifest rejects final approval and changed surface contract", () => {
  assert.equal(validateManifest(fixtureManifest()).finalReleaseReady, false);
  assert.throws(
    () => validateManifest(fixtureManifest({ finalReleaseReady: true })),
    /RELEASE_SECURITY_MANIFEST_BOUNDARY/
  );
  const changed = fixtureManifest();
  changed.surfaces[0].path = "infra/aws/lambda/other.cjs";
  assert.throws(
    () => validateManifest(changed),
    /RELEASE_SECURITY_MANIFEST_SURFACE/
  );
});

test("security template contract rejects public route or CORS expansion", () => {
  const routeExpanded = structuredClone(buildGate2Template());
  routeExpanded.Resources.UnreviewedRoute = {
    Type: "AWS::ApiGatewayV2::Route",
    Properties: {
      ApiId: { Ref: "HttpApi" },
      RouteKey: "GET /unreviewed",
      AuthorizationType: "NONE"
    }
  };
  assert.throws(
    () => __test.assertTemplateContract(routeExpanded, routeExpanded),
    /RELEASE_SECURITY_PUBLIC_ROUTES/
  );

  const corsExpanded = structuredClone(buildGate2Template());
  corsExpanded.Resources.HttpApi.Properties.CorsConfiguration = {
    AllowOrigins: ["*"]
  };
  assert.throws(
    () => __test.assertTemplateContract(corsExpanded, corsExpanded),
    /RELEASE_SECURITY_PUBLIC_API/
  );
});

test("security template contract rejects new public-demo capability", () => {
  const template = structuredClone(buildGate2Template());
  template.Resources.DemoRole.Properties.Policies[0].PolicyDocument.Statement.push(
    {
      Sid: "UnreviewedCapability",
      Effect: "Allow",
      Action: "s3:GetObject",
      Resource: "*"
    }
  );
  assert.throws(
    () => __test.assertTemplateContract(template, template),
    /RELEASE_SECURITY_DemoRole_ALLOW/
  );
});

test("security source contract rejects a removed fail-closed marker", () => {
  assert.equal(
    Object.keys(__test.SOURCE_MARKERS).length,
    RELEASE_SECURITY_SURFACE_COUNT
  );
  const sources = new Map(
    Object.entries(__test.SOURCE_MARKERS).map(([id, markers]) => [
      id,
      markers.join("\n")
    ])
  );
  assert.equal(__test.assertSourceMarkers(sources), true);
  sources.set("managed-mcp-client", "redirect: \"follow\"");
  assert.throws(
    () => __test.assertSourceMarkers(sources),
    /RELEASE_SECURITY_MARKER_MANAGED_MCP_CLIENT/
  );
  sources.set(
    "managed-mcp-client",
    __test.SOURCE_MARKERS["managed-mcp-client"].join("\n")
  );
  sources.set(
    "primary-security-bootstrap",
    `${sources.get("primary-security-bootstrap")}\n${
      __test.FORBIDDEN_SOURCE_MARKERS["primary-security-bootstrap"][0]
    }`
  );
  assert.throws(
    () => __test.assertSourceMarkers(sources),
    /RELEASE_SECURITY_FORBIDDEN_MARKER_PRIMARY_SECURITY_BOOTSTRAP/
  );
});

test("public verifier contract remains exact", () => {
  assert.deepEqual(__test.assertRuntimeContract(), {
    publicPathCount: 10,
    securityHeaderCount: 9,
    negativeProbeCount: 6
  });
});
