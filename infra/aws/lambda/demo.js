import appJs from "../../../web/app.js?raw";
import faviconSvg from "../../../web/favicon.svg?raw";
import indexHtml from "../../../web/index.html?raw";
import stylesCss from "../../../web/styles.css?raw";
import claimsMarkdown from "../../../CLAIMS.md?raw";
import authorityEvidence from "../../../evidence/gate1-authority-2026-07-30.md?raw";
import ambiguityEvidence from "../../../evidence/gate1-ambiguity-2026-07-30.md?raw";
import recoveryEvidence from "../../../evidence/gate1-recovery-broker-2026-07-30.md?raw";
import { createPublicDemoHandler } from "../../../src/cloud/public-demo.js";
import { runScenario } from "../../../src/scenario.js";

export const handler = createPublicDemoHandler({
  assets: {
    "/": indexHtml,
    "/app.js": appJs,
    "/styles.css": stylesCss,
    "/favicon.svg": faviconSvg,
    "/evidence/gate1-authority": authorityEvidence,
    "/evidence/gate1-recovery": recoveryEvidence,
    "/evidence/gate1-ambiguity": ambiguityEvidence,
    "/claims": claimsMarkdown
  },
  binding: {
    expectedApiId: process.env.EXPECTED_API_ID,
    sourceCommit: process.env.SOURCE_COMMIT,
    treeDigest: process.env.TREE_DIGEST,
    configDigest: process.env.CONFIG_DIGEST,
    demoSourceDigest: process.env.DEMO_SOURCE_DIGEST,
    demoArtifactDigest: process.env.DEMO_ARTIFACT_DIGEST,
    packageLockDigest: process.env.PACKAGE_LOCK_DIGEST,
    functionVersion: process.env.AWS_LAMBDA_FUNCTION_VERSION
  },
  runScenario
});
