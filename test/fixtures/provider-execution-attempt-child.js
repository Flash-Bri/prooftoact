import { __test } from
  "../../src/cloud/integrated-live-drill-provider-recovery.js";

const result = __test.claimCreateOnlyExactForTest({
  filePath: process.env.EXECUTION_ATTEMPT_PATH,
  forbiddenRootPath: process.env.EXECUTION_FORBIDDEN_ROOT,
  rootPath: process.env.EXECUTION_EVIDENCE_ROOT,
  value: Object.freeze({
    authorizationId: "11111111-1111-4111-8111-111111111111",
    marker: "provider-execution-attempt-fence-v1"
  })
});

process.stdout.write(`${JSON.stringify({ created: result.created })}\n`);
