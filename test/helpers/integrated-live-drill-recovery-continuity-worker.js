import fs from "node:fs";
import path from "node:path";

import { canonicalJson } from "../../src/cloud/canonical-json.js";
import {
  runIntegratedLiveDrillRecoveryContinuityW1,
  runIntegratedLiveDrillRecoveryContinuityW2,
  runIntegratedLiveDrillRecoveryContinuityW3,
  runIntegratedLiveDrillRecoveryContinuityW4,
  runIntegratedLiveDrillRecoveryContinuityW5
} from
  "../../src/cloud/integrated-live-drill-recovery-continuity.js";

function argument(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const fixturePath = argument("--fixture");
const worker = argument("--worker");
const crashAfterEvent = argument("--crash-after");
const barrierDirectory = argument("--barrier-directory");
const noClient = process.argv.includes("--no-client");

if (!fixturePath || !worker) {
  throw new Error("TEST_RECOVERY_CONTINUITY_WORKER_ARGUMENT_REJECTED");
}

const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
const options = {
  now: fixture.now,
  ...(crashAfterEvent ? { crashAfterEvent } : {})
};

function waitAtBarrier(directory) {
  const readyPath = path.join(directory, `${process.pid}.ready`);
  const releasePath = path.join(directory, "release");
  fs.writeFileSync(readyPath, "ready\n", { flag: "wx", mode: 0o600 });
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(releasePath)) {
    if (Date.now() >= deadline) {
      throw new Error("TEST_RECOVERY_CONTINUITY_BARRIER_TIMEOUT");
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
  }
}

async function fakeMcpCall({ mcpRequestSha256 }) {
  const names = fs.readdirSync(fixture.context.ledgerRootPath)
    .filter((name) => name.includes(".recovery-continuity."));
  if (
    mcpRequestSha256 !== fixture.context.mcpRequestSha256 ||
    !names.some((name) => name.includes("06.mcp-call-claimed")) ||
    !names.some((name) => name.includes("07.mcp-dispatch-marker-durable"))
  ) {
    throw new Error("TEST_MCP_CALLED_BEFORE_DURABLE_CLAIM");
  }
  if (fixture.fakeDelayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, fixture.fakeDelayMs));
  }
  fs.appendFileSync(fixture.counterPath, "call\n", { mode: 0o600 });
  return {
    mcpResultSha256: "9".repeat(64),
    sessionCloseSha256: "8".repeat(64),
    sessionClosed: true
  };
}

let result;
switch (worker) {
  case "W1":
    result = runIntegratedLiveDrillRecoveryContinuityW1(
      fixture.context,
      options
    );
    break;
  case "W2":
    if (barrierDirectory) waitAtBarrier(barrierDirectory);
    result = await runIntegratedLiveDrillRecoveryContinuityW2(
      fixture.context,
      noClient ? options : { ...options, mcpCall: fakeMcpCall }
    );
    break;
  case "W3":
    result = runIntegratedLiveDrillRecoveryContinuityW3(
      fixture.context,
      options
    );
    break;
  case "W4":
    result = runIntegratedLiveDrillRecoveryContinuityW4(
      fixture.context,
      options
    );
    break;
  case "W5":
    result = runIntegratedLiveDrillRecoveryContinuityW5(
      fixture.context,
      options
    );
    break;
  default:
    throw new Error("TEST_RECOVERY_CONTINUITY_WORKER_REJECTED");
}

process.stdout.write(`${canonicalJson(result)}\n`);
