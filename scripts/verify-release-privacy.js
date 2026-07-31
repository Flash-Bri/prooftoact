import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const MANIFEST_PATH = "RELEASE_PRIVACY_MANIFEST.json";
const SCHEMA = "tideproof.release-privacy-verification.v1";
const MAX_BLOB_BYTES = 5 * 1024 * 1024;
const MAX_HISTORY_BYTES = 128 * 1024 * 1024;
const HEX_40 = /^[0-9a-f]{40}$/;
const HEX_64 = /^[0-9a-f]{64}$/;
const ALLOWED_CLASSIFICATIONS = new Set([
  "PUBLIC_UPSTREAM_ATTRIBUTION",
  "SYNTHETIC_TEST_FIXTURE"
]);

const RULES = Object.freeze([
  Object.freeze({
    id: "pem-private-key",
    source:
      "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    flags: "g"
  }),
  Object.freeze({
    id: "aws-access-key",
    source: "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "github-token",
    source:
      "\\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "model-provider-key",
    source: "\\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "slack-token",
    source: "\\bxox[baprs]-[A-Za-z0-9-]{20,}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "google-api-key",
    source: "\\bAIza[0-9A-Za-z_-]{35}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "stripe-secret",
    source: "\\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "jwt",
    source:
      "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "basic-auth-url",
    source:
      "\\b(?:postgres(?:ql)?|cockroachdb|mysql|mongodb(?:\\+srv)?|redis):\\/\\/[^:\\s/@]+:[^@\\s/]+@[^ \\t\\r\\n\\\"'<>]+",
    flags: "gi"
  }),
  Object.freeze({
    id: "bearer-token",
    source: "\\bBearer[ \\t]+[A-Za-z0-9._~+/=-]{20,}",
    flags: "g"
  }),
  Object.freeze({
    id: "private-home-path",
    source:
      "(?:\\/Users\\/[A-Za-z0-9._-]+\\/|\\/home\\/[A-Za-z0-9._-]+\\/|[A-Za-z]:\\\\Users\\\\[^\\s\\\\]+\\\\)",
    flags: "g"
  }),
  Object.freeze({
    id: "private-ipv4",
    source:
      "\\b(?:10(?:\\.[0-9]{1,3}){3}|192\\.168(?:\\.[0-9]{1,3}){2}|172\\.(?:1[6-9]|2[0-9]|3[01])(?:\\.[0-9]{1,3}){2})\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "email-address",
    source:
      "\\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\\.[A-Za-z]{2,63}\\b",
    flags: "g"
  }),
  Object.freeze({
    id: "aws-account-id",
    source:
      "\\barn:aws(?:-[a-z]+)?:[a-z0-9-]*:[a-z0-9-]*:([0-9]{12}):",
    flags: "g",
    capture: 1
  })
]);

function assert(condition, code) {
  if (!condition) {
    throw new Error(code);
  }
}

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") ===
      [...keys].sort().join("\n")
  );
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeRelativePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    !path.isAbsolute(value) &&
    !value.split("/").some((part) => part === "" || part === "..")
  );
}

function sortedUnique(values) {
  return (
    new Set(values).size === values.length &&
    JSON.stringify(values) === JSON.stringify([...values].sort())
  );
}

export function validateManifest(value) {
  assert(
    exactKeys(value, [
      "allowedCommitIdentityDigests",
      "allowedFindings",
      "finalReleaseReady",
      "reviewedOn",
      "schema",
      "status",
      "syntheticAwsAccountIds"
    ]),
    "RELEASE_PRIVACY_MANIFEST_SHAPE"
  );
  assert(
    value.schema === "tideproof.release-privacy-manifest.v1" &&
      value.status ===
        "CURRENT_PUBLIC_HISTORY_REVIEWED_FINAL_RELEASE_PENDING" &&
      /^\d{4}-\d{2}-\d{2}$/.test(value.reviewedOn) &&
      value.finalReleaseReady === false,
    "RELEASE_PRIVACY_MANIFEST_BOUNDARY"
  );
  assert(
    Array.isArray(value.allowedFindings) &&
      value.allowedFindings.length > 0,
    "RELEASE_PRIVACY_MANIFEST_FINDINGS"
  );
  const findingKeys = value.allowedFindings.map((finding) => {
    assert(
      exactKeys(finding, [
        "classification",
        "matchSha256",
        "path",
        "rule"
      ]) &&
        RULES.some((rule) => rule.id === finding.rule) &&
        safeRelativePath(finding.path) &&
        HEX_64.test(finding.matchSha256) &&
        ALLOWED_CLASSIFICATIONS.has(finding.classification),
      "RELEASE_PRIVACY_MANIFEST_FINDING"
    );
    return `${finding.rule}\0${finding.path}\0${finding.matchSha256}`;
  });
  assert(
    sortedUnique(findingKeys),
    "RELEASE_PRIVACY_MANIFEST_FINDING_ORDER"
  );
  assert(
    Array.isArray(value.allowedCommitIdentityDigests) &&
      value.allowedCommitIdentityDigests.length > 0 &&
      value.allowedCommitIdentityDigests.every((digest) =>
        HEX_64.test(digest)
      ) &&
      sortedUnique(value.allowedCommitIdentityDigests),
    "RELEASE_PRIVACY_MANIFEST_IDENTITIES"
  );
  assert(
    Array.isArray(value.syntheticAwsAccountIds) &&
      value.syntheticAwsAccountIds.length > 0 &&
      value.syntheticAwsAccountIds.every((accountId) =>
        /^[0-9]{12}$/.test(accountId)
      ) &&
      sortedUnique(value.syntheticAwsAccountIds),
    "RELEASE_PRIVACY_MANIFEST_AWS_FIXTURES"
  );
  return value;
}

export function forbiddenTrackedPath(filePath) {
  const normalized = filePath.replaceAll("\\", "/");
  const parts = normalized.split("/");
  const base = parts.at(-1)?.toLowerCase() ?? "";
  if (parts.some((part) => [".aws", ".ssh"].includes(part.toLowerCase()))) {
    return true;
  }
  if (base.startsWith(".env") && base !== ".env.example") {
    return true;
  }
  if (
    [
      ".netrc",
      ".npmrc",
      ".pypirc",
      "credentials",
      "id_ed25519",
      "id_rsa"
    ].includes(base)
  ) {
    return true;
  }
  return /\.(?:jks|key|keystore|p12|pem|pfx)$/i.test(base);
}

export function scanBuffer(buffer, filePath) {
  assert(Buffer.isBuffer(buffer), "RELEASE_PRIVACY_SCAN_BUFFER");
  assert(
    Number.isSafeInteger(buffer.length) && buffer.length <= MAX_BLOB_BYTES,
    "RELEASE_PRIVACY_BLOB_SIZE"
  );
  const text = buffer.toString("latin1");
  const findings = [];
  for (const rule of RULES) {
    const pattern = new RegExp(rule.source, rule.flags);
    let match;
    while ((match = pattern.exec(text)) !== null) {
      const matchedValue = match[rule.capture ?? 0];
      findings.push({
        rule: rule.id,
        path: filePath,
        matchSha256: sha256(matchedValue),
        matchedValue,
        start: match.index,
        end: match.index + match[0].length
      });
      if (match[0].length === 0) {
        pattern.lastIndex += 1;
      }
    }
  }
  return findings.filter(
    (finding) =>
      finding.rule !== "email-address" ||
      !findings.some(
        (candidate) =>
          candidate.rule === "basic-auth-url" &&
          candidate.start <= finding.start &&
          candidate.end >= finding.end
      )
  );
}

export function reviewFindings(findings, manifest) {
  const usedAllowances = new Set();
  for (const finding of findings) {
    if (
      finding.rule === "aws-account-id" &&
      finding.path.startsWith("test/") &&
      manifest.syntheticAwsAccountIds.includes(finding.matchedValue)
    ) {
      continue;
    }
    const key = `${finding.rule}\0${finding.path}\0${finding.matchSha256}`;
    const allowed = manifest.allowedFindings.find(
      (entry) =>
        `${entry.rule}\0${entry.path}\0${entry.matchSha256}` === key
    );
    if (!allowed) {
      throw new Error(
        `RELEASE_PRIVACY_UNREVIEWED_FINDING:${finding.rule}:${finding.path}:${finding.matchSha256}`
      );
    }
    usedAllowances.add(key);
  }
  for (const entry of manifest.allowedFindings) {
    const key = `${entry.rule}\0${entry.path}\0${entry.matchSha256}`;
    assert(
      usedAllowances.has(key),
      "RELEASE_PRIVACY_STALE_FINDING_ALLOWANCE"
    );
  }
  return {
    findingCount: findings.length,
    allowedFindingCount: findings.length,
    allowanceCount: manifest.allowedFindings.length
  };
}

function defaultRunner(projectRoot) {
  return (command, args, options = {}) =>
    spawnSync(command, args, {
      cwd: projectRoot,
      encoding: Object.hasOwn(options, "encoding")
        ? options.encoding
        : "utf8",
      input: options.input,
      maxBuffer: options.maxBuffer ?? 160 * 1024 * 1024
    });
}

function checked(run, command, args, code, options = {}) {
  const result = run(command, args, options);
  assert(
    result && !result.error && result.status === 0,
    code
  );
  return result.stdout;
}

function textCommand(run, command, args, code, options = {}) {
  const output = checked(run, command, args, code, options);
  assert(typeof output === "string", `${code}_OUTPUT`);
  return output;
}

function loadManifest(rootDir) {
  const manifestBytes = fs.readFileSync(path.join(rootDir, MANIFEST_PATH));
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("RELEASE_PRIVACY_MANIFEST_JSON");
  }
  validateManifest(manifest);
  assert(
    manifestBytes.toString("utf8") ===
      `${JSON.stringify(manifest, null, 2)}\n`,
    "RELEASE_PRIVACY_MANIFEST_CANONICAL"
  );
  return { manifest, manifestSha256: sha256(manifestBytes) };
}

function parseBatch(buffer, expected) {
  assert(Buffer.isBuffer(buffer), "RELEASE_PRIVACY_BATCH_OUTPUT");
  const blobs = [];
  let offset = 0;
  for (const item of expected) {
    const newline = buffer.indexOf(0x0a, offset);
    assert(newline >= 0, "RELEASE_PRIVACY_BATCH_HEADER");
    const header = buffer.subarray(offset, newline).toString("ascii");
    const match = header.match(/^([0-9a-f]{40}) blob ([0-9]+)$/);
    assert(
      match && match[1] === item.oid && Number(match[2]) === item.size,
      "RELEASE_PRIVACY_BATCH_HEADER"
    );
    const start = newline + 1;
    const end = start + item.size;
    assert(
      end < buffer.length && buffer[end] === 0x0a,
      "RELEASE_PRIVACY_BATCH_BODY"
    );
    blobs.push({ ...item, body: buffer.subarray(start, end) });
    offset = end + 1;
  }
  assert(offset === buffer.length, "RELEASE_PRIVACY_BATCH_TRAILING");
  return blobs;
}

function readReachableBlobs(run) {
  const objectOutput = textCommand(
    run,
    "git",
    ["rev-list", "--objects", "HEAD"],
    "RELEASE_PRIVACY_REV_LIST"
  );
  const objectPaths = new Map();
  for (const line of objectOutput.trim().split("\n")) {
    const match = line.match(/^([0-9a-f]{40})(?: (.*))?$/);
    assert(match, "RELEASE_PRIVACY_REV_LIST_FORMAT");
    if (!objectPaths.has(match[1])) {
      objectPaths.set(match[1], match[2] ?? "");
    }
  }
  const objectIds = [...objectPaths.keys()];
  const batchInput = `${objectIds.join("\n")}\n`;
  const checkOutput = textCommand(
    run,
    "git",
    ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
    "RELEASE_PRIVACY_BATCH_CHECK",
    { input: batchInput }
  );
  const blobs = [];
  for (const line of checkOutput.trim().split("\n")) {
    const match = line.match(/^([0-9a-f]{40}) ([a-z]+) ([0-9]+)$/);
    assert(match, "RELEASE_PRIVACY_BATCH_CHECK_FORMAT");
    if (match[2] !== "blob") {
      continue;
    }
    const size = Number(match[3]);
    assert(
      Number.isSafeInteger(size) && size >= 0 && size <= MAX_BLOB_BYTES,
      "RELEASE_PRIVACY_HISTORY_BLOB_SIZE"
    );
    blobs.push({
      oid: match[1],
      path: objectPaths.get(match[1]) || "[reachable-history-blob]",
      size
    });
  }
  const totalBytes = blobs.reduce((sum, blob) => sum + blob.size, 0);
  assert(totalBytes <= MAX_HISTORY_BYTES, "RELEASE_PRIVACY_HISTORY_SIZE");
  const output = checked(
    run,
    "git",
    ["cat-file", "--batch"],
    "RELEASE_PRIVACY_BATCH_READ",
    {
      encoding: null,
      input: Buffer.from(`${blobs.map((blob) => blob.oid).join("\n")}\n`),
      maxBuffer: MAX_HISTORY_BYTES + blobs.length * 96
    }
  );
  return { blobs: parseBatch(output, blobs), totalBytes };
}

function reviewedCommitIdentities(run, manifest) {
  const output = textCommand(
    run,
    "git",
    ["log", "HEAD", "--format=%ae%x00%ce%x00"],
    "RELEASE_PRIVACY_COMMIT_IDENTITIES"
  );
  const identities = [
    ...new Set(
      output
        .split("\0")
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean)
    )
  ];
  const digests = identities.map((identity) => sha256(identity)).sort();
  assert(
    JSON.stringify(digests) ===
      JSON.stringify(manifest.allowedCommitIdentityDigests),
    "RELEASE_PRIVACY_COMMIT_IDENTITY"
  );
  return identities.length;
}

export function verifyReleasePrivacy({
  rootDir = ROOT,
  run = defaultRunner(rootDir)
} = {}) {
  const { manifest, manifestSha256 } = loadManifest(rootDir);
  const initialStatus = textCommand(
    run,
    "git",
    ["status", "--short"],
    "RELEASE_PRIVACY_GIT_STATUS"
  );
  assert(initialStatus.trim().length === 0, "RELEASE_PRIVACY_DIRTY_TREE");
  const shallow = textCommand(
    run,
    "git",
    ["rev-parse", "--is-shallow-repository"],
    "RELEASE_PRIVACY_GIT_SHALLOW"
  ).trim();
  assert(shallow === "false", "RELEASE_PRIVACY_SHALLOW_HISTORY");
  const sourceCommit = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD"],
    "RELEASE_PRIVACY_GIT_HEAD"
  ).trim();
  const treeDigest = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "RELEASE_PRIVACY_GIT_TREE"
  ).trim();
  assert(
    HEX_40.test(sourceCommit) && HEX_40.test(treeDigest),
    "RELEASE_PRIVACY_GIT_DIGEST"
  );

  const trackedOutput = checked(
    run,
    "git",
    ["ls-files", "-z"],
    "RELEASE_PRIVACY_TRACKED_FILES",
    { encoding: null }
  );
  assert(Buffer.isBuffer(trackedOutput), "RELEASE_PRIVACY_TRACKED_OUTPUT");
  const trackedFiles = trackedOutput
    .toString("utf8")
    .split("\0")
    .filter(Boolean);
  assert(trackedFiles.length > 0, "RELEASE_PRIVACY_TRACKED_EMPTY");
  assert(
    trackedFiles.every(
      (filePath) => safeRelativePath(filePath) && !forbiddenTrackedPath(filePath)
    ),
    "RELEASE_PRIVACY_TRACKED_PATH"
  );

  const currentFindings = [];
  let currentBytes = 0;
  for (const filePath of trackedFiles) {
    const absolutePath = path.join(rootDir, filePath);
    const stat = fs.lstatSync(absolutePath);
    assert(
      stat.isFile() && !stat.isSymbolicLink(),
      "RELEASE_PRIVACY_TRACKED_FILE"
    );
    assert(stat.size <= MAX_BLOB_BYTES, "RELEASE_PRIVACY_CURRENT_BLOB_SIZE");
    const body = fs.readFileSync(absolutePath);
    currentBytes += body.length;
    currentFindings.push(...scanBuffer(body, filePath));
  }

  const history = readReachableBlobs(run);
  const historyFindings = history.blobs.flatMap((blob) =>
    scanBuffer(blob.body, blob.path)
  );
  const reviewed = reviewFindings(
    [...currentFindings, ...historyFindings],
    manifest
  );
  const commitIdentityCount = reviewedCommitIdentities(run, manifest);
  const commitCount = Number(
    textCommand(
      run,
      "git",
      ["rev-list", "--count", "HEAD"],
      "RELEASE_PRIVACY_COMMIT_COUNT"
    ).trim()
  );
  assert(
    Number.isSafeInteger(commitCount) && commitCount > 0,
    "RELEASE_PRIVACY_COMMIT_COUNT"
  );

  const finalHead = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD"],
    "RELEASE_PRIVACY_FINAL_HEAD"
  ).trim();
  const finalTree = textCommand(
    run,
    "git",
    ["rev-parse", "HEAD^{tree}"],
    "RELEASE_PRIVACY_FINAL_TREE"
  ).trim();
  const finalStatus = textCommand(
    run,
    "git",
    ["status", "--short"],
    "RELEASE_PRIVACY_FINAL_STATUS"
  );
  assert(
    finalHead === sourceCommit &&
      finalTree === treeDigest &&
      finalStatus.trim().length === 0,
    "RELEASE_PRIVACY_CHECKOUT_CHANGED"
  );

  return {
    schemaVersion: SCHEMA,
    status: "CURRENT_PUBLIC_HISTORY_PASS",
    finalReleaseReady: false,
    reviewedOn: manifest.reviewedOn,
    sourceCommit,
    treeDigest,
    manifestPath: MANIFEST_PATH,
    manifestSha256,
    commitCount,
    commitIdentityCount,
    trackedFileCount: trackedFiles.length,
    reachableBlobCount: history.blobs.length,
    scannedBytes: currentBytes + history.totalBytes,
    findingCount: reviewed.findingCount,
    allowanceCount: reviewed.allowanceCount,
    checks: {
      canonicalManifest: true,
      cleanBeforeAndAfter: true,
      fullReachableHistory: true,
      trackedPathPolicy: true,
      everyReachableBlobScanned: true,
      highConfidenceSignaturesReviewed: true,
      commitIdentitiesReviewed: true
    },
    finalReleaseRequirements: [
      "Rerun on the exact final official-main commit and bind the PASS receipt to hosted CI and deployed artifact hashes.",
      "Complete a private human review for secrets, personal data, internal URLs, metadata, screenshots, video, and submission fields."
    ],
    claimBoundary:
      "This deterministic control scans every current tracked file and every size-bounded blob reachable from HEAD for a bounded set of high-confidence secret, credential, private-path, private-network, cloud-account, and email signatures; it also rejects credential-like tracked paths and unreviewed commit identity digests. Exact hash allowances cover only reviewed upstream license attribution and synthetic test fixtures. CURRENT_PUBLIC_HISTORY_PASS is not proof that no secret or personal data exists, does not scan unreachable objects or external systems, and does not replace the exact-release private human review."
  };
}

async function main() {
  assert(process.argv.length === 2, "RELEASE_PRIVACY_ARGUMENT");
  const receipt = verifyReleasePrivacy();
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
}

const startedDirectly =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (startedDirectly) {
  main().catch((error) => {
    const message = String(error?.message ?? "");
    const code = /^RELEASE_PRIVACY_[A-Z0-9_]{1,120}$/.test(message)
      ? message
      : "RELEASE_PRIVACY_UNKNOWN";
    process.stderr.write(`TIDEPROOF_RELEASE_PRIVACY_FAILED:${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  MAX_BLOB_BYTES,
  RULES,
  parseBatch,
  sha256
});
