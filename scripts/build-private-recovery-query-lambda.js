import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { build } from "esbuild";

import { canonicalJson } from "../src/cloud/canonical-json.js";
import {
  buildPrivateRecoveryQueryTemplate,
  privateRecoveryQueryTemplateReceipt
} from "../src/cloud/private-recovery-query-template.js";
import {
  packageNamesFromMetafile,
  verifyBundledThirdPartyNotices
} from "./lib/bundled-third-party-notices.js";
import { writeDeterministicZip } from "./lib/deterministic-zip.js";
import { collectBundledPackageNames } from
  "./verify-bundled-third-party-notices.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

function reject(code, cause) {
  throw new Error(code, cause === undefined ? undefined : { cause });
}

function requireCondition(condition, code) {
  if (!condition) reject(code);
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export async function buildPrivateRecoveryQueryLambda(outputRoot) {
  const resolvedOutput = path.resolve(outputRoot);
  requireCondition(resolvedOutput !== root && !fs.existsSync(resolvedOutput),
    "PRIVATE_RECOVERY_QUERY_BUILD_OUTPUT_REJECTED");
  fs.mkdirSync(resolvedOutput, { recursive: true, mode: 0o700 });
  const bundlePath = path.join(resolvedOutput, "index.mjs");
  const result = await build({
    absWorkingDir: root,
    bundle: true,
    entryPoints: ["infra/aws/lambda/private-recovery-query.js"],
    external: [],
    format: "esm",
    legalComments: "none",
    logLevel: "silent",
    metafile: true,
    minify: false,
    outfile: bundlePath,
    packages: "bundle",
    platform: "node",
    sourcemap: false,
    target: "node22",
    treeShaking: true
  });
  const bundle = fs.readFileSync(bundlePath);
  requireCondition(bundle.length > 0 && bundle.length <= 20 * 1024 * 1024,
    "PRIVATE_RECOVERY_QUERY_BUILD_BUNDLE_REJECTED");
  const bundled = await collectBundledPackageNames({ rootDir: root });
  const notice = verifyBundledThirdPartyNotices({
    rootDir: root,
    packageNames: bundled.packageNames
  });
  const bundlePackages = packageNamesFromMetafile(result.metafile);
  requireCondition(notice.status === "PASS" &&
    canonicalJson(bundlePackages) ===
      canonicalJson(bundled.artifactPackages.privateRecoveryQuery),
  "PRIVATE_RECOVERY_QUERY_BUILD_NOTICE_REJECTED");
  const noticeBytes = fs.readFileSync(path.join(root, notice.noticePath));
  requireCondition(sha256(noticeBytes) === notice.noticeSha256,
    "PRIVATE_RECOVERY_QUERY_BUILD_NOTICE_REJECTED");
  const provisional = path.join(resolvedOutput, "private-recovery-query.zip");
  const archive = writeDeterministicZip(provisional, [
    { fileName: "THIRD_PARTY_NOTICES.txt", content: noticeBytes },
    { fileName: "index.mjs", content: bundle }
  ]);
  const artifactSha256 = sha256(archive);
  const artifactPath = path.join(
    resolvedOutput,
    `private-recovery-query-${artifactSha256}.zip`
  );
  fs.renameSync(provisional, artifactPath);
  const template = buildPrivateRecoveryQueryTemplate();
  const templatePath = path.join(
    resolvedOutput,
    "private-recovery-query-template.json"
  );
  fs.writeFileSync(templatePath, `${canonicalJson(template)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  const receiptBody = Object.freeze({
    schemaVersion: "prooftoact.private-recovery-query-build-receipt.v1",
    status: "PASS",
    artifactBytes: archive.length,
    artifactPath: path.basename(artifactPath),
    artifactSha256,
    artifactSha256Base64: crypto.createHash("sha256")
      .update(archive).digest("base64"),
    archiveEntryCount: 2,
    bundledPackages: bundlePackages,
    bundledInputCount: Object.keys(result.metafile.inputs).length,
    bundleBytes: bundle.length,
    bundleSha256: sha256(bundle),
    handler: "index.handler",
    noticeBytes: notice.noticeBytes,
    noticeSha256: notice.noticeSha256,
    templateReceipt: privateRecoveryQueryTemplateReceipt(),
    templateSha256: sha256(fs.readFileSync(templatePath))
  });
  const receipt = Object.freeze({
    ...receiptBody,
    receiptSha256: sha256(canonicalJson(receiptBody))
  });
  const receiptPath = path.join(
    resolvedOutput,
    "private-recovery-query-build-receipt.json"
  );
  fs.writeFileSync(receiptPath, `${canonicalJson(receipt)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx"
  });
  fs.rmSync(bundlePath);
  return receipt;
}

async function main() {
  requireCondition(process.argv.length === 3,
    "PRIVATE_RECOVERY_QUERY_BUILD_ARGUMENT_REJECTED");
  const receipt = await buildPrivateRecoveryQueryLambda(process.argv[2]);
  process.stdout.write(`${canonicalJson(receipt)}\n`);
}

const isDirect = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isDirect) {
  main().catch((cause) => {
    const code = /^PRIVATE_RECOVERY_QUERY_[A-Z0-9_]{1,100}$/u.test(
      cause?.message ?? ""
    ) ? cause.message : "PRIVATE_RECOVERY_QUERY_BUILD_UNKNOWN";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({ sha256 });
