#!/usr/bin/env node
import path from "node:path";

import { verifyHostedDualRootArtifact } from
  "./hosted-dual-root-verification.js";

function parse(arguments_) {
  const allowed = new Set([
    "--application-root", "--control-root", "--output-root"
  ]);
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!allowed.has(name) || values.has(name) ||
      typeof value !== "string" || !path.isAbsolute(value)) {
      throw new Error("HOSTED_DUAL_ROOT_VERIFY_ARGUMENT_REJECTED");
    }
    values.set(name, path.resolve(value));
  }
  if (values.size !== allowed.size) {
    throw new Error("HOSTED_DUAL_ROOT_VERIFY_ARGUMENT_REJECTED");
  }
  return values;
}

try {
  const values = parse(process.argv.slice(2));
  const result = verifyHostedDualRootArtifact({
    applicationRoot: values.get("--application-root"),
    controlRoot: values.get("--control-root"),
    outputRoot: values.get("--output-root")
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (cause) {
  const message = String(cause?.message ?? "");
  const code = /^HOSTED_DUAL_ROOT_[A-Z0-9_]{1,120}$/u.test(message)
    ? message : "HOSTED_DUAL_ROOT_VERIFY_UNKNOWN_HOLD";
  process.stderr.write(`HOLD:${code}\n`);
  process.exitCode = 1;
}
