import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { __test } from "../scripts/lib/official-node-runtime.js";

test("official runtime node reader binds one stable regular executable", () => {
  const root = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-official-node-")
  ));
  try {
    const filePath = path.join(root, "node");
    const bytes = Buffer.from("synthetic-official-node");
    fs.writeFileSync(filePath, bytes, { mode: 0o700 });
    const expected = {
      "darwin-arm64": {
        sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
        version: "v22.23.1"
      }
    };
    const record = __test.readNodeRuntime({
      architecture: "arm64",
      filePath,
      platform: "darwin"
    }, expected);
    assert.equal(record.sha256, expected["darwin-arm64"].sha256);
    assert.equal(record.distribution, "nodejs.org-release-v22.23.1");

    fs.linkSync(filePath, path.join(root, "node-hardlink"));
    assert.throws(
      () => __test.readNodeRuntime({
        architecture: "arm64",
        filePath,
        platform: "darwin"
      }, expected),
      /OFFICIAL_NODE_RUNTIME_REJECTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("official runtime node reader rejects an unpinned platform or digest", () => {
  const root = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-official-node-negative-")
  ));
  try {
    const filePath = path.join(root, "node");
    fs.writeFileSync(filePath, "not-the-pinned-binary", { mode: 0o700 });
    assert.throws(
      () => __test.readNodeRuntime({
        architecture: "x64",
        filePath,
        platform: "linux"
      }, {
        "linux-x64": {
          sha256: "0".repeat(64),
          version: "v22.23.1"
        }
      }),
      /OFFICIAL_NODE_RUNTIME_REJECTED/u
    );
    assert.throws(
      () => __test.readNodeRuntime({
        architecture: "arm64",
        filePath,
        platform: "linux"
      }, {}),
      /OFFICIAL_NODE_RUNTIME_REJECTED/u
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
