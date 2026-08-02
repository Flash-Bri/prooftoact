import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  createBuildToolchain,
  createDependencySnapshot,
  validateBuildToolchain,
  validateDependencySnapshot
} from "../scripts/lib/dependency-snapshot.js";

const PACKAGE_JSON_DIGEST = "1".repeat(64);
const PACKAGE_LOCK_DIGEST = "2".repeat(64);

function fixture() {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-dependency-snapshot-")
  );
  fs.mkdirSync(path.join(root, "example", "lib"), { recursive: true });
  fs.writeFileSync(path.join(root, "example", "package.json"), "{}\n");
  fs.writeFileSync(
    path.join(root, "example", "lib", "index.js"),
    "export default true;\n"
  );
  return root;
}

test("dependency snapshot detects a tampered installed dependency byte", () => {
  const root = fixture();
  try {
    const first = createDependencySnapshot({
      dependencyRoot: root,
      packageJsonDigest: PACKAGE_JSON_DIGEST,
      packageLockDigest: PACKAGE_LOCK_DIGEST
    });
    assert.deepEqual(
      validateDependencySnapshot(first, {
        packageJsonDigest: PACKAGE_JSON_DIGEST,
        packageLockDigest: PACKAGE_LOCK_DIGEST
      }),
      first
    );
    fs.writeFileSync(
      path.join(root, "example", "lib", "index.js"),
      "export default false;\n"
    );
    const tampered = createDependencySnapshot({
      dependencyRoot: root,
      packageJsonDigest: PACKAGE_JSON_DIGEST,
      packageLockDigest: PACKAGE_LOCK_DIGEST
    });
    assert.notDeepEqual(tampered, first);
    assert.notEqual(tampered.treeDigest, first.treeDigest);
    assert.notEqual(tampered.totalBytes, first.totalBytes);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("dependency snapshot rejects installed-tree symlinks", () => {
  const root = fixture();
  try {
    fs.symlinkSync(
      path.join(root, "example", "package.json"),
      path.join(root, "example", "linked-package.json")
    );
    assert.throws(
      () =>
        createDependencySnapshot({
          dependencyRoot: root,
          packageJsonDigest: PACKAGE_JSON_DIGEST,
          packageLockDigest: PACKAGE_LOCK_DIGEST
        }),
      /DEPENDENCY_SNAPSHOT_SYMLINK/
    );
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});

test("build toolchain receipt requires executable and npm CLI digests", () => {
  const receipt = {
    schemaVersion: "tideproof.build-toolchain.v1",
    architecture: "arm64",
    nodeExecutableSha256: "3".repeat(64),
    nodeVersion: "v22.23.1",
    npmCliSha256: "4".repeat(64),
    npmPackageBytes: 1234,
    npmPackageFileCount: 12,
    npmPackageTreeDigest: "5".repeat(64),
    npmVersion: "11.6.2",
    platform: "darwin"
  };
  assert.deepEqual(validateBuildToolchain(receipt), receipt);
  assert.throws(
    () => validateBuildToolchain({ ...receipt, npmCliSha256: "0" }),
    /DEPENDENCY_SNAPSHOT_TOOLCHAIN/
  );
});

test("build toolchain binds the complete npm package tree", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "tideproof-build-toolchain-")
  );
  try {
    const npmRoot = path.join(root, "npm");
    const npmCli = path.join(npmRoot, "bin", "npm-cli.js");
    const nodeExecutable = path.join(root, "node");
    fs.mkdirSync(path.dirname(npmCli), { recursive: true });
    fs.writeFileSync(
      path.join(npmRoot, "package.json"),
      '{"name":"npm","version":"11.6.2"}\n'
    );
    fs.writeFileSync(npmCli, "export {};\n");
    fs.writeFileSync(nodeExecutable, "fixture-node\n");
    const first = createBuildToolchain({
      architecture: "arm64",
      nodeExecutable,
      nodeVersion: "v22.23.1",
      npmCli,
      platform: "darwin"
    });
    fs.writeFileSync(path.join(npmRoot, "lib.js"), "tampered\n");
    const changed = createBuildToolchain({
      architecture: "arm64",
      nodeExecutable,
      nodeVersion: "v22.23.1",
      npmCli,
      platform: "darwin"
    });
    assert.notEqual(first.npmPackageTreeDigest, changed.npmPackageTreeDigest);
  } finally {
    fs.rmSync(root, { force: true, recursive: true });
  }
});
