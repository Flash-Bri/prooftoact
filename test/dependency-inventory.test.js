import assert from "node:assert/strict";
import {
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  renderDependencyInventory,
  verifyDependencyInventory
} from "../scripts/verify-dependency-inventory.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

function fixtureRoot(context) {
  const root = mkdtempSync(path.join(tmpdir(), "tideproof-dependencies-"));
  mkdirSync(path.join(root, "docs"));
  for (const relativePath of [
    "package.json",
    "package-lock.json",
    "docs/DEPENDENCY_INVENTORY.md"
  ]) {
    cpSync(
      new URL(`../${relativePath}`, import.meta.url),
      path.join(root, relativePath)
    );
  }
  context.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test("locked dependency inventory matches every reviewed package record", () => {
  const receipt = verifyDependencyInventory({ rootDir: ROOT });

  assert.equal(receipt.status, "PASS");
  assert.equal(receipt.packageCount, 71);
  assert.equal(receipt.runtimeCount, 44);
  assert.equal(receipt.developmentOnlyCount, 27);
  assert.equal(receipt.optionalCount, 27);
  assert.equal(receipt.installScriptCount, 1);
  assert.deepEqual(receipt.licenses, {
    "0BSD": 1,
    "Apache-2.0": 28,
    ISC: 2,
    MIT: 40
  });
});

test("inventory renderer is deterministic", () => {
  const first = renderDependencyInventory({ rootDir: ROOT });
  const second = renderDependencyInventory({ rootDir: ROOT });

  assert.equal(first.content, second.content);
  assert.match(first.content, /Package lock SHA-256: `[0-9a-f]{64}`/);
  assert.match(
    first.content,
    /\| `esbuild` \| `0\.28\.1` \| `node_modules\/esbuild` \| development-only \| no \| yes \| `MIT` \|/
  );
});

test("unreviewed dependency licenses fail closed", (context) => {
  const root = fixtureRoot(context);
  const lockPath = path.join(root, "package-lock.json");
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  lock.packages["node_modules/pg"].license = "GPL-3.0-only";
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  assert.throws(
    () => verifyDependencyInventory({ rootDir: root }),
    /unreviewed license: GPL-3\.0-only/
  );
});

test("package declarations must match the lock root", (context) => {
  const root = fixtureRoot(context);
  const lockPath = path.join(root, "package-lock.json");
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  lock.packages[""].dependencies.pg = "8.21.0";
  writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  assert.throws(
    () => verifyDependencyInventory({ rootDir: root }),
    /dependencies differ across package\.json and package-lock\.json/
  );
});

test("stale generated inventory fails closed", (context) => {
  const root = fixtureRoot(context);
  const inventoryPath = path.join(root, "docs/DEPENDENCY_INVENTORY.md");
  writeFileSync(
    inventoryPath,
    `${readFileSync(inventoryPath, "utf8")}stale\n`
  );

  assert.throws(
    () => verifyDependencyInventory({ rootDir: root }),
    /does not match the exact locked dependency inventory/
  );
});
