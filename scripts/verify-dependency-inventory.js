import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = fileURLToPath(new URL("..", import.meta.url));
const INVENTORY_PATH = "docs/DEPENDENCY_INVENTORY.md";
const PACKAGE_PATH = "package.json";
const LOCK_PATH = "package-lock.json";
const RECEIPT_SCHEMA = "tideproof.dependency-inventory-verification.v1";
const ALLOWED_LICENSES = Object.freeze([
  "0BSD",
  "Apache-2.0",
  "ISC",
  "MIT"
]);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function readJson(filePath, label) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  assert(
    parsed && typeof parsed === "object" && !Array.isArray(parsed),
    `${label} must be an object`
  );
  return parsed;
}

function packageNameFromLockPath(lockPath) {
  assert(
    lockPath === lockPath.trim() &&
      !/[`|\\\r\n]/.test(lockPath) &&
      lockPath.split("/").every((segment) => segment !== "" && segment !== ".."),
    `unsafe package-lock path: ${lockPath}`
  );
  const marker = "node_modules/";
  const markerIndex = lockPath.lastIndexOf(marker);
  assert(markerIndex !== -1, `unsupported package-lock path: ${lockPath}`);
  const name = lockPath.slice(markerIndex + marker.length);
  assert(
    /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(name),
    `invalid package name derived from package-lock path: ${lockPath}`
  );
  return name;
}

function canonicalDependencyMap(value, label) {
  const map = value ?? {};
  assert(
    map && typeof map === "object" && !Array.isArray(map),
    `${label} must be an object`
  );
  return JSON.stringify(
    Object.entries(map).sort(([left], [right]) => left.localeCompare(right))
  );
}

function verifyRootPackage(packageJson, lock) {
  const root = lock.packages?.[""];
  assert(root && typeof root === "object", "package-lock root package is missing");
  for (const field of ["name", "version"]) {
    assert(
      packageJson[field] === root[field] && packageJson[field] === lock[field],
      `${field} differs across package.json and package-lock.json`
    );
  }
  assert(
    packageJson.license === root.license,
    "license differs across package.json and package-lock.json"
  );
  for (const group of ["dependencies", "devDependencies"]) {
    assert(
      canonicalDependencyMap(packageJson[group], `package.json ${group}`) ===
        canonicalDependencyMap(root[group], `package-lock root ${group}`),
      `${group} differ across package.json and package-lock.json`
    );
  }
  for (const group of [
    "optionalDependencies",
    "peerDependencies",
    "bundledDependencies"
  ]) {
    assert(
      packageJson[group] === undefined && root[group] === undefined,
      `${group} require explicit inventory support`
    );
  }
}

function packageRecords(lock) {
  assert(
    lock.lockfileVersion === 3,
    "package-lock.json must use lockfileVersion 3"
  );
  assert(
    lock.packages && typeof lock.packages === "object",
    "package-lock.json packages must be an object"
  );

  const records = [];
  for (const [lockPath, metadata] of Object.entries(lock.packages)) {
    if (lockPath === "") {
      continue;
    }
    assert(
      metadata && typeof metadata === "object" && !Array.isArray(metadata),
      `${lockPath} metadata must be an object`
    );
    assert(
      typeof metadata.version === "string" &&
        /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(
          metadata.version
        ),
      `${lockPath} must have an exact semantic version`
    );
    assert(
      typeof metadata.license === "string" &&
        ALLOWED_LICENSES.includes(metadata.license),
      `${lockPath} has an unreviewed license: ${String(metadata.license)}`
    );
    assert(
      typeof metadata.resolved === "string" &&
        metadata.resolved.startsWith("https://registry.npmjs.org/"),
      `${lockPath} must resolve from the reviewed npm registry origin`
    );
    assert(
      typeof metadata.integrity === "string" &&
        /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(metadata.integrity),
      `${lockPath} must have sha512 lock integrity`
    );
    assert(
      metadata.deprecated === undefined,
      `${lockPath} is marked deprecated and requires review`
    );

    const name = packageNameFromLockPath(lockPath);
    records.push({
      name,
      version: metadata.version,
      lockPath,
      use: metadata.dev === true ? "development-only" : "runtime",
      optional: metadata.optional === true,
      installScript: metadata.hasInstallScript === true,
      license: metadata.license
    });
  }

  records.sort((left, right) =>
    left.name.localeCompare(right.name) ||
    left.version.localeCompare(right.version) ||
    left.lockPath.localeCompare(right.lockPath)
  );
  const identifiers = records.map(
    ({ name, version, lockPath }) => `${name}@${version}:${lockPath}`
  );
  assert(
    new Set(identifiers).size === identifiers.length,
    "package-lock.json contains duplicate dependency inventory records"
  );
  assert(records.length > 0, "package-lock.json has no installed packages");
  return records;
}

function directRecords(packageJson, lock, records) {
  const declarations = [
    ...Object.entries(packageJson.dependencies ?? {}).map(([name, declared]) => ({
      name,
      declared,
      use: "runtime"
    })),
    ...Object.entries(packageJson.devDependencies ?? {}).map(
      ([name, declared]) => ({
        name,
        declared,
        use: "development-only"
      })
    )
  ].sort((left, right) => left.name.localeCompare(right.name));

  assert(
    declarations.length > 0,
    "package.json must declare at least one dependency"
  );
  assert(
    new Set(declarations.map(({ name }) => name)).size === declarations.length,
    "package.json must not declare one package in multiple dependency groups"
  );

  return declarations.map((declaration) => {
    assert(
      /^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/.test(
        declaration.declared
      ),
      `${declaration.name} must use an exact declared version`
    );
    const lockPath = `node_modules/${declaration.name}`;
    const metadata = lock.packages[lockPath];
    assert(metadata, `${declaration.name} is missing from package-lock.json`);
    assert(
      metadata.version === declaration.declared,
      `${declaration.name} declared and locked versions differ`
    );
    const record = records.find((candidate) => candidate.lockPath === lockPath);
    assert(record, `${declaration.name} is missing from the inventory`);
    assert(
      record.use === declaration.use,
      `${declaration.name} dependency class differs from package-lock.json`
    );
    return {
      ...declaration,
      locked: record.version,
      license: record.license
    };
  });
}

function summarize(records) {
  const licenses = Object.fromEntries(
    ALLOWED_LICENSES.map((license) => [
      license,
      records.filter((record) => record.license === license).length
    ])
  );
  return {
    packageCount: records.length,
    runtimeCount: records.filter((record) => record.use === "runtime").length,
    developmentOnlyCount: records.filter(
      (record) => record.use === "development-only"
    ).length,
    optionalCount: records.filter((record) => record.optional).length,
    installScriptCount: records.filter((record) => record.installScript).length,
    licenses
  };
}

function yesNo(value) {
  return value ? "yes" : "no";
}

export function renderDependencyInventory({ rootDir = DEFAULT_ROOT } = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const packageJson = readJson(
    path.join(resolvedRoot, PACKAGE_PATH),
    PACKAGE_PATH
  );
  const lockBytes = readFileSync(path.join(resolvedRoot, LOCK_PATH));
  const lock = readJson(path.join(resolvedRoot, LOCK_PATH), LOCK_PATH);
  verifyRootPackage(packageJson, lock);
  const records = packageRecords(lock);
  const direct = directRecords(packageJson, lock, records);
  const summary = summarize(records);
  const licenseSummary = Object.entries(summary.licenses)
    .map(([license, count]) => `${license}: ${count}`)
    .join("; ");

  const lines = [
    "# Locked dependency inventory",
    "",
    "**Status: CURRENT LOCK + AUTOMATED RELEASE PROVENANCE CONTROL — final deployed-bundle audit pending**",
    "",
    "This inventory is generated deterministically from `package.json` and",
    "`package-lock.json`. It records the complete locked npm package set,",
    "dependency class, package-lock license identifier, optional-package state,",
    "and install-script flag. The verifier rejects ranges in direct declarations,",
    "non-registry sources, missing SHA-512 integrity, deprecated packages, and",
    "licenses outside the explicitly reviewed identifier set.",
    "",
    "This is a provenance and review control, not legal advice or an independent",
    "verification of every upstream copyright statement. The exact package union",
    "and normalized license texts present in the Gate Two bundles are controlled by",
    "`THIRD_PARTY_NOTICES.txt` and `npm run licenses:verify`. On official `main`,",
    "`npm run release:provenance` additionally rejects shallow or replaced history,",
    "an unexpected clean-room root, tracked symlinks or submodules, and installed",
    "package identities that differ from the lock. The final release must rerun the",
    "combined control and bind its clean vulnerability report, uploaded object",
    "versions, and deployed Lambda `CodeSha256` values before submission.",
    "",
    "## Bound source",
    "",
    `- Package lock SHA-256: \`${sha256(lockBytes)}\``,
    `- Direct runtime declarations: **${direct.filter(({ use }) => use === "runtime").length}**`,
    `- Direct development declarations: **${direct.filter(({ use }) => use === "development-only").length}**`,
    `- Complete locked package records: **${summary.packageCount}**`,
    `- Runtime package records: **${summary.runtimeCount}**`,
    `- Development-only package records: **${summary.developmentOnlyCount}**`,
    `- Optional platform package records: **${summary.optionalCount}**`,
    `- Packages declaring an install script: **${summary.installScriptCount}**`,
    `- Reviewed package-lock license identifiers: ${licenseSummary}`,
    "- CI install boundary: `npm ci --ignore-scripts`; the deterministic Gate Two",
    "  build separately proves the exact bundled artifacts and embeds the verified",
    "  third-party notice file in every ZIP.",
    "",
    "## Direct declarations",
    "",
    "| Package | Declared | Locked | Use | License |",
    "| --- | --- | --- | --- | --- |",
    ...direct.map(
      ({ name, declared, locked, use, license }) =>
        `| \`${name}\` | \`${declared}\` | \`${locked}\` | ${use} | \`${license}\` |`
    ),
    "",
    "## Complete locked package set",
    "",
    "| Package | Version | Lock path | Use | Optional | Install script | License |",
    "| --- | --- | --- | --- | --- | --- | --- |",
    ...records.map(
      ({ name, version, lockPath, use, optional, installScript, license }) =>
        `| \`${name}\` | \`${version}\` | \`${lockPath}\` | ${use} | ${yesNo(optional)} | ${yesNo(installScript)} | \`${license}\` |`
    ),
    ""
  ];

  return {
    content: lines.join("\n"),
    sourceLockSha256: sha256(lockBytes),
    ...summary
  };
}

export function verifyDependencyInventory({ rootDir = DEFAULT_ROOT } = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const expected = renderDependencyInventory({ rootDir: resolvedRoot });
  const inventoryPath = path.join(resolvedRoot, INVENTORY_PATH);
  const actual = readFileSync(inventoryPath, "utf8");
  assert(
    actual === expected.content,
    `${INVENTORY_PATH} does not match the exact locked dependency inventory`
  );
  return {
    schema: RECEIPT_SCHEMA,
    status: "PASS",
    sourceLockSha256: expected.sourceLockSha256,
    inventorySha256: sha256(actual),
    packageCount: expected.packageCount,
    runtimeCount: expected.runtimeCount,
    developmentOnlyCount: expected.developmentOnlyCount,
    optionalCount: expected.optionalCount,
    installScriptCount: expected.installScriptCount,
    licenses: expected.licenses
  };
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    if (process.argv.length === 3 && process.argv[2] === "--print") {
      process.stdout.write(renderDependencyInventory().content);
    } else {
      assert(
        process.argv.length === 2,
        "usage: node scripts/verify-dependency-inventory.js [--print]"
      );
      process.stdout.write(
        `${JSON.stringify(verifyDependencyInventory(), null, 2)}\n`
      );
    }
  } catch (error) {
    process.stderr.write(`DEPENDENCY_INVENTORY_FAIL: ${error.message}\n`);
    process.exitCode = 1;
  }
}
