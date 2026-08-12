import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";

import {
  __test as runtimeTest,
  stagedRuntimeComponentForScript
} from "../src/cloud/integrated-live-drill-runtime.js";
import { __test as spawnTest } from
  "../src/cloud/integrated-live-drill-runtime-spawn.js";

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const OFFICIAL_NODE_SHA256 =
  "2e3f1286a7eb3736346ed1803e458a0ff909e2b2d5bc746144dcb76970e9b99d";
const COMPONENTS = [
  "authority-race",
  "dvi",
  "finalizer",
  "orchestrator",
  "reconciler",
  "recovery",
  "supervisor",
  "worker"
];
const require = createRequire(import.meta.url);

function manifest() {
  return {
    schemaVersion: "tideproof.integrated-live-drill-runtime-manifest.v1",
    sourceCommit: "1".repeat(40),
    treeDigest: "2".repeat(40),
    packageLockDigest: SHA_A,
    toolchainSha256: SHA_B,
    launcher: {
      file: "verified-node-bundle-launcher.pl",
      sha256: "c".repeat(64)
    },
    node: {
      architecture: "arm64",
      distribution: "nodejs.org-release-v22.23.1",
      file: `node-${OFFICIAL_NODE_SHA256}`,
      platform: "darwin",
      sha256: OFFICIAL_NODE_SHA256,
      version: "v22.23.1"
    },
    components: Object.fromEntries(COMPONENTS.map((name, index) => [
      name,
      {
        bundledPackages: [4, 7].includes(index) ? ["pg"] : [],
        bytes: index + 1,
        externalImports: ["node:fs"],
        file: `${name}-${String(index + 1).repeat(64)}.mjs`,
        sha256: String(index + 1).repeat(64)
      }
    ]))
  };
}

test("runtime manifest binds every content-addressed executable component", () => {
  const value = manifest();
  assert.equal(runtimeTest.validateRuntimeManifest(value), value);
  for (const mutate of [
    (candidate) => { candidate.components.worker.bytes = 0; },
    (candidate) => { candidate.components.worker.file = "worker.mjs"; },
    (candidate) => { candidate.components.worker.externalImports = ["pg"]; },
    (candidate) => { candidate.node.version = "v23.0.0"; },
    (candidate) => { candidate.unbound = true; }
  ]) {
    const changed = structuredClone(value);
    mutate(changed);
    assert.throws(
      () => runtimeTest.validateRuntimeManifest(changed),
      /INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_REJECTED/u
    );
  }
});

test("reviewed runtime makes the optional native Postgres binding unavailable", () => {
  assert.throws(
    () => require("../scripts/lib/pg-native-unavailable.cjs"),
    (error) =>
      error?.code === "MODULE_NOT_FOUND" &&
      /optional pg-native binding is unavailable/u.test(error.message)
  );
});

test("runtime stage rejects any mutable ancestor in its absolute path", () => {
  const directories = new Map([
    ["/", { uid: 0, mode: 0o40755 }],
    ["/opt", { uid: 0, mode: 0o40755 }],
    ["/opt/prooftoact", { uid: 0, mode: 0o40755 }],
    ["/opt/prooftoact/runtime", { uid: 0, mode: 0o40755 }]
  ]);
  const options = {
    lstat(candidate) {
      const record = directories.get(candidate);
      if (!record) throw new Error("missing fixture path");
      return {
        isDirectory: () => true,
        isSymbolicLink: () => false,
        ...record
      };
    },
    realpath: (candidate) => candidate
  };
  assert.doesNotThrow(() =>
    runtimeTest.assertRootOwnedStagePath("/opt/prooftoact/runtime", options)
  );
  directories.set("/opt", { uid: 0, mode: 0o40777 });
  assert.throws(
    () => runtimeTest.assertRootOwnedStagePath("/opt/prooftoact/runtime", options),
    /INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_REJECTED/
  );
});

test("pre-execution launcher validates immutable ancestry before pathname exec", () => {
  const source = fs.readFileSync(
    new URL("../scripts/lib/verified-node-bundle-launcher.pl", import.meta.url),
    "utf8"
  );
  assert.match(source, /assert_root_owned_immutable_directory_chain\(\$stage_root\)/u);
  assert.match(source, /exec \{\s*"\$stage_root\/\$node_name"/u);
});

test("script dispatch maps only the eight reviewed runtime entry roles", () => {
  assert.equal(
    stagedRuntimeComponentForScript(
    "/immutable/gate1-integrated-live-drill-provider-worker.js"
    ),
    "worker"
  );
  assert.equal(
    stagedRuntimeComponentForScript(
      "/immutable/gate1-integrated-live-drill-provider-reconciler.js"
    ),
    "reconciler"
  );
  assert.throws(
    () => stagedRuntimeComponentForScript("/mutable/arbitrary.js"),
    /INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_REJECTED/u
  );
});

test("child launch removes every pre-execution injection surface", () => {
  const injected = {
    SAFE_INPUT: "preserved",
    DYLD_INSERT_LIBRARIES: "/tmp/inject.dylib",
    GCONV_PATH: "/tmp/gconv",
    GLIBC_TUNABLES: "glibc.malloc.check=1",
    LD_AUDIT: "/tmp/audit.so",
    LD_LIBRARY_PATH: "/tmp/lib",
    LD_PRELOAD: "/tmp/inject.so",
    NODE_EXTRA_CA_CERTS: "/tmp/ca.pem",
    NODE_OPTIONS: "--require=/tmp/inject.cjs",
    NODE_PATH: "/tmp/modules",
    PERL5LIB: "/tmp/perl",
    PERL5OPT: "-MInject"
  };
  const environment = spawnTest.runtimeChildEnvironment(injected, {
    manifestSha256: SHA_A,
    stageRoot: "/immutable/runtime"
  });
  assert.equal(environment.SAFE_INPUT, "preserved");
  for (const name of Object.keys(injected).filter((name) => name !== "SAFE_INPUT")) {
    assert.equal(Object.hasOwn(environment, name), false, name);
  }
  assert.equal(
    environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256,
    SHA_A
  );
  assert.equal(
    environment.TIDEPROOF_INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT,
    "/immutable/runtime"
  );
});
