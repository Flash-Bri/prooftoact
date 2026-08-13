import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SCHEMA =
  "tideproof.highwater-drill-process-boundary-verification.v4";

const ROOT = fs.realpathSync(path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  ".."
));
const IMPORT_PATTERN =
  /\b(?:import|export)\s+(?:[^'";]*?\s+from\s+)?["']([^"']+)["']|\bimport\s*\(\s*["']([^"']+)["']\s*\)|\brequire\s*\(\s*["']([^"']+)["']\s*\)/gu;

const FINALIZER_ROOTS = Object.freeze([
  "scripts/gate2-integrated-live-drill-provider-finalizer.js",
  "src/cloud/integrated-live-drill-provider-finalization.js"
]);
const WORKER_ROOTS = Object.freeze([
  "scripts/gate1-integrated-live-drill-provider-worker.js",
  "src/cloud/integrated-live-drill-provider-worker.js"
]);
const PROVIDER_OPERATION_ROOTS = Object.freeze([
  "scripts/gate1-integrated-live-drill-provider-operation-broker.js",
  "src/cloud/integrated-live-drill-provider-operation-broker.js"
]);
const RECONCILER_ROOTS = Object.freeze([
  "scripts/gate1-integrated-live-drill-provider-reconciler.js",
  "src/cloud/integrated-live-drill-provider-reconciliation.js"
]);
const SUPERVISOR_PATH =
  "scripts/gate1-integrated-live-drill-provider-supervisor.js";
const SAFE_BUILTINS = new Set([
  "node:crypto",
  "node:fs",
  "node:module",
  "node:path",
  "node:url"
]);
const PROVIDER_OPERATION_SAFE_BUILTINS = new Set([
  ...SAFE_BUILTINS,
  "node:net"
]);
const WORKER_SAFE_BUILTINS = new Set([
  ...SAFE_BUILTINS,
  "node:net"
]);
const FINALIZER_FORBIDDEN_PATH_PATTERNS = Object.freeze([
  /(?:^|\/)database-runtime\.js$/u,
  /(?:^|\/)integrated-live-drill-provider-recovery\.js$/u,
  /(?:^|\/)integrated-live-drill-provider-worker\.js$/u,
  /(?:^|\/)managed-mcp-client\.js$/u,
  /(?:^|\/)recovery-broker\.js$/u
]);
const WORKER_FORBIDDEN_PATH_PATTERNS = Object.freeze([
  /(?:^|\/)gate2-/u,
  /(?:^|\/)integrated-live-drill-provider-finalization\.js$/u,
  /(?:^|\/)integrated-live-drill-provider-finalizer\.js$/u,
  /(?:^|\/)integrated-live-drill-provider-operation-broker\.js$/u,
  /(?:^|\/)managed-mcp-client\.js$/u,
  /(?:^|\/)provider-dispatch-finalize-control\.js$/u,
  /(?:^|\/)provider-dispatch-redeem-control\.js$/u
]);
const RECONCILER_FORBIDDEN_PATH_PATTERNS = Object.freeze([
  /(?:^|\/)integrated-live-drill-provider-worker\.js$/u,
  /(?:^|\/)managed-mcp-client\.js$/u
]);

function reject(code, detail) {
  throw new Error(detail === undefined ? code : `${code}:${detail}`);
}

function normalizedRelative(filePath) {
  const relative = path.relative(ROOT, filePath);
  if (
    relative === "" ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_PATH_REJECTED", filePath);
  }
  return relative.split(path.sep).join("/");
}

function secureModulePath(filePath) {
  const resolved = path.resolve(filePath);
  let real;
  let stat;
  try {
    real = fs.realpathSync(resolved);
    stat = fs.lstatSync(resolved);
  } catch (cause) {
    reject(
      "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_PATH_REJECTED",
      String(cause?.message ?? cause)
    );
  }
  if (
    real !== resolved ||
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    ![".cjs", ".js"].includes(path.extname(real))
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_PATH_REJECTED", resolved);
  }
  normalizedRelative(real);
  return real;
}

function localImportPath(specifier, importer) {
  if (!specifier.startsWith(".")) return null;
  const unresolved = path.resolve(path.dirname(importer), specifier);
  const candidates = path.extname(unresolved) === ""
    ? [`${unresolved}.js`, path.join(unresolved, "index.js")]
    : [unresolved];
  const existing = candidates.filter((candidate) => fs.existsSync(candidate));
  if (existing.length !== 1) {
    reject(
      "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_IMPORT_REJECTED",
      `${normalizedRelative(importer)}:${specifier}`
    );
  }
  return secureModulePath(existing[0]);
}

function importSpecifiers(source) {
  const matches = [];
  for (const match of source.matchAll(IMPORT_PATTERN)) {
    matches.push(match[1] ?? match[2] ?? match[3]);
  }
  return matches;
}

function collectGraph(rootPaths) {
  const pending = rootPaths.map((entry) => secureModulePath(
    path.join(ROOT, entry)
  ));
  const modules = new Set();
  const builtins = new Set();
  const externalPackages = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (modules.has(current)) continue;
    modules.add(current);
    const source = fs.readFileSync(current, "utf8");
    for (const specifier of importSpecifiers(source)) {
      const local = localImportPath(specifier, current);
      if (local !== null) {
        pending.push(local);
      } else if (specifier.startsWith("node:")) {
        builtins.add(specifier);
      } else {
        externalPackages.add(specifier);
      }
    }
  }
  return Object.freeze({
    builtins: Object.freeze([...builtins].sort()),
    externalPackages: Object.freeze([...externalPackages].sort()),
    modules: Object.freeze([...modules].map(normalizedRelative).sort()),
    rootPaths: Object.freeze([...rootPaths])
  });
}

function validateGraph(graph, {
  allowedExternalPackages,
  allowedBuiltins = SAFE_BUILTINS,
  forbiddenPathPatterns,
  name
}) {
  for (const builtin of graph.builtins) {
    if (!allowedBuiltins.has(builtin)) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_BUILTIN_REJECTED",
        `${name}:${builtin}`
      );
    }
  }
  for (const dependency of graph.externalPackages) {
    if (!allowedExternalPackages.has(dependency)) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_PACKAGE_REJECTED",
        `${name}:${dependency}`
      );
    }
  }
  for (const modulePath of graph.modules) {
    for (const pattern of forbiddenPathPatterns) {
      if (pattern.test(modulePath)) {
        reject(
          "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_MODULE_REJECTED",
          `${name}:${modulePath}`
        );
      }
    }
  }
  return graph;
}

function validateSupervisorSource() {
  const filePath = secureModulePath(path.join(ROOT, SUPERVISOR_PATH));
  const source = fs.readFileSync(filePath, "utf8");
  const directImports = importSpecifiers(source).sort();
  for (const forbidden of [
    "./gate1-recovery-broker.js",
    "../src/cloud/managed-mcp-client.js"
  ]) {
    if (directImports.includes(forbidden)) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SUPERVISOR_REJECTED",
        forbidden
      );
    }
  }
  for (const required of [
    "INTEGRATED_LIVE_DRILL_PROVIDER_SUPERVISOR_RESUME_DISABLED",
    "mode === \"PREPARE\""
  ]) {
    if (!source.includes(required)) {
      reject(
        "INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SUPERVISOR_REJECTED",
        required
      );
    }
  }
  if (
    /new\s+CockroachManagedMcpRecoveryClient\b/u.test(source) ||
    /new\s+DeterministicRecoveryBroker\b/u.test(source) ||
    /integratedLiveDrillProviderWorkerEnvironment\b/u.test(source) ||
    /integratedLiveDrillProviderFinalizerEnvironment\b/u.test(source)
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SUPERVISOR_REJECTED");
  }
  return Object.freeze({
    directImports: Object.freeze(directImports),
    legacyRecoveryEntryPointImported: false,
    managedMcpClientConstructed: false,
    path: SUPERVISOR_PATH,
    providerFinalizerEnvironmentRequired: false,
    providerWorkerEnvironmentRequired: false,
    resumeDisabled: true
  });
}

export function verifyIntegratedLiveDrillProcessBoundaries() {
  const finalizer = validateGraph(collectGraph(FINALIZER_ROOTS), {
    allowedExternalPackages: new Set(),
    forbiddenPathPatterns: FINALIZER_FORBIDDEN_PATH_PATTERNS,
    name: "finalizer"
  });
  const worker = validateGraph(collectGraph(WORKER_ROOTS), {
    allowedExternalPackages: new Set(["pg"]),
    allowedBuiltins: WORKER_SAFE_BUILTINS,
    forbiddenPathPatterns: WORKER_FORBIDDEN_PATH_PATTERNS,
    name: "worker"
  });
  const providerOperation = validateGraph(
    collectGraph(PROVIDER_OPERATION_ROOTS),
    {
      allowedBuiltins: PROVIDER_OPERATION_SAFE_BUILTINS,
      allowedExternalPackages: new Set(["pg"]),
      forbiddenPathPatterns: Object.freeze([
        /(?:^|\/)integrated-live-drill-provider-reconciliation\.js$/u
      ]),
      name: "provider-operation"
    }
  );
  const reconciler = validateGraph(collectGraph(RECONCILER_ROOTS), {
    allowedExternalPackages: new Set(["pg"]),
    forbiddenPathPatterns: RECONCILER_FORBIDDEN_PATH_PATTERNS,
    name: "reconciler"
  });
  const supervisor = validateSupervisorSource();
  if (
    !finalizer.modules.includes(
      "src/cloud/integrated-live-drill-provider-evidence.js"
    ) ||
    !worker.modules.includes(
      "src/cloud/integrated-live-drill-provider-recovery.js"
    ) ||
    !worker.modules.includes("src/cloud/recovery-broker.js") ||
    worker.modules.includes("src/cloud/managed-mcp-client.js") ||
    !worker.modules.includes(
      "src/cloud/brokered-provider-operation-client.js"
    ) ||
    !providerOperation.modules.includes("src/cloud/managed-mcp-client.js") ||
    !providerOperation.modules.includes(
      "src/cloud/provider-dispatch-redeem-control.js"
    ) ||
    !providerOperation.modules.includes(
      "src/cloud/provider-dispatch-finalize-control.js"
    ) ||
    !reconciler.modules.includes(
      "src/cloud/provider-dispatch-resolver.js"
    ) ||
    reconciler.modules.includes(
      "src/cloud/provider-dispatch-control.js"
    ) ||
    reconciler.modules.includes("src/cloud/managed-mcp-client.js")
  ) {
    reject("INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_GRAPH_REJECTED");
  }
  return Object.freeze({
    schemaVersion: INTEGRATED_LIVE_DRILL_PROCESS_BOUNDARY_SCHEMA,
    finalizer,
    providerOperation,
    reconciler,
    supervisor,
    worker,
    status: "PASS"
  });
}

const startedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  try {
    process.stdout.write(
      `${JSON.stringify(verifyIntegratedLiveDrillProcessBoundaries())}\n`
    );
  } catch (error) {
    process.stderr.write(`${String(error?.message ?? error)}\n`);
    process.exitCode = 1;
  }
}
