import { pathToFileURL } from "node:url";

const INTEGRATED_PERSISTENCE_ENVIRONMENT = Object.freeze([
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_SPEC",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_RECOVERY_BUNDLE_PATH",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_PRIVATE_EVIDENCE_ROOT",
  "TIDEPROOF_INTEGRATED_LIVE_DRILL_FORBIDDEN_ROOT"
]);

export function integratedPersistenceEnvironment(environment = process.env) {
  const present = INTEGRATED_PERSISTENCE_ENVIRONMENT.filter(
    (name) => typeof environment[name] === "string" && environment[name].length > 0
  );
  if (present.length === 0) return null;
  if (present.length !== INTEGRATED_PERSISTENCE_ENVIRONMENT.length) {
    throw new Error(
      "INTEGRATED_LIVE_DRILL_RECOVERY_BROKER_PARTIAL_CONFIG_REJECTED"
    );
  }
  return Object.freeze(Object.fromEntries(
    INTEGRATED_PERSISTENCE_ENVIRONMENT.map((name) => [name, environment[name]])
  ));
}

export async function main() {
  throw new Error("INTEGRATED_LIVE_DRILL_SYSTEMD_BOUNDARY_REQUIRED");
}

const startedDirectly = process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;

if (startedDirectly) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 126;
  });
}
