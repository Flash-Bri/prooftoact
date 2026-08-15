import { spawnSync } from "node:child_process";
import path from "node:path";

import {
  assertIntegratedLiveDrillRuntime,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT,
  INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT,
  stagedRuntimeComponentForScript
} from "./integrated-live-drill-runtime.js";

const PRE_EXECUTION_INJECTION_ENVIRONMENT =
  /^(?:NODE_.*|LD_.*|DYLD_.*|GLIBC_TUNABLES|GCONV_PATH|PERL.*|OPENSSL_.*|SSL_.*|SSLKEYLOGFILE|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|all_proxy|no_proxy|TZDIR|ICU_DATA|MALLOC_CONF|MALLOC_OPTIONS|ASAN_OPTIONS|LSAN_OPTIONS|MSAN_OPTIONS|TSAN_OPTIONS|UBSAN_OPTIONS)$/u;

function runtimeChildEnvironment(childEnvironment, runtime) {
  const environment = {
    ...childEnvironment,
    [INTEGRATED_LIVE_DRILL_RUNTIME_MANIFEST_SHA256_ENVIRONMENT]:
      runtime.manifestSha256,
    [INTEGRATED_LIVE_DRILL_RUNTIME_STAGE_ROOT_ENVIRONMENT]: runtime.stageRoot
  };
  delete environment[INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_ENVIRONMENT];
  delete environment[
    INTEGRATED_LIVE_DRILL_RUNTIME_COMPONENT_SHA256_ENVIRONMENT
  ];
  for (const name of Object.keys(environment)) {
    if (PRE_EXECUTION_INJECTION_ENVIRONMENT.test(name)) {
      delete environment[name];
    }
  }
  return environment;
}

export function spawnIntegratedLiveDrillRuntimeComponent({
  args,
  childEnvironment,
  cwd,
  parentEnvironment,
  parentComponent,
  script,
  spec,
  stdio
}) {
  const runtime = assertIntegratedLiveDrillRuntime({
    environment: parentEnvironment,
    expectedComponent: parentComponent,
    spec
  });
  const component = stagedRuntimeComponentForScript(script);
  const environment = runtimeChildEnvironment(childEnvironment, runtime);
  return spawnSync(
    "/usr/bin/perl",
    [
      path.join(runtime.stageRoot, runtime.manifest.launcher.file),
      component,
      ...args
    ],
    {
      cwd,
      encoding: "utf8",
      env: environment,
      maxBuffer: 8 * 1024 * 1024,
      timeout: 10 * 60 * 1_000,
      stdio
    }
  );
}

export const __test = Object.freeze({
  PRE_EXECUTION_INJECTION_ENVIRONMENT,
  runtimeChildEnvironment
});
