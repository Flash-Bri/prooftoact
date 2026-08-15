import { main } from "../gate1-integrated-live-drill-provider-terminalizer.js";
main().catch((error) => {
  process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_TERMINALIZATION_UNKNOWN")}\n`);
  process.exitCode = 1;
});
