import { main } from "../gate1-integrated-live-drill-provider-activation.js";
main().catch((error) => {
  process.stderr.write(`${String(error?.message ?? "INTEGRATED_LIVE_DRILL_PROVIDER_ACTIVATION_UNKNOWN")}\n`);
  process.exitCode = 1;
});
