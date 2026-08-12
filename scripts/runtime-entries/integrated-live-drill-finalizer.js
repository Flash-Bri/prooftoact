import { main } from "../gate2-integrated-live-drill-provider-finalizer.js";

main().catch((error) => {
  const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
    String(error?.message ?? "")
  )
    ? error.message
    : "INTEGRATED_LIVE_DRILL_PROVIDER_FINALIZATION_UNKNOWN";
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
});
