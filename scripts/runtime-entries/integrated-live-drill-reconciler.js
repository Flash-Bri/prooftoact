import { main } from "../gate1-integrated-live-drill-provider-reconciler.js";

main().catch((error) => {
  const code = /^INTEGRATED_LIVE_DRILL_[A-Z0-9_]{1,140}$/u.test(
    String(error?.message ?? "")
  )
    ? error.message
    : "INTEGRATED_LIVE_DRILL_PROVIDER_RECONCILIATION_UNKNOWN_DO_NOT_ACT";
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
});
