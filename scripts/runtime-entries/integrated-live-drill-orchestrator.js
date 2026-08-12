import {
  main,
  safeIntegratedLiveDrillFailureCode
} from "../gate2-integrated-live-drill.js";

main().catch((error) => {
  process.stderr.write(`${safeIntegratedLiveDrillFailureCode(error)}\n`);
  process.exitCode = 1;
});
