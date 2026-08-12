import { main } from "../gate1-recovery-broker.js";

main().catch((error) => {
  process.stderr.write(
    `${JSON.stringify({
      gate: "noninteractive Managed MCP deterministic recovery broker",
      passed: false,
      name: error?.name,
      code: error?.code,
      message: error?.message
    })}\n`
  );
  process.exitCode = 1;
});
