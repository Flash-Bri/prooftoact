import {
  main,
  safeAuthorityRaceFailureCode
} from "../gate2-authority-race.js";

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(
    `${JSON.stringify({
      schemaVersion: "tideproof.aws-authority-race-error.v1",
      status: "FAIL",
      code: safeAuthorityRaceFailureCode(error)
    })}\n`
  );
  process.exitCode = 1;
});
