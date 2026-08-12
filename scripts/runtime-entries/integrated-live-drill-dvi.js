import {
  main,
  safeAdmissibleVectorFailureCode
} from "../gate1-admissible-vector.js";

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`${safeAdmissibleVectorFailureCode(error)}\n`);
  process.exitCode = 1;
});
