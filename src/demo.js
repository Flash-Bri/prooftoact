import { runScenario } from "./scenario.js";

process.stdout.write(`${JSON.stringify(runScenario(), null, 2)}\n`);
