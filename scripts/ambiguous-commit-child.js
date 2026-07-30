import { writeSync } from "node:fs";
import { AuthorityStore } from "../src/cloud/authority-store.js";

const mode = process.env.TIDEPROOF_AMBIGUITY_MODE;
const request = JSON.parse(process.env.TIDEPROOF_REQUEST_JSON ?? "null");
const connectionString = process.env.DATABASE_URL;

if (
  !connectionString ||
  !request ||
  ![
    "before_commit",
    "commit_dispatched",
    "after_commit_before_response"
  ].includes(mode)
) {
  process.exitCode = 64;
} else {
  const store = new AuthorityStore({
    connectionString,
    databaseName: "tideproof",
    maxConnections: 1
  });
  let markerWritten = false;
  const terminateAtBoundary = () => {
    if (markerWritten) {
      return;
    }
    markerWritten = true;
    writeSync(
      3,
      `${JSON.stringify({
        event:
          mode === "before_commit"
            ? "dml_staged_commit_not_sent"
            : mode === "commit_dispatched"
              ? "commit_bytes_flushed_ack_unread"
              : "commit_acknowledged_response_not_sent",
        pid: process.pid,
        operationId: request.operationId
      })}\n`
    );
    process.kill(process.pid, "SIGKILL");
  };

  await store.spendAuthority(request, {
    beforeCommitObserver:
      mode === "before_commit" ? terminateAtBoundary : undefined,
    commitDispatchObserver:
      mode === "commit_dispatched" ? terminateAtBoundary : undefined,
    afterCommitObserver:
      mode === "after_commit_before_response" ? terminateAtBoundary : undefined
  });

  writeSync(
    3,
    `${JSON.stringify({
      event: "boundary_not_triggered",
      pid: process.pid,
      operationId: request.operationId
    })}\n`
  );
  await store.close();
  process.exitCode = 65;
}
