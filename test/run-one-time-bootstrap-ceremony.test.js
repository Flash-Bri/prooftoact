import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  __test as runnerTest,
  AwsOneTimeBootstrapB0Provider,
  AwsOneTimeBootstrapRootProvider,
  buildOneTimeBootstrapAuthorizationReceipt,
  deriveA1SecretCensus,
  OneTimeBootstrapJournal,
  inspectOneTimeBootstrapOperationLock,
  recoverOneTimeBootstrapStaleLock,
  RootActionGate,
  runCrashConvergentMutation,
  runCrashConvergentSecretSeal,
  validateOneTimeBootstrapTimingBudget,
  validateOneTimeBootstrapAuthorizationReceipt
} from "../scripts/run-one-time-bootstrap-ceremony.js";
import { buildOneTimeBootstrapCostReconciliationReceipt } from
  "../scripts/prepare-one-time-bootstrap-authority.js";
import { buildSyntheticProofToActHumanAuthorization } from
  "./helpers/prooftoact-human-authorization-fixture.js";

const PLAN = Object.freeze({
  authorization: Object.freeze({
    userAuthorizationReceiptSha256: "d".repeat(64)
  }),
  operation: Object.freeze({
    operationId: "123e4567-e89b-42d3-a456-426614174000",
    operationToken: "0123456789abcdef"
  }),
  planBodySha256: "a".repeat(64)
});

function privateDirectory(t) {
  const directory = fs.mkdtempSync(path.join(
    fs.realpathSync(os.tmpdir()),
    "prooftoact-b0-journal-"
  ));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

function clock() {
  let milliseconds = Date.parse("2026-08-18T14:00:00.000Z");
  return () => new Date(milliseconds++);
}

function journal(t, mode = "NEW", directory = privateDirectory(t)) {
  const active = new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: directory,
    mode,
    plan: PLAN
  });
  return active;
}

function receipt(value) {
  return { stateSha256: String(value).padStart(64, "0").slice(-64) };
}

test("journal is owner-only, fsync/atomic, tamper-evident, and rejects credentials", (t) => {
  const directory = privateDirectory(t);
  const active = journal(t, "NEW", directory);
  assert.equal(fs.statSync(active.filePath).mode & 0o077, 0);
  active.recordIntent("create-role", "iam:CreateRole", {
    roleName: "ProofToActBootstrapCreator-0123456789abcdef"
  });
  assert.throws(() => active.recordAccepted(
    "create-role",
    "PRESTATE_RECONCILIATION",
    { AccessKeyId: "must-never-enter-journal" }
  ), /ONE_TIME_BOOTSTRAP_JOURNAL_SECRET_MATERIAL_REJECTED/u);

  const parsed = JSON.parse(fs.readFileSync(active.filePath, "utf8"));
  parsed.steps["create-role"].contractSha256 = "f".repeat(64);
  fs.writeFileSync(active.filePath, `${JSON.stringify(parsed)}\n`, {
    mode: 0o600
  });
  active.releaseLock();
  assert.throws(() => journal(t, "RECONCILE_ONLY", directory),
    /ONE_TIME_BOOTSTRAP_JOURNAL_INTEGRITY_REJECTED/u);
});

test("mutation classes journal before dispatch and converge ACK loss without redispatch", async (t) => {
  const mutationClasses = [
    "iam:CreateRole",
    "iam:TagRole",
    "iam:PutRolePolicy",
    "cloudformation:CreateChangeSet",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:UpdateTerminationProtection",
    "secretsmanager:PutSecretValue",
    "iam:DeleteRolePolicy",
    "iam:DeleteRole"
  ];
  for (const [index, mutationClass] of mutationClasses.entries()) {
    const active = journal(t);
    let providerState = "ABSENT";
    let dispatchCount = 0;
    const accepted = await runCrashConvergentMutation({
      acceptReceipt: ({ generation }) => receipt(generation),
      classify: ({ state }) => state,
      contract: { targetSha256: String(index).repeat(64).slice(0, 64) },
      async dispatch() {
        dispatchCount += 1;
        assert.equal(active.step(`step-${index}`).state, "DISPATCH_STARTED");
        providerState = "MATCH";
        throw new Error("ACK_LOST_AFTER_PROVIDER_COMMIT");
      },
      id: `step-${index}`,
      inspect: async () => ({ state: providerState, generation: index }),
      journal: active,
      mutationClass
    });
    assert.deepEqual(accepted, receipt(index));
    assert.equal(dispatchCount, 1);
    assert.equal(active.step(`step-${index}`).acceptedBy,
      "POST_DISPATCH_RECONCILIATION");
  }
});

test("reconcile-only resume accepts strong matching state and never fills absent state", async (t) => {
  const directory = privateDirectory(t);
  const active = journal(t, "NEW", directory);
  active.recordIntent("execute-stack", "cloudformation:ExecuteChangeSet", {
    changeSetName: "exact"
  });
  active.recordDispatchStarted("execute-stack");
  active.releaseLock();
  const resumed = journal(t, "RECONCILE_ONLY", directory);
  let dispatchCount = 0;
  const accepted = await runCrashConvergentMutation({
    acceptReceipt: () => receipt(1),
    classify: ({ state }) => state,
    contract: { changeSetName: "exact" },
    dispatch: async () => { dispatchCount += 1; },
    id: "execute-stack",
    inspect: async () => ({ state: "MATCH" }),
    journal: resumed,
    mutationClass: "cloudformation:ExecuteChangeSet"
  });
  assert.deepEqual(accepted, receipt(1));
  assert.equal(dispatchCount, 0);
  await assert.rejects(() => runCrashConvergentMutation({
    acceptReceipt: () => receipt(1),
    classify: ({ state }) => state,
    contract: { changeSetName: "exact" },
    dispatch: async () => { dispatchCount += 1; },
    id: "execute-stack",
    inspect: async () => ({ state: "CONFLICT" }),
    journal: resumed,
    mutationClass: "cloudformation:ExecuteChangeSet"
  }), /ONE_TIME_BOOTSTRAP_MUTATION_CONVERGENCE_REJECTED/u);
  assert.equal(dispatchCount, 0);

  const secondDirectory = privateDirectory(t);
  const second = journal(t, "NEW", secondDirectory);
  second.recordIntent("create-role", "iam:CreateRole", { roleName: "exact" });
  second.recordDispatchStarted("create-role");
  second.releaseLock();
  const absentResume = journal(t, "RECONCILE_ONLY", secondDirectory);
  await assert.rejects(() => runCrashConvergentMutation({
    acceptReceipt: () => receipt(2),
    classify: ({ state }) => state,
    contract: { roleName: "exact" },
    dispatch: async () => { dispatchCount += 1; },
    id: "create-role",
    inspect: async () => ({ state: "ABSENT" }),
    journal: absentResume,
    mutationClass: "iam:CreateRole"
  }), /ONE_TIME_BOOTSTRAP_AMBIGUOUS_MUTATION_RETAIN_AND_RECONCILE/u);
  assert.equal(dispatchCount, 0);
});

test("reconcile-only safely dispatches a durable intent that never crossed dispatch boundary", async (t) => {
  const directory = privateDirectory(t);
  const active = journal(t, "NEW", directory);
  active.recordIntent("create-stack", "cloudformation:CreateChangeSet", {
    changeSetName: "exact-intent-only"
  });
  active.releaseLock();
  const resumed = journal(t, "RECONCILE_ONLY", directory);
  let state = "ABSENT";
  let dispatchCount = 0;
  const accepted = await runCrashConvergentMutation({
    acceptReceipt: () => receipt(9),
    classify: ({ state: value }) => value,
    contract: { changeSetName: "exact-intent-only" },
    dispatch: async () => {
      dispatchCount += 1;
      assert.equal(resumed.step("create-stack").state, "DISPATCH_STARTED");
      state = "MATCH";
    },
    id: "create-stack",
    inspect: async () => ({ state }),
    journal: resumed,
    mutationClass: "cloudformation:CreateChangeSet"
  });
  assert.deepEqual(accepted, receipt(9));
  assert.equal(dispatchCount, 1);
});

test("exclusive operation lock rejects concurrent or stale-lock auto-break", (t) => {
  const directory = privateDirectory(t);
  const active = journal(t, "NEW", directory);
  assert.throws(() => new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: directory,
    mode: "RECONCILE_ONLY",
    plan: PLAN
  }), /ONE_TIME_BOOTSTRAP_OPERATION_LOCK_REJECTED/u);
  assert.equal(fs.existsSync(active.lock.filePath), true);
  active.releaseLock();
  const resumed = journal(t, "RECONCILE_ONLY", directory);
  assert.equal(fs.existsSync(resumed.lock.filePath), true);
});

test("audited stale-lock recovery requires exact dead-process receipt and preserves journal", (t) => {
  const directory = privateDirectory(t);
  const crashed = journal(t, "NEW", directory);
  const lock = inspectOneTimeBootstrapOperationLock({
    directoryPath: directory,
    plan: PLAN
  });
  const receipt = {
    schemaVersion: "prooftoact.one-time-bootstrap-stale-lock-recovery.v1",
    status: "CONFIRMED_DEAD_PROCESS_LOCK_REMOVAL_AUTHORIZED",
    confirmedAt: "2026-08-18T14:05:00.000Z",
    confirmedPid: lock.pid,
    confirmedProcessDead: true,
    journalPreserved: true,
    lockFileSha256: lock.lockFileSha256,
    manualRemovalAuthorized: true,
    operationId: PLAN.operation.operationId,
    operatorAuthorizationReceiptSha256:
      PLAN.authorization.userAuthorizationReceiptSha256,
    planBodySha256: PLAN.planBodySha256
  };
  assert.throws(() => recoverOneTimeBootstrapStaleLock({
    auditReceipt: { ...receipt, confirmedProcessDead: false },
    directoryPath: directory,
    plan: PLAN
  }), /ONE_TIME_BOOTSTRAP_STALE_LOCK_RECOVERY_REJECTED/u);
  const recovered = recoverOneTimeBootstrapStaleLock({
    auditReceipt: receipt,
    directoryPath: directory,
    plan: PLAN
  });
  assert.equal(recovered.lockRemoved, true);
  assert.equal(recovered.journalPreserved, true);
  assert.equal(fs.existsSync(crashed.filePath), true);
  assert.equal(fs.existsSync(lock.filePath), false);
  crashed.lock = null;
  const resumed = journal(t, "RECONCILE_ONLY", directory);
  assert.equal(fs.existsSync(resumed.lock.filePath), true);
});

test("root action gate rejects phase skips and any unlisted project action", async () => {
  const gate = new RootActionGate();
  assert.equal(await gate.invoke(
    "discovery",
    "sts:GetCallerIdentity",
    async () => "root"
  ), "root");
  await assert.rejects(() => gate.invoke(
    "discovery",
    "cloudformation:CreateStack",
    async () => null
  ), /ONE_TIME_BOOTSTRAP_ROOT_ACTION_REJECTED/u);
  assert.throws(() => gate.advance("reconcile"),
    /ONE_TIME_BOOTSTRAP_ROOT_PHASE_REJECTED/u);
  gate.advance("setup");
  await assert.rejects(() => gate.invoke(
    "setup",
    "secretsmanager:GetSecretValue",
    async () => null
  ), /ONE_TIME_BOOTSTRAP_ROOT_ACTION_REJECTED/u);
});

test("every root lifecycle mutation performs an immediate deadline read before SDK dispatch", () => {
  const source = fs.readFileSync(new URL(
    "../scripts/run-one-time-bootstrap-ceremony.js",
    import.meta.url
  ), "utf8");
  for (const [method, command] of [
    ["createRole", "CreateRoleCommand"],
    ["tagRole", "TagRoleCommand"],
    ["putPolicy", "PutRolePolicyCommand"],
    ["deletePolicy", "DeleteRolePolicyCommand"],
    ["deleteRole", "DeleteRoleCommand"]
  ]) {
    const start = source.indexOf(`  async ${method}(`);
    const dispatch = source.indexOf(`new ${command}(`, start);
    const deadlineRead = source.lastIndexOf("this.now();", dispatch);
    assert.notEqual(start, -1, method);
    assert.notEqual(dispatch, -1, command);
    assert.equal(deadlineRead > start, true, `${method}:deadline`);
    assert.match(source.slice(deadlineRead, dispatch + command.length + 5),
      new RegExp(`this\\.now\\(\\);\\s*await this\\.iam\\.send\\(new ` +
        `${command}\\(`, "u"), `${method}:immediate-deadline-check`);
  }
  const logoutStart = source.indexOf("  async logout()");
  const logoutDispatch = source.indexOf(
    "const { stderr } = await execFileAsync(this.awsCliPath",
    logoutStart
  );
  assert.notEqual(logoutStart, -1);
  assert.notEqual(logoutDispatch, -1);
  assert.match(source.slice(logoutStart, logoutDispatch),
    /this\.destroy\(\);\s*this\.now\(\);\s*$/u);

  const boundaryPlan = {
    preparedAt: "2026-08-19T14:00:00.000Z",
    notAfter: "2026-08-19T15:00:00.000Z",
    authorization: {
      cleanupOnlyAuthorization: {
        expiresAt: "2026-08-20T15:00:00.000Z"
      }
    }
  };
  for (const [instant, accepted] of [
    ["2026-08-20T14:59:59.999Z", true],
    ["2026-08-20T15:00:00.000Z", false],
    ["2026-08-20T15:00:00.001Z", false]
  ]) {
    const provider = Object.create(AwsOneTimeBootstrapRootProvider.prototype);
    provider.allowExpiredCleanup = true;
    provider.clock = () => new Date(instant);
    provider.plan = boundaryPlan;
    if (accepted) {
      assert.equal(provider.now().toISOString(), instant);
    } else {
      assert.throws(() => provider.now(),
        /ONE_TIME_BOOTSTRAP_AWS_ROOT_CLOCK_REJECTED/u);
    }
  }
});

test("B0 mutation adapters recheck latest-dispatch deadline while read-only polling has a fixed tail", async () => {
  const source = fs.readFileSync(new URL(
    "../scripts/run-one-time-bootstrap-ceremony.js",
    import.meta.url
  ), "utf8");
  for (const [method, command] of [
    ["createChangeSet", "CreateChangeSetCommand"],
    ["executeChangeSet", "ExecuteChangeSetCommand"],
    ["enableTerminationProtection", "UpdateTerminationProtectionCommand"]
  ]) {
    const start = source.indexOf(`  async ${method}(`);
    const dispatch = source.indexOf(`new ${command}(`, start);
    const deadlineRead = source.lastIndexOf("this.dispatchNow();", dispatch);
    assert.notEqual(start, -1, method);
    assert.notEqual(dispatch, -1, command);
    assert.equal(deadlineRead > start, true, `${method}:deadline`);
    assert.match(source.slice(deadlineRead, dispatch + command.length + 5),
      new RegExp(`this\\.dispatchNow\\(\\);\\s*await this\\.` +
        `cloudFormation\\.send\\(new ${command}\\(`, "u"));
  }
  const writerStart = source.indexOf("  async createWriterProvider(");
  const writerDispatch = source.indexOf("new PutSecretValueCommand(",
    writerStart);
  assert.match(source.slice(writerStart, writerDispatch),
    /putSecretVersion:[\s\S]*?assertDispatchOpen\(\);\s*return secrets\.send\($/u);

  const plan = {
    notAfter: "2026-08-19T15:00:00.000Z",
    targets: {
      exact: {
        changeSetName: "exact-change-set",
        stackName: "exact-stack"
      }
    },
    account: { accountId: "123456789012" }
  };
  for (const [instant, accepted] of [
    ["2026-08-19T14:59:59.999Z", true],
    ["2026-08-19T15:00:00.000Z", false],
    ["2026-08-19T15:00:00.001Z", false]
  ]) {
    const provider = Object.create(AwsOneTimeBootstrapB0Provider.prototype);
    provider.clock = () => new Date(instant);
    provider.plan = plan;
    if (accepted) assert.equal(provider.dispatchNow().toISOString(), instant);
    else assert.throws(() => provider.dispatchNow(),
      /ONE_TIME_BOOTSTRAP_AWS_OPERATION_EXPIRED/u, instant);
  }
  const convergence = Object.create(AwsOneTimeBootstrapB0Provider.prototype);
  convergence.plan = plan;
  convergence.clock = () => new Date("2026-08-19T15:44:59.999Z");
  assert.equal(convergence.now().toISOString(),
    "2026-08-19T15:44:59.999Z");
  convergence.clock = () => new Date("2026-08-19T15:45:00.000Z");
  assert.throws(() => convergence.now(),
    /ONE_TIME_BOOTSTRAP_AWS_CONVERGENCE_EXPIRED/u);

  const delayed = Object.create(AwsOneTimeBootstrapB0Provider.prototype);
  let tick = 0;
  delayed.plan = plan;
  delayed.clock = () => new Date([
    "2026-08-19T15:00:00.001Z",
    "2026-08-19T15:00:01.001Z"
  ][Math.min(tick++, 1)]);
  let reads = 0;
  delayed.cloudFormation = {
    async send(command) {
      reads += 1;
      if (command.constructor.name === "DescribeChangeSetCommand") {
        return reads === 1 ? {
          Status: "CREATE_IN_PROGRESS"
        } : {
          Status: "FAILED",
          ExecutionStatus: "UNAVAILABLE"
        };
      }
      throw new Error("UNEXPECTED_READ");
    }
  };
  const observed = await delayed.inspectChangeSet({ targetKey: "exact" });
  assert.equal(observed.state, "CONFLICT");
  assert.equal(reads, 2);
});

test("real root gate reconciles dispatched root and writer sessions from CloudTrail", async (t) => {
  const directory = privateDirectory(t);
  const plan = {
    ...PLAN,
    account: { accountId: "123456789012" },
    bootstrapRole: {
      arn: "arn:aws:iam::123456789012:role/prooftoact/bootstrap/B0"
    },
    notAfter: "2026-08-18T15:30:00.000Z",
    sessionContract: { roleSessionName: "b0-session" },
    writerContract: {
      roleArn: "arn:aws:iam::123456789012:role/prooftoact/bootstrap/Writer",
      roleSessionName: "writer-session"
    }
  };
  const active = new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: directory,
    mode: "NEW",
    plan
  });
  active.recordIntent("root-assume-b0-session", "sts:AssumeRole", {
    roleArn: plan.bootstrapRole.arn
  });
  active.recordDispatchStarted("root-assume-b0-session");
  active.recordIntent("b0-assume-a1-writer-session", "sts:AssumeRole", {
    roleArn: plan.writerContract.roleArn
  });
  active.recordDispatchStarted("b0-assume-a1-writer-session");
  active.releaseLock();
  const resumed = new OneTimeBootstrapJournal({
    clock: () => new Date("2026-08-18T14:16:00.000Z"),
    directoryPath: directory,
    mode: "RECONCILE_ONLY",
    plan
  });
  const gate = new RootActionGate();
  gate.advance("setup");
  let lookups = 0;
  let providerNow = Date.parse("2026-08-18T14:16:00.000Z");
  const rootProvider = {
    clock: () => new Date(providerNow),
    async lookupRootMutationEvents() {
      lookups += 1;
      return {
        rootAssumeEventTimes: ["2026-08-18T14:00:00.000Z"],
        rootDirectEvents: [],
        unexpectedRootMutationEvents: [],
        writerAssumeEventTimes: ["2026-08-18T14:00:30.000Z"]
      };
    },
    now() {
      return this.clock();
    },
    async sleep(milliseconds) {
      providerNow += milliseconds;
    },
    operationDeadline() {
      return new Date(plan.notAfter);
    }
  };
  await runnerTest.reconcilePriorLostSessions({
    gate,
    journal: resumed,
    plan,
    rootProvider
  });
  assert.equal(lookups, 2);
  assert.equal(resumed.step("root-assume-b0-session").state, "ACCEPTED");
  assert.equal(resumed.step("b0-assume-a1-writer-session").state,
    "ACCEPTED");
  assert.equal(resumed.step("root-assume-b0-session").receipt
    .sessionReceipt.recoveredAmbiguousDispatch, true);
  assert.equal(new Date(providerNow).toISOString(),
    "2026-08-18T14:20:30.000Z");
  assert.deepEqual(gate.invocations.map(({ action, phase }) =>
    `${phase}:${action}`), [
    "setup:cloudtrail:LookupEvents",
    "setup:cloudtrail:LookupEvents"
  ]);
});

test("accepted lost sessions wait through lifetime plus CloudTrail lag and cap each role at two", async (t) => {
  const plan = {
    ...PLAN,
    account: { accountId: "123456789012" },
    bootstrapRole: { arn: "arn:aws:iam::123456789012:role/B0" },
    notAfter: "2026-08-18T15:30:00.000Z",
    sessionContract: { roleSessionName: "b0-session" },
    writerContract: {
      roleArn: "arn:aws:iam::123456789012:role/Writer",
      roleSessionName: "writer-session"
    }
  };
  const active = new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: privateDirectory(t),
    mode: "NEW",
    plan
  });
  for (const [id, roleArn, expiration] of [
    ["root-assume-b0-session", plan.bootstrapRole.arn,
      "2026-08-18T14:15:00.000Z"],
    ["b0-assume-a1-writer-session", plan.writerContract.roleArn,
      "2026-08-18T14:16:00.000Z"]
  ]) {
    active.recordIntent(id, "sts:AssumeRole", { roleArn });
    active.recordDispatchStarted(id);
    active.recordAccepted(id, "POST_DISPATCH_RECONCILIATION", {
      sessionReceipt: {
        credentialsExpiration: expiration,
        roleArn,
        schemaVersion: "prooftoact.test-session.v1"
      }
    });
  }
  let now = Date.parse("2026-08-18T14:16:30.000Z");
  const gate = new RootActionGate();
  gate.advance("setup");
  let sleeps = 0;
  await runnerTest.reconcilePriorLostSessions({
    gate,
    journal: active,
    plan,
    rootProvider: {
      clock: () => new Date(now),
      async lookupRootMutationEvents() {
        throw new Error("ACCEPTED_SESSION_MUST_NOT_REQUERY");
      },
      now() {
        return new Date(now);
      },
      operationDeadline() {
        return new Date(plan.notAfter);
      },
      async sleep(milliseconds) {
        sleeps += 1;
        now += milliseconds;
      }
    }
  });
  assert.ok(sleeps > 0);
  assert.equal(new Date(now).toISOString(),
    "2026-08-18T14:21:00.000Z");
  for (const [base, ids] of [
    ["root-assume-b0-session", runnerTest.rootAssumeStepIds(active)],
    ["b0-assume-a1-writer-session", runnerTest.writerAssumeStepIds(active)]
  ]) {
    const continuation = runnerTest.nextSessionStepId(active, base, ids);
    assert.equal(continuation, `${base}-continuation-001`);
    active.recordIntent(continuation, "sts:AssumeRole", { roleArn: base });
    active.recordDispatchStarted(continuation);
    active.recordAccepted(continuation, "POST_DISPATCH_RECONCILIATION", {
      sessionReceipt: {
        credentialsExpiration: "2026-08-18T14:36:00.000Z",
        roleArn: base,
        schemaVersion: "prooftoact.test-session.v1"
      }
    });
    const capped = base.startsWith("root-") ?
      runnerTest.rootAssumeStepIds(active) :
      runnerTest.writerAssumeStepIds(active);
    assert.equal(capped.length, 2);
    assert.throws(() => runnerTest.nextSessionStepId(active, base, capped),
      /ONE_TIME_BOOTSTRAP_SESSION_COUNT_REJECTED/u);
  }
});

test("no-event AssumeRole ambiguity waits past max lifetime and never claims an event", async (t) => {
  const directory = privateDirectory(t);
  const plan = {
    ...PLAN,
    account: { accountId: "123456789012" },
    bootstrapRole: { arn: "arn:aws:iam::123456789012:role/B0" },
    notAfter: "2026-08-18T15:30:00.000Z",
    sessionContract: { roleSessionName: "b0-session" },
    writerContract: {
      roleArn: "arn:aws:iam::123456789012:role/Writer",
      roleSessionName: "writer-session"
    }
  };
  const active = new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: directory,
    mode: "NEW",
    plan
  });
  for (const [id, roleArn] of [
    ["root-assume-b0-session", plan.bootstrapRole.arn],
    ["b0-assume-a1-writer-session", plan.writerContract.roleArn]
  ]) {
    active.recordIntent(id, "sts:AssumeRole", { roleArn });
    active.recordDispatchStarted(id);
  }
  active.releaseLock();
  const resumed = new OneTimeBootstrapJournal({
    clock: () => new Date("2026-08-18T14:21:00.000Z"),
    directoryPath: directory,
    mode: "RECONCILE_ONLY",
    plan
  });
  const gate = new RootActionGate();
  gate.advance("setup");
  let lookups = 0;
  const rootProvider = {
    clock: () => new Date("2026-08-18T14:21:00.000Z"),
    async lookupRootMutationEvents() {
      lookups += 1;
      return {
        rootAssumeEventTimes: [],
        rootDirectEvents: [],
        unexpectedRootMutationEvents: [],
        writerAssumeEventTimes: []
      };
    },
    now() {
      return this.clock();
    },
    operationDeadline() {
      return new Date(plan.notAfter);
    }
  };
  await runnerTest.reconcilePriorLostSessions({
    gate,
    journal: resumed,
    plan,
    rootProvider
  });
  assert.equal(lookups, 2);
  for (const id of ["root-assume-b0-session",
    "b0-assume-a1-writer-session"]) {
    const receipt = resumed.step(id).receipt.sessionReceipt;
    assert.equal(receipt.assumeEventObserved, false);
    assert.equal(receipt.status,
      "AMBIGUOUS_ASSUME_MAX_LIFETIME_ELAPSED_WITHOUT_EVENT");
    assert.equal(Object.hasOwn(receipt, "eventTime"), false);
  }
  assert.equal(Object.keys(resumed.value.steps).length, 2);
});

test("cleanup tail reconciles a pre-expiry AssumeRole dispatch through session and CloudTrail lag", async (t) => {
  const directory = privateDirectory(t);
  const plan = {
    ...PLAN,
    account: { accountId: "123456789012" },
    authorization: {
      cleanupOnlyAuthorization: {
        expiresAt: "2026-08-19T15:00:00.000Z"
      },
      userAuthorizationReceiptSha256: "d".repeat(64)
    },
    bootstrapRole: { arn: "arn:aws:iam::123456789012:role/B0" },
    notAfter: "2026-08-18T15:00:00.000Z",
    sessionContract: { roleSessionName: "b0-session" },
    writerContract: {
      roleArn: "arn:aws:iam::123456789012:role/Writer",
      roleSessionName: "writer-session"
    }
  };
  const dispatchedAt = "2026-08-18T14:59:59.000Z";
  const active = new OneTimeBootstrapJournal({
    clock: () => new Date(dispatchedAt),
    directoryPath: directory,
    mode: "NEW",
    plan
  });
  active.recordIntent("root-assume-b0-session", "sts:AssumeRole", {
    roleArn: plan.bootstrapRole.arn
  });
  active.recordDispatchStarted("root-assume-b0-session");
  active.releaseLock();
  const cleanupNow = new Date("2026-08-18T15:20:00.000Z");
  const resumed = new OneTimeBootstrapJournal({
    clock: () => cleanupNow,
    directoryPath: directory,
    mode: "RECONCILE_ONLY",
    plan
  });
  const gate = new RootActionGate();
  gate.advance("setup");
  const rootProvider = {
    allowExpiredCleanup: true,
    clock: () => cleanupNow,
    async lookupRootMutationEvents() {
      return {
        rootAssumeEventTimes: [],
        rootDirectEvents: [],
        unexpectedRootMutationEvents: [],
        writerAssumeEventTimes: []
      };
    },
    now() {
      return cleanupNow;
    },
    operationDeadline() {
      return new Date(plan.authorization.cleanupOnlyAuthorization.expiresAt);
    }
  };
  await runnerTest.reconcilePriorLostSessions({
    gate,
    journal: resumed,
    plan,
    rootProvider
  });
  const accepted = resumed.step("root-assume-b0-session");
  assert.equal(accepted.state, "ACCEPTED");
  assert.equal(accepted.receipt.sessionReceipt.assumeEventObserved, false);
  assert.equal(accepted.receipt.sessionReceipt.credentialsExpiration,
    "2026-08-18T15:19:59.000Z");
});

test("abandoned cleanup never adopts a same-name role after ambiguous CreateRole", (t) => {
  const ambiguous = journal(t);
  ambiguous.recordIntent("root-create-b0-role", "iam:CreateRole", {
    roleName: "exact"
  });
  ambiguous.recordDispatchStarted("root-create-b0-role");
  const observed = {
    state: "MATCH",
    receipt: { roleId: "AROAEXACTROLE1234" }
  };
  assert.throws(() => runnerTest.abandonedCleanupRoleId(
    ambiguous,
    observed
  ), /ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED/u);
  assert.throws(() => runnerTest.abandonedCleanupRoleId(
    ambiguous,
    { state: "ABSENT" }
  ), /ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED/u);

  const neverDispatched = journal(t);
  neverDispatched.recordIntent("root-create-b0-role", "iam:CreateRole", {
    roleName: "exact"
  });
  assert.equal(runnerTest.abandonedCleanupRoleId(
    neverDispatched,
    { state: "ABSENT" }
  ), null);

  const accepted = journal(t);
  accepted.recordIntent("root-create-b0-role", "iam:CreateRole", {
    roleName: "exact"
  });
  accepted.recordDispatchStarted("root-create-b0-role");
  accepted.recordAccepted(
    "root-create-b0-role",
    "POST_DISPATCH_RECONCILIATION",
    { roleId: "AROAEXACTROLE1234" }
  );
  assert.equal(runnerTest.abandonedCleanupRoleId(accepted, observed),
    "AROAEXACTROLE1234");
  assert.throws(() => runnerTest.abandonedCleanupRoleId(accepted, {
    state: "MATCH",
    receipt: { roleId: "AROAREPLACED12345" }
  }), /ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED/u);
});

function ambiguousCreateJournal(t, plan) {
  const active = new OneTimeBootstrapJournal({
    clock: () => new Date("2026-08-19T14:00:00.000Z"),
    directoryPath: privateDirectory(t),
    mode: "NEW",
    plan
  });
  active.recordIntent("root-create-b0-role", "iam:CreateRole", {
    roleName: plan.bootstrapRole.name
  });
  active.recordDispatchStarted("root-create-b0-role");
  return active;
}

function exactAmbiguousCreateRole(plan) {
  return {
    state: "MATCH",
    receipt: {
      arn: plan.bootstrapRole.arn,
      createdAt: "2026-08-19T14:00:00.000Z",
      exactTrust: true,
      roleId: "AROAEXACTROLE1234",
      roleName: plan.bootstrapRole.name
    }
  };
}

function exactCreateCloudTrail(plan) {
  return {
    rootAssumeEventTimes: [],
    rootCreateRoleReceipts: [{
      arn: plan.bootstrapRole.arn,
      createDate: "2026-08-19T14:00:00Z",
      eventTime: "2026-08-19T14:00:00.000Z",
      path: plan.bootstrapRole.path,
      roleId: "AROAEXACTROLE1234",
      roleName: plan.bootstrapRole.name
    }],
    rootDirectEvents: [{
      eventName: "CreateRole",
      roleName: plan.bootstrapRole.name,
      rolePath: plan.bootstrapRole.path
    }],
    unexpectedRootMutationEvents: [],
    writerAssumeEventTimes: []
  };
}

test("ambiguous CreateRole adopts only an exact CloudTrail response RoleId", async (t) => {
  const plan = abandonedCleanupPlan();
  const active = ambiguousCreateJournal(t, plan);
  const role = exactAmbiguousCreateRole(plan);
  const gate = new RootActionGate();
  gate.advance("setup");
  const reconciled = await runnerTest.reconcileAbandonedCreateRole({
    cloudTrail: exactCreateCloudTrail(plan),
    gate,
    journal: active,
    plan,
    role,
    rootProvider: {
      now: () => new Date("2026-08-19T16:00:00.000Z")
    }
  });
  assert.equal(reconciled, role);
  assert.equal(active.step("root-create-b0-role").state, "ACCEPTED");
  assert.equal(active.step("root-create-b0-role").receipt.roleId,
    "AROAEXACTROLE1234");
  assert.equal(runnerTest.abandonedCleanupRoleId(active, role),
    "AROAEXACTROLE1234");
});

test("ambiguous CreateRole holds on an absent read without authoritative provider evidence", async (t) => {
  const plan = abandonedCleanupPlan();
  const active = ambiguousCreateJournal(t, plan);
  const gate = new RootActionGate();
  gate.advance("setup");
  await assert.rejects(() => runnerTest.reconcileAbandonedCreateRole({
    cloudTrail: {
      rootCreateRoleReceipts: [],
      rootDirectEvents: [],
      unexpectedRootMutationEvents: []
    },
    gate,
    journal: active,
    plan,
    role: { state: "ABSENT" },
    rootProvider: {
      async inspectRole() {
        return exactAmbiguousCreateRole(plan);
      },
      async lookupRootMutationEvents() {
        return exactCreateCloudTrail(plan);
      },
      now: () => new Date("2026-08-19T16:00:00.000Z")
    }
  }), /ONE_TIME_BOOTSTRAP_CREATE_ROLE_RECONCILIATION_REJECTED/u);
  assert.equal(active.step("root-create-b0-role").state,
    "DISPATCH_STARTED");
  assert.equal(active.step("local-abandoned-create-role-absence"), null);
});

test("ambiguous CreateRole never converts repeated eventual-consistency absences into a terminal claim", async (t) => {
  const plan = abandonedCleanupPlan();
  const active = ambiguousCreateJournal(t, plan);
  const gate = new RootActionGate();
  gate.advance("setup");
  const noCreateEvidence = {
    rootCreateRoleReceipts: [],
    rootDirectEvents: [],
    unexpectedRootMutationEvents: []
  };
  await assert.rejects(() => runnerTest.reconcileAbandonedCreateRole({
    cloudTrail: noCreateEvidence,
    gate,
    journal: active,
    plan,
    role: { state: "ABSENT" },
    rootProvider: {
      async inspectRole() {
        return { state: "ABSENT" };
      },
      async lookupRootMutationEvents() {
        return noCreateEvidence;
      },
      now: () => new Date("2026-08-19T16:00:00.000Z")
    }
  }), /ONE_TIME_BOOTSTRAP_CREATE_ROLE_RECONCILIATION_REJECTED/u);
  assert.equal(active.step("local-abandoned-create-role-absence"), null);
  assert.throws(() => runnerTest.abandonedCleanupRoleId(
    active,
    { state: "ABSENT" }
  ), /ONE_TIME_BOOTSTRAP_ABANDONED_CLEANUP_REJECTED/u);
});

function abandonedCleanupPlan() {
  const roleName = "ProofToActBootstrapCreator-0123456789abcdef";
  const inlinePolicyName = "ProofToActBootstrapCreatorOnly-0123456789abcdef";
  const roleTags = [{ Key: "OperationId", Value: PLAN.operation.operationId }];
  return {
    ...PLAN,
    account: {
      accountId: "123456789012",
      mfaSerialArn:
        "arn:aws:iam::123456789012:mfa/root-account-mfa-device",
      rootPrincipalArn: "arn:aws:iam::123456789012:root",
      rootProfile: "default"
    },
    authorization: {
      cleanupOnlyAuthorization: {
        expiresAt: "2026-08-20T15:00:00.000Z"
      },
      userAuthorizationReceiptSha256: "d".repeat(64)
    },
    bootstrapRole: {
      arn: `arn:aws:iam::123456789012:role/prooftoact/bootstrap/${roleName}`,
      inlinePolicyName,
      inlinePolicySha256: "e".repeat(64),
      name: roleName,
      path: "/prooftoact/bootstrap/",
      roleTags
    },
    notAfter: "2026-08-19T15:00:00.000Z",
    preparedAt: "2026-08-19T14:00:00.000Z",
    sessionContract: {
      roleSessionName: "prooftoact-b0",
      sourceIdentity: "prooftoact-b0-source"
    },
    writerContract: {
      roleArn: "arn:aws:iam::123456789012:role/Writer",
      roleSessionName: "prooftoact-writer"
    }
  };
}

function abandonedSetupEvents(plan, state) {
  const events = [
    {
      eventName: "CreateRole",
      roleName: plan.bootstrapRole.name,
      rolePath: plan.bootstrapRole.path
    },
    {
      eventName: "TagRole",
      roleName: plan.bootstrapRole.name,
      tagsSha256: runnerTest.digest(plan.bootstrapRole.roleTags)
    },
    {
      eventName: "PutRolePolicy",
      policyName: plan.bootstrapRole.inlinePolicyName,
      policySha256: plan.bootstrapRole.inlinePolicySha256,
      roleName: plan.bootstrapRole.name
    }
  ];
  if (!state.policyPresent) events.push({
    eventName: "DeleteRolePolicy",
    policyName: plan.bootstrapRole.inlinePolicyName,
    roleName: plan.bootstrapRole.name
  });
  if (!state.rolePresent) events.push({
    eventName: "DeleteRole",
    roleName: plan.bootstrapRole.name
  });
  return events;
}

function abandonedRootProvider(plan, state, crashPoint) {
  const roleId = "AROAEXACTROLE1234";
  const targetCensus = Object.freeze(
    ["freshPrimaryBootstrapRole", "freshPrimaryCredentialCustody",
      "privateRecoveryQueryBootstrap"].map((targetKey) => Object.freeze({
      censusSha256: runnerTest.digest({ targetKey, absent: true }),
      changeSetCount: 0,
      changeSetSetSha256: runnerTest.digest([]),
      secretCensus: [],
      stack: {
        exactIdentity: true,
        stackIdSha256: null,
        stackStatus: "ABSENT",
        templateSha256: null,
        terminationProtection: null
      },
      targetKey
    }))
  );
  function inject(point) {
    if (crashPoint === point && !state.crashed) {
      state.crashed = true;
      throw new Error(`INJECTED_${point.toUpperCase().replaceAll("-", "_")}`);
    }
  }
  return {
    allowExpiredCleanup: true,
    clock: () => new Date("2026-08-19T16:00:00.000Z"),
    destroy() {
      state.destroyed = true;
    },
    async assertExactCleanupRole(expectedRoleId, posture) {
      assert.equal(expectedRoleId, roleId);
      assert.equal(state.rolePresent, true);
      assert.equal(posture.inlinePolicyPresent, state.policyPresent);
      assert.equal(posture.tagsPresent, true);
      return {};
    },
    async deletePolicy(expectedRoleId) {
      assert.equal(expectedRoleId, roleId);
      state.policyPresent = false;
    },
    async deleteRole(expectedRoleId) {
      assert.equal(expectedRoleId, roleId);
      assert.equal(state.policyPresent, false);
      state.rolePresent = false;
    },
    async inspectAbandonedTarget(targetKey, invoke) {
      await invoke("cloudformation:DescribeStacks", async () => ({}));
      await invoke("cloudformation:ListChangeSets", async () => ({}));
      return targetCensus.find((value) => value.targetKey === targetKey);
    },
    async inspectNamedRootLogin() {
      if (state.loginPresent) return { state: "ACTIVE" };
      inject("after-logout");
      return {
        state: "ABSENT",
        receipt: { namedRootLoginSessionUnavailable: true }
      };
    },
    async inspectPolicy() {
      return state.policyPresent ? {
        state: "MATCH",
        receipt: { policySha256: plan.bootstrapRole.inlinePolicySha256 }
      } : { state: "ABSENT" };
    },
    async inspectPolicyAbsent() {
      return state.policyPresent ? { state: "ABSENT" } : {
        state: "MATCH",
        receipt: { inlinePolicyAbsent: true }
      };
    },
    async inspectRole() {
      return state.rolePresent ? {
        state: "MATCH",
        receipt: { roleId }
      } : { state: "ABSENT" };
    },
    async inspectRoleAbsent() {
      if (state.rolePresent) {
        inject("after-policy-delete");
        return { state: "ABSENT" };
      }
      return {
        state: "MATCH",
        receipt: { bootstrapRoleAbsent: true }
      };
    },
    async inspectTags() {
      return { state: "MATCH", receipt: { tagsSha256: "f".repeat(64) } };
    },
    async logout() {
      state.loginPresent = false;
      return { logoutCommandCompleted: true };
    },
    async lookupRootMutationEvents() {
      if (!state.rolePresent) inject("after-role-delete");
      const evidence = {
        rootAssumeEventTimes: [],
        rootCreateRoleReceipts: [],
        rootDirectEvents: abandonedSetupEvents(plan, state),
        unexpectedRootMutationEvents: [],
        writerAssumeEventTimes: []
      };
      if (!state.rolePresent && crashPoint === "after-cloudtrail" &&
        !state.crashed) state.crashOnNextNow = true;
      return evidence;
    },
    now() {
      if (state.crashOnNextNow) {
        state.crashOnNextNow = false;
        inject("after-cloudtrail");
      }
      return this.clock();
    },
    operationDeadline() {
      return new Date(plan.authorization.cleanupOnlyAuthorization.expiresAt);
    }
  };
}

function abandonedJournal(t, plan) {
  const directory = privateDirectory(t);
  const initial = new OneTimeBootstrapJournal({
    clock: clock(),
    directoryPath: directory,
    mode: "NEW",
    plan
  });
  for (const [id, mutationClass, value] of [
    ["root-create-b0-role", "iam:CreateRole", {
      roleId: "AROAEXACTROLE1234"
    }],
    ["root-tag-b0-role", "iam:TagRole", { exactTags: true }],
    ["root-put-b0-inline-policy", "iam:PutRolePolicy", {
      exactPolicy: true
    }]
  ]) {
    initial.recordIntent(id, mutationClass, { exact: id });
    initial.recordDispatchStarted(id);
    initial.recordAccepted(id, "POST_DISPATCH_RECONCILIATION", value);
  }
  initial.releaseLock();
  return { directory };
}

test("abandoned partial cleanup resumes every durable crash boundary without recomputing authority", async (t) => {
  for (const crashPoint of [
    "after-disposition", "after-policy-delete", "after-role-delete",
    "after-cloudtrail", "after-logout"
  ]) {
    const plan = abandonedCleanupPlan();
    const { directory } = abandonedJournal(t, plan);
    const state = {
      crashed: false,
      destroyed: false,
      loginPresent: true,
      policyPresent: true,
      rolePresent: true
    };
    let active = new OneTimeBootstrapJournal({
      clock: clock(),
      directoryPath: directory,
      mode: "RECONCILE_ONLY",
      plan
    });
    active.cleanupOnly = true;
    const firstGate = new RootActionGate();
    firstGate.advance("setup");
    const firstProvider = abandonedRootProvider(plan, state, crashPoint);
    if (crashPoint === "after-disposition") {
      const original = firstProvider.inspectPolicyAbsent;
      firstProvider.inspectPolicyAbsent = async () => {
        injectAfterDisposition();
        return original.call(firstProvider);
      };
      function injectAfterDisposition() {
        if (!state.crashed) {
          state.crashed = true;
          throw new Error("INJECTED_AFTER_DISPOSITION");
        }
      }
    }
    await assert.rejects(() => runnerTest.cleanupAbandonedPartialBootstrap({
      gate: firstGate,
      journal: active,
      plan,
      rootProvider: firstProvider
    }), /INJECTED_/u, crashPoint);
    assert.equal(active.step("abandoned-partial-b0-disposition")?.state,
      "ACCEPTED", crashPoint);
    active.releaseLock();

    active = new OneTimeBootstrapJournal({
      clock: clock(),
      directoryPath: directory,
      mode: "RECONCILE_ONLY",
      plan
    });
    active.cleanupOnly = true;
    const resumedGate = new RootActionGate();
    resumedGate.advance("setup");
    const resumed = await runnerTest.cleanupAbandonedPartialBootstrap({
      gate: resumedGate,
      journal: active,
      plan,
      rootProvider: abandonedRootProvider(plan, state, crashPoint)
    });
    assert.equal(resumed.schemaVersion,
      "prooftoact.abandoned-partial-b0-cleanup.v2", crashPoint);
    assert.equal(resumed.publicDisposition, "HOLD", crashPoint);
    assert.equal(state.rolePresent, false, crashPoint);
    assert.equal(state.policyPresent, false, crashPoint);
    assert.equal(state.loginPresent, false, crashPoint);
    assert.equal(active.step("root-logout")?.state, "ACCEPTED", crashPoint);
    active.releaseLock();
  }
});

test("authorization receipt semantically binds root scope, cost, source, targets, and five value digests", () => {
  const accountId = "123456789012";
  const operationId = "123e4567-e89b-42d3-a456-426614174000";
  const sourceCommit = "1".repeat(40);
  const treeDigest = "2".repeat(40);
  const targetTemplateSha256 = {
    freshPrimaryBootstrapRole: "3".repeat(64),
    freshPrimaryCredentialCustody: "4".repeat(64),
    privateRecoveryQueryBootstrap: "5".repeat(64)
  };
  const writerValueSha256 = {
    auditor: "6".repeat(64),
    cloudApi: "7".repeat(64),
    credential: "8".repeat(64),
    mcp: "9".repeat(64),
    publisher: "a".repeat(64)
  };
  const costReconciliation =
    buildOneTimeBootstrapCostReconciliationReceipt({
      accountId,
      operationId,
      pricingObservedAt: "2026-08-18T14:00:00.000Z",
      pricingSourceSha256: {
        awsSecretsManager: "b".repeat(64),
        cockroachBasic: "c".repeat(64)
      },
      sourceCommit,
      targetTemplateSha256,
      treeDigest
    });
  const costCeiling = {
    currency: "USD",
    maximumMonthlyUsdCents: 350,
    maximumOneTimeUsdCents: 500,
    reconciliationReceipt: costReconciliation,
    reconciliationReceiptSha256: costReconciliation.receiptSha256
  };
  const privateRecoveryWorkflowCommits = {
    deployment: "c".repeat(40),
    secretSeal: "d".repeat(40)
  };
  const runtimeExecutionBinding = {
    exactRuntimeFixture: true
  };
  const runtimeExecutionBindingSha256 =
    runnerTest.digest(runtimeExecutionBinding);
  const { humanAuthorizationBinding } =
    buildSyntheticProofToActHumanAuthorization({
      dynamicInput: {
    a1ApprovalId: "223e4567-e89b-42d3-a456-426614174001",
    a1CallerWorkflowRef: "Flash-Bri/prooftoact/.github/workflows/" +
      "prooftoact-fresh-primary.yml@refs/heads/main",
    a1CallerWorkflowSha: "e".repeat(40),
    a1ControllerImportGraphSha256: "f".repeat(64),
    a1CredentialSha256: {
      adoptedAdminPassword: "5".repeat(64),
      auditorTokenValue: writerValueSha256.auditor,
      creatorTokenValue: writerValueSha256.cloudApi
    },
    a1ProviderClusterId: "323e4567-e89b-42d3-a456-426614174002",
    a1ProviderReceiptSha256: {
      auditorAuthority: "0".repeat(64),
      creatorAuthority: "1".repeat(64),
      creatorProviderReadback: "2".repeat(64),
      manualCluster: "3".repeat(64),
      pricingSource: "4".repeat(64)
    },
    a1ReservationDeadline: "2026-08-18T15:00:00.000Z",
    a1SqlClusterId: "423e4567-e89b-42d3-a456-426614174003",
    accountId,
    authorizationNotBefore: "2026-08-18T14:00:00.000Z",
    b0DispatchDeadline: "2026-08-18T15:00:00.000Z",
    b0PrivateRecoveryWorkflowCommits: privateRecoveryWorkflowCommits,
    b0RuntimeExecutionBindingSha256: runtimeExecutionBindingSha256,
    b0TargetTemplateSha256: targetTemplateSha256,
    b0WriterValueSha256: writerValueSha256,
    cleanupRetentionDeadline: "2026-08-19T15:00:00.000Z",
    costAuthorization: {
      awsMonthlyResidualCeilingUsdCents: 350,
      cockroachMonthlySubCeilingUsdCents: 200,
      cockroachPaidWorstCaseMonthlyUsdCents: 150,
      combinedMonthlyCeilingUsdCents: 500,
      currency: "USD",
      freeBenefitsAssumed: false,
      maximumOneTimeUsdCents: 500,
      noAdditiveMonthlyCeilings: true,
      reconciliationReceiptSha256:
        costCeiling.reconciliationReceiptSha256
    },
    operationId,
    sourceCommit,
    treeDigest
      },
      inboundAt: "2026-08-18T14:00:00.000Z",
      outboundAt: "2026-08-18T14:00:00.000Z"
    });
  const receipt = buildOneTimeBootstrapAuthorizationReceipt({
    accountId,
    approvedBy: "BRIAN_SMITH",
    approvedAt: "2026-08-18T14:00:00.000Z",
    artifactBucketName: "prooftoact-private-artifacts-123456789012",
    cleanupOnlyAuthorizationApproved: true,
    costCeiling,
    expiresAt: "2026-08-18T15:00:00.000Z",
    githubOidcProviderArn: `arn:aws:iam::${accountId}:oidc-provider/` +
      "token.actions.githubusercontent.com",
    humanAuthorizationBinding,
    humanAuthorizationReceiptSha256:
      humanAuthorizationBinding.receiptBindingSha256,
    humanAuthorizedTextSha256:
      humanAuthorizationBinding.humanAuthorizedTextSha256,
    operationId,
    privateRecoveryWorkflowCommits,
    runtimeExecutionBindingSha256,
    sourceCommit,
    targetTemplateSha256,
    treeDigest,
    writerValueSha256
  });
  const plan = {
    account: { accountId },
    authorization: {
      cleanupOnlyAuthorization: receipt.cleanupOnlyAuthorization,
      userAuthorizationReceiptSha256: runnerTest.sha256(
        runnerTest.canonicalBytes(receipt)
      )
    },
    costCeiling,
    existingInputs: receipt.existingInputs,
    notAfter: receipt.expiresAt,
    operation: {
      operationId,
      operationToken: receipt.operationToken
    },
    source: {
      commit: sourceCommit,
      privateRecoveryWorkflowPins: {
        deployment: { commit: privateRecoveryWorkflowCommits.deployment },
        secretSeal: { commit: privateRecoveryWorkflowCommits.secretSeal }
      },
      runtimeExecutionBinding,
      tree: treeDigest
    },
    targets: Object.fromEntries(Object.entries(receipt.targets).map(
      ([key, value]) => [key, {
        parameters: key === "privateRecoveryQueryBootstrap" ? {
          DeploymentWorkflowCommit: privateRecoveryWorkflowCommits.deployment,
          SecretSealWorkflowCommit: privateRecoveryWorkflowCommits.secretSeal
        } : {},
        stackName: value.stackName,
        templateSha256: value.templateSha256
      }]
    ))
  };
  assert.equal(validateOneTimeBootstrapAuthorizationReceipt(
    plan,
    receipt,
    new Date("2026-08-18T14:01:00.000Z")
  ), receipt);
  for (const mutate of [
    (value) => { value.costCeiling.maximumMonthlyUsdCents += 1; },
    (value) => { value.rootScope.projectResourceAccessAuthorized = true; },
    (value) => { value.workloadStackAuthorized = true; },
    (value) => { value.sourceCommit = "f".repeat(40); },
    (value) => {
      value.targets.freshPrimaryCredentialCustody.templateSha256 =
        "e".repeat(64);
    },
    (value) => { value.writerValueSha256.publisher = "d".repeat(64); }
  ]) {
    const candidate = structuredClone(receipt);
    mutate(candidate);
    assert.throws(() => validateOneTimeBootstrapAuthorizationReceipt(
      plan,
      candidate,
      new Date("2026-08-18T14:01:00.000Z")
    ), /ONE_TIME_BOOTSTRAP_AUTHORIZATION_/u);
  }
});

test("exact 60-minute budget fits normal and no-event replacement cleanup strictly before expiry", () => {
  const timing = validateOneTimeBootstrapTimingBudget({
    preparedAt: "2026-08-18T14:00:00.000Z",
    notAfter: "2026-08-18T15:00:00.000Z"
  });
  assert.equal(timing.normalSessionExpiration,
    "2026-08-18T14:15:00.000Z");
  assert.equal(timing.noEventRetrySafeAt,
    "2026-08-18T14:20:00.000Z");
  assert.equal(timing.replacementSessionExpiration,
    "2026-08-18T14:35:00.000Z");
  assert.equal(timing.worstCaseCleanupBound,
    "2026-08-18T14:45:00.000Z");
  assert.ok(Date.parse(timing.worstCaseCleanupBound) <
    Date.parse("2026-08-18T15:00:00.000Z"));
  for (const notAfter of [
    "2026-08-18T14:59:59.999Z",
    "2026-08-18T15:00:00.001Z"
  ]) {
    assert.throws(() => validateOneTimeBootstrapTimingBudget({
      preparedAt: "2026-08-18T14:00:00.000Z",
      notAfter
    }), /ONE_TIME_BOOTSTRAP_TIMING_BUDGET_REJECTED/u);
  }
});

test("A1 nested continuation resumes crashes after secrets 1-4 and final ACK loss without rewriting", async (t) => {
  const targets = ["auditor", "cloudApi", "credential", "mcp",
    "publisher"];
  for (const crashAfter of [1, 2, 3, 4, 5]) {
    const directory = privateDirectory(t);
    const active = journal(t, "NEW", directory);
    const versions = new Set();
    const writes = Object.fromEntries(targets.map((name) => [name, 0]));
    let crashArmed = true;
    const approval = {
      schemaVersion: "synthetic.a1.approval.v1",
      expectedValueSha256: Object.fromEntries(targets.map((name, index) =>
        [name, String(index + 1).repeat(64)]))
    };
    const contract = {
      approvalSha256: String(crashAfter).repeat(64),
      exactWriteCount: 5,
      runtimeTargetWriteCount: 0
    };
    async function deterministicSeal() {
      for (const name of targets) {
        if (!versions.has(name)) {
          versions.add(name);
          writes[name] += 1;
          if (crashArmed && versions.size === crashAfter) {
            crashArmed = false;
            throw new Error(crashAfter === 5 ?
              "ACK_LOST_AFTER_FIFTH" : `CRASH_AFTER_${crashAfter}`);
          }
        }
      }
      return {
        status: "EXACT_FIVE_VERSIONS_SEALED_TWO_TARGETS_EMPTY",
        immutableVersionCount: versions.size,
        versionSetSha256: "f".repeat(64)
      };
    }
    await assert.rejects(() => runCrashConvergentSecretSeal({
      approval,
      contract,
      journal: active,
      seal: deterministicSeal,
      validateSealReceipt: (value) => value
    }), /ONE_TIME_BOOTSTRAP_SECRET_SEAL_PARTIAL_RECONCILIATION_REQUIRED/u);
    active.releaseLock();
    const resumed = journal(t, "RECONCILE_ONLY", directory);
    const accepted = await runCrashConvergentSecretSeal({
      approval,
      contract,
      journal: resumed,
      seal: deterministicSeal,
      validateSealReceipt: (value) => value
    });
    assert.equal(accepted.immutableVersionCount, 5);
    assert.equal([...versions].length, 5);
    assert.deepEqual(writes,
      Object.fromEntries(targets.map((name) => [name, 1])));
    assert.equal(resumed.step("seal-five-a1-writer-values")
      .continuationCount, 1);
  }
});

test("completion census is derived and hash-bound to accepted A1 sealed readback", () => {
  const writerTargets = ["auditor", "cloudApi", "credential", "mcp",
    "publisher"];
  const runtimeTargets = ["admin", "signer"];
  const secretNames = {
    admin: "prooftoact/fresh-primary/admin-op",
    auditor: "prooftoact/fresh-cluster/auditor",
    cloudApi: "prooftoact/fresh-primary/cloud-api",
    credential: "prooftoact/fresh-primary/runtime-credentials",
    mcp: "prooftoact/gate2/managed-mcp",
    publisher: "prooftoact/gate2/recovery-publisher",
    signer: "prooftoact/fresh-primary/recovery-signer-op"
  };
  const receipt = {
    phase: "SEALED",
    receiptSha256: "e".repeat(64),
    status: "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED",
    secrets: Object.fromEntries([
      ...writerTargets.map((name) => [name, { versionCount: 1 }]),
      ...runtimeTargets.map((name) => [name, { versionCount: 0 }])
    ])
  };
  const census = deriveA1SecretCensus({
    custodyPlan: { secretNames },
    runtimeTargets,
    writerTargets
  }, receipt);
  assert.equal(census.sourceReadbackReceiptSha256, receipt.receiptSha256);
  assert.deepEqual(census.initializedWriterTargets,
    writerTargets.map((name) => ({
      secretName: secretNames[name],
      versionCount: 1
    })));
  const drift = structuredClone(receipt);
  drift.secrets.publisher.versionCount = 0;
  assert.throws(() => deriveA1SecretCensus({
    custodyPlan: { secretNames },
    runtimeTargets,
    writerTargets
  }, drift), /ONE_TIME_BOOTSTRAP_A1_CENSUS_REJECTED/u);
});

test("real AWS provider custody surface maps stack outputs in EMPTY and SEALED phases", async (t) => {
  const creatorName = "ProofToActBootstrapCreator-0123456789abcdef";
  const creatorArn = `arn:aws:iam::123456789012:role/prooftoact/bootstrap/${creatorName}`;
  const custodyPlan = { marker: "exact-custody-plan" };
  const outputs = {
    AuditorSecretArn:
      "arn:aws:secretsmanager:us-east-1:123456789012:secret:auditor"
  };
  const mappedArns = { auditor: outputs.AuditorSecretArn };
  const provider = new AwsOneTimeBootstrapB0Provider({
    clock: () => new Date("2026-08-18T14:00:00.000Z"),
    credentials: {
      accessKeyId: "ASIAEXACTTESTCREDENTIAL",
      secretAccessKey: "x".repeat(40),
      sessionToken: "y".repeat(32)
    },
    plan: {
      bootstrapRole: { arn: creatorArn, name: creatorName },
      notAfter: "2026-08-18T14:30:00.000Z"
    }
  });
  const realIam = provider.iam;
  t.after(() => {
    provider.cloudFormation.destroy();
    realIam.destroy();
    provider.secrets.destroy();
    provider.sts.destroy();
  });
  let creatorPresent = true;
  provider.callerIdentity = async () => ({
    Account: "123456789012",
    Arn: "arn:aws:sts::123456789012:assumed-role/exact/session",
    UserId: "AROAEXACTEXACTEXACTEXA:session"
  });
  provider.collectStackForA1 = async (targetKey) => {
    assert.equal(targetKey, "freshPrimaryCredentialCustody");
    return {
      deployedTemplate: { Resources: {} },
      resources: [{ logicalResourceId: "Synthetic" }],
      stack: { outputs }
    };
  };
  provider.collectRole = async (roleName, options) => ({
    exactRoleName: roleName,
    includeCreatedAt: options.includeCreatedAt
  });
  provider.collectSecret = async (arn) => ({ arn, versions: {} });
  provider.iam = {
    async send(command) {
      assert.equal(command.constructor.name, "GetRoleCommand");
      assert.equal(command.input.RoleName, creatorName);
      if (!creatorPresent) {
        const cause = new Error("not found");
        cause.name = "NoSuchEntityException";
        throw cause;
      }
      return { Role: { Arn: creatorArn } };
    }
  };
  let mapperCalls = 0;
  const verifiedPhases = [];
  const a1 = {
    collectorBinding: { binding: "exact" },
    custodyPlan,
    secretArnsFromOutputs(input) {
      mapperCalls += 1;
      assert.equal(input.plan, custodyPlan);
      assert.equal(input.outputs, outputs);
      return mappedArns;
    },
    verifyCustodyReadback({ collectorBinding, input, plan }) {
      assert.equal(collectorBinding, a1.collectorBinding);
      assert.equal(plan, custodyPlan);
      assert.deepEqual(Object.keys(input).sort(), [
        "approval", "callerIdentity", "creatorRole", "deployedTemplate",
        "observedAt", "phase", "resources", "schemaVersion",
        "sealReceipt", "secrets", "stack", "writerRole"
      ]);
      assert.equal(input.schemaVersion,
        "prooftoact.fresh-primary-credential-custody-readback-input.v1");
      assert.deepEqual(Object.keys(input.secrets), ["auditor"]);
      verifiedPhases.push(input.phase);
      return input.phase === "EMPTY" ? { phase: "EMPTY" } : {
        phase: "SEALED",
        receiptSha256: "e".repeat(64),
        secrets: { auditor: { versionCount: 1 } },
        status: "EXACT_FIVE_SEALED_TWO_EMPTY_CREATOR_LIFECYCLE_ACCEPTED"
      };
    }
  };
  const empty = await runnerTest.collectAndVerifyA1CustodyPhase({
    a1,
    approval: null,
    b0Provider: provider,
    phase: "EMPTY",
    sealReceipt: null
  });
  assert.equal(empty.input.creatorRole.state, "PRESENT");
  assert.equal(empty.input.approval, null);
  assert.equal(empty.input.sealReceipt, null);

  creatorPresent = false;
  const approval = { exactApproval: true };
  const sealReceipt = { exactSealReceipt: true };
  const sealed = await runnerTest.collectAndVerifyA1CustodyPhase({
    a1,
    approval,
    b0Provider: provider,
    phase: "SEALED",
    sealReceipt
  });
  assert.equal(sealed.input.creatorRole.state, "DELETED");
  assert.equal(sealed.input.approval, approval);
  assert.equal(sealed.input.sealReceipt, sealReceipt);
  assert.equal(mapperCalls, 2);
  assert.deepEqual(verifiedPhases, ["EMPTY", "SEALED"]);
});

test("termination protection uses the exact accepted StackId and rejects replacement drift", async (t) => {
  const stackArn = "arn:aws:cloudformation:us-east-1:123456789012:stack/" +
    "exact/123e4567-e89b-42d3-a456-426614174000";
  const provider = new AwsOneTimeBootstrapB0Provider({
    clock: () => new Date("2026-08-18T14:00:00.000Z"),
    credentials: {
      accessKeyId: "ASIAEXACTTESTCREDENTIAL",
      secretAccessKey: "x".repeat(40),
      sessionToken: "y".repeat(32)
    },
    plan: {
      notAfter: "2026-08-18T15:00:00.000Z",
      targets: { exact: { stackName: "exact" } }
    }
  });
  const realCloudFormation = provider.cloudFormation;
  t.after(() => {
    realCloudFormation.destroy();
    provider.iam.destroy();
    provider.secrets.destroy();
    provider.sts.destroy();
  });
  const inputs = [];
  provider.inspectStack = async ({ expectedStackArn, targetKey }) => {
    assert.equal(expectedStackArn, stackArn);
    assert.equal(targetKey, "exact");
    return { state: "MATCH" };
  };
  provider.cloudFormation = {
    async send(command) {
      inputs.push({ name: command.constructor.name, input: command.input });
      if (command.constructor.name === "DescribeStacksCommand") {
        return {
          Stacks: [{ EnableTerminationProtection: true, StackId: stackArn }]
        };
      }
      return {};
    }
  };
  await provider.enableTerminationProtection({ stackArn, targetKey: "exact" });
  const inspected = await provider.inspectTerminationProtection({
    stackArn,
    targetKey: "exact"
  });
  assert.equal(inspected.state, "MATCH");
  assert.deepEqual(inputs.map(({ input }) => input.StackName),
    [stackArn, stackArn]);

  provider.cloudFormation.send = async () => ({
    Stacks: [{
      EnableTerminationProtection: true,
      StackId: `${stackArn}-replacement`
    }]
  });
  await assert.rejects(() => provider.inspectTerminationProtection({
    stackArn,
    targetKey: "exact"
  }), /ONE_TIME_BOOTSTRAP_STACK_ID_BINDING_REJECTED/u);
});

test("main prepares authorized writer values before any AWS provider and destroys them on every exit", () => {
  const source = fs.readFileSync(new URL(
    "../scripts/run-one-time-bootstrap-ceremony.js",
    import.meta.url
  ), "utf8");
  const main = source.slice(source.indexOf("export async function main"),
    source.indexOf("const startedDirectly"));
  const authorization = main.indexOf(
    "const authorization = validateOneTimeBootstrapAuthorizationBytes("
  );
  const prepare = main.indexOf(
    "valueLease.prepare(authorization.receipt.writerValueSha256);"
  );
  const rootProvider = main.indexOf(
    "new AwsOneTimeBootstrapRootProvider"
  );
  const b0Provider = main.indexOf("new AwsOneTimeBootstrapB0Provider");
  const destroy = main.lastIndexOf("valueLease.destroy();");
  assert.ok(authorization >= 0 && prepare > authorization);
  assert.ok(rootProvider > prepare && b0Provider > prepare);
  assert.ok(destroy > b0Provider);
  assert.match(main, /finally \{[\s\S]*valueLease\.destroy\(\);/u);
  assert.doesNotMatch(main,
    /ONE_TIME_BOOTSTRAP_LIVE_PROVIDER_ADAPTER_NOT_BOUND/u);
});
