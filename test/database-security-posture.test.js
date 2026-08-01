import assert from "node:assert/strict";
import test from "node:test";

import {
  quoteIdentifier,
  validateDatabaseSecurityPosture,
  validateManagedObjectGrants,
  validateNoSystemGrants,
  validatePrincipalOptions,
  validateRoleMemberships
} from "../src/cloud/database-security-posture.js";

const SPEC = Object.freeze({
  databaseName: "tideproof",
  managedSchemas: ["tp_private", "tp_api"],
  roles: ["tp_owner", "tp_authorizer_role"],
  users: ["tp_authorizer_user"],
  bindings: [["tp_authorizer_role", "tp_authorizer_user"]]
});

const CLEAN = Object.freeze({
  principals: [
    { username: "tp_authorizer_role", options: ["NOLOGIN"] },
    { username: "tp_authorizer_user", options: [] },
    { username: "tp_owner", options: "{NOLOGIN}" }
  ],
  memberships: [{
    role_name: "tp_authorizer_role",
    member: "tp_authorizer_user",
    is_admin: false
  }],
  systemGrants: [],
  objectGrants: [{
    database_name: "tideproof",
    schema_name: "tp_api",
    grantee: "tp_authorizer_role",
    privilege_type: "EXECUTE",
    is_grantable: false
  }]
});

test("clean database posture validates and produces a stable digest", () => {
  const first = validateDatabaseSecurityPosture(CLEAN, SPEC);
  const second = validateDatabaseSecurityPosture(CLEAN, SPEC);
  assert.match(first.postureDigest, /^[a-f0-9]{64}$/u);
  assert.equal(first.postureDigest, second.postureDigest);
});

test("principal posture rejects login or privileged capability roles", () => {
  for (const options of [[], ["LOGIN"], ["NOLOGIN", "CREATEROLE"]]) {
    assert.throws(
      () => validatePrincipalOptions(
        [{ username: "tp_owner", options }],
        { roles: ["tp_owner"], users: [], allowMissing: false }
      ),
      /DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE/u
    );
  }
  assert.throws(
    () => validatePrincipalOptions(
      [{ username: "tp_authorizer_user", options: ["CREATEROLE"] }],
      { roles: [], users: ["tp_authorizer_user"], allowMissing: false }
    ),
    /DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE/u
  );
});

test("membership posture rejects external, admin, missing, and duplicate edges", () => {
  const options = {
    bindings: SPEC.bindings,
    managedPrincipals: [...SPEC.roles, ...SPEC.users]
  };
  assert.throws(
    () => validateRoleMemberships([{
      role_name: "external_role",
      member: "tp_authorizer_user",
      is_admin: false
    }], options),
    /DATABASE_POSTURE_EXTERNAL_MEMBERSHIP/u
  );
  assert.throws(
    () => validateRoleMemberships([{
      role_name: "tp_authorizer_role",
      member: "tp_authorizer_user",
      is_admin: true
    }], options),
    /DATABASE_POSTURE_ADMIN_MEMBERSHIP/u
  );
  assert.throws(
    () => validateRoleMemberships([], options),
    /DATABASE_POSTURE_MEMBERSHIP_MISSING/u
  );
  assert.throws(
    () => validateRoleMemberships([
      CLEAN.memberships[0],
      CLEAN.memberships[0]
    ], options),
    /DATABASE_POSTURE_MEMBERSHIP_DUPLICATE/u
  );
});

test("grant posture rejects system, direct-user, grantable, and out-of-scope grants", () => {
  assert.throws(
    () => validateNoSystemGrants([{ grantee: "tp_owner" }]),
    /DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE/u
  );
  assert.throws(
    () => validateManagedObjectGrants([{
      database_name: "tideproof",
      schema_name: "tp_api",
      grantee: "tp_authorizer_user",
      privilege_type: "SELECT",
      is_grantable: false
    }], {
      databaseName: SPEC.databaseName,
      managedSchemas: SPEC.managedSchemas,
      runtimeUsers: SPEC.users
    }),
    /DATABASE_POSTURE_DIRECT_USER_GRANT/u
  );
  assert.throws(
    () => validateManagedObjectGrants([{
      database_name: "tideproof",
      schema_name: "tp_api",
      grantee: "tp_authorizer_role",
      privilege_type: "EXECUTE",
      is_grantable: true
    }], {
      databaseName: SPEC.databaseName,
      managedSchemas: SPEC.managedSchemas,
      runtimeUsers: SPEC.users
    }),
    /DATABASE_POSTURE_GRANT_OPTION_UNSAFE/u
  );
  assert.throws(
    () => validateManagedObjectGrants([{
      database_name: "some_other_database",
      schema_name: "public",
      grantee: "tp_authorizer_role",
      privilege_type: "SELECT",
      is_grantable: false
    }], {
      databaseName: SPEC.databaseName,
      managedSchemas: SPEC.managedSchemas,
      runtimeUsers: SPEC.users
    }),
    /DATABASE_POSTURE_OUT_OF_SCOPE_GRANT/u
  );
});

test("preflight mode tolerates only missing principals and managed drift", () => {
  const result = validateDatabaseSecurityPosture({
    principals: [],
    memberships: [],
    systemGrants: [],
    objectGrants: []
  }, SPEC, { allowMissing: true, allowManagedDrift: true });
  assert.equal(result.principalCount, 0);
});

test("bootstrap owner identifiers are quoted rather than trusted", () => {
  assert.equal(quoteIdentifier("reviewer"), '"reviewer"');
  assert.equal(quoteIdentifier('review"owner'), '"review""owner"');
  assert.throws(() => quoteIdentifier(""), /IDENTIFIER_INVALID/u);
});
