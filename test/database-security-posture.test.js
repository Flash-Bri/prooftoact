import assert from "node:assert/strict";
import test from "node:test";

import {
  collectClusterManagedGrantPosture,
  collectDatabaseSecurityPosture,
  quoteIdentifier,
  validateDatabaseSecurityPosture,
  validateDefaultGrants,
  validateManagedObjectGrants,
  validateNoSystemGrants,
  validatePrincipalOptions,
  validateRoleMemberships
} from "../src/cloud/database-security-posture.js";

const SPEC = Object.freeze({
  databaseName: "tideproof",
  managedSchemas: ["tp_private", "tp_api"],
  managedPrefixes: ["tp_"],
  apiSchema: "tp_api",
  ownerRoles: ["tp_owner"],
  roleGrantPolicies: Object.freeze({
    tp_authorizer_role: Object.freeze({
      functions: Object.freeze(["g1_spend_authority_v1(UUID)"])
    })
  }),
  roles: ["tp_owner", "tp_authorizer_role"],
  users: ["tp_authorizer_user"],
  bindings: [["tp_authorizer_role", "tp_authorizer_user"]]
});

const CLEAN = Object.freeze({
  session: [{
    database_name: "tideproof",
    current_user_name: "cluster_admin",
    session_user_name: "cluster_admin",
    database_version: "CockroachDB CCL v26.2.1"
  }],
  principals: [
    { username: "admin", options: [] },
    { username: "cluster_admin", options: [] },
    { username: "external_observer", options: ["NOLOGIN"] },
    { username: "tp_authorizer_role", options: ["NOLOGIN"] },
    { username: "tp_authorizer_user", options: [] },
    { username: "tp_owner", options: "{NOLOGIN}" }
  ],
  memberships: [
    {
      role_name: "admin",
      member: "cluster_admin",
      is_admin: false
    },
    {
      role_name: "tp_authorizer_role",
      member: "tp_authorizer_user",
      is_admin: false
    }
  ],
  systemGrants: [{
    grantee: "cluster_admin",
    privilege_type: "VIEWACTIVITY",
    grant_option: true
  }],
  objectGrants: [
    {
      database_name: "tideproof",
      schema_name: null,
      object_name: null,
      object_type: "database",
      grantee: "cluster_admin",
      privilege_type: "ALL",
      is_grantable: true
    },
    {
      database_name: "tideproof",
      schema_name: "public",
      object_name: null,
      object_type: "schema",
      grantee: "public",
      privilege_type: "USAGE",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: "tp_private",
      object_name: "g1_resources",
      object_type: "table",
      grantee: "tp_owner",
      privilege_type: "ALL",
      is_grantable: true
    },
    {
      database_name: "tideproof",
      schema_name: null,
      object_name: null,
      object_type: "database",
      grantee: "tp_authorizer_role",
      privilege_type: "CONNECT",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: "tp_api",
      object_name: null,
      object_type: "schema",
      grantee: "tp_authorizer_role",
      privilege_type: "USAGE",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: "tp_api",
      object_name: "g1_spend_authority_v1(uuid)",
      object_type: "function",
      grantee: "tp_authorizer_role",
      privilege_type: "EXECUTE",
      is_grantable: false
    }
  ],
  defaultGrants: [
    {
      database_name: "tideproof",
      schema_name: null,
      role: "tp_owner",
      for_all_roles: false,
      object_type: "tables",
      grantee: "tp_owner",
      privilege_type: "ALL",
      is_grantable: true
    },
    {
      database_name: "tideproof",
      schema_name: null,
      role: null,
      for_all_roles: true,
      object_type: "routines",
      grantee: "public",
      privilege_type: "EXECUTE",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: null,
      role: null,
      for_all_roles: true,
      object_type: "types",
      grantee: "public",
      privilege_type: "USAGE",
      is_grantable: false
    }
  ]
});

const OBJECT_OPTIONS = Object.freeze({
  databaseName: SPEC.databaseName,
  managedSchemas: SPEC.managedSchemas,
  managedPrefixes: SPEC.managedPrefixes,
  apiSchema: SPEC.apiSchema,
  ownerRoles: SPEC.ownerRoles,
  roleGrantPolicies: SPEC.roleGrantPolicies,
  runtimeUsers: SPEC.users,
  trustedPrincipals: ["cluster_admin"]
});

test("clean exhaustive database posture validates and binds the census", () => {
  const first = validateDatabaseSecurityPosture(CLEAN, SPEC);
  const second = validateDatabaseSecurityPosture({
    ...CLEAN,
    principals: [...CLEAN.principals].reverse(),
    objectGrants: [...CLEAN.objectGrants].reverse()
  }, SPEC);
  assert.match(first.postureDigest, /^[a-f0-9]{64}$/u);
  assert.equal(first.postureDigest, second.postureDigest);
  assert.equal(first.principalCount, 3);
  assert.equal(first.censusPrincipalCount, 6);
  assert.equal(first.objectGrantCount, 3);
  assert.equal(first.censusObjectGrantCount, 6);
});

test("principal census rejects unsafe options and stale managed names", () => {
  for (const options of [[], ["LOGIN"], ["NOLOGIN", "CREATEROLE"]]) {
    assert.throws(
      () => validatePrincipalOptions(
        [{ username: "tp_owner", options }],
        {
          roles: ["tp_owner"],
          users: [],
          managedPrefixes: ["tp_"],
          allowMissing: false
        }
      ),
      /DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE/u
    );
  }
  assert.throws(
    () => validatePrincipalOptions(
      [{ username: "tp_retired_authorizer", options: ["NOLOGIN"] }],
      {
        roles: [],
        users: [],
        managedPrefixes: ["tp_"],
        allowMissing: true
      }
    ),
    /DATABASE_POSTURE_STALE_PRINCIPAL/u
  );
  for (const options of [[], ["CREATEROLE"]]) {
    assert.throws(
      () => validatePrincipalOptions(
        [{ username: "external_operator", options }],
        {
          roles: [],
          users: [],
          managedPrefixes: ["tp_"],
          trustedPrincipals: ["cluster_admin"],
          allowMissing: true
        }
      ),
      /DATABASE_POSTURE_EXTERNAL_PRINCIPAL_CAPABILITY/u
    );
  }
});

test("membership census rejects external, admin, missing, and duplicate edges", () => {
  const options = {
    bindings: SPEC.bindings,
    managedPrincipals: [...SPEC.roles, ...SPEC.users],
    managedPrefixes: SPEC.managedPrefixes
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
    () => validateRoleMemberships(
      [CLEAN.memberships[1], CLEAN.memberships[1]],
      options
    ),
    /DATABASE_POSTURE_MEMBERSHIP_DUPLICATE/u
  );
  assert.throws(
    () => validateRoleMemberships([{
      role_name: "admin",
      member: "external_operator",
      is_admin: false
    }], { ...options, trustedPrincipals: ["admin", "cluster_admin"] }),
    /DATABASE_POSTURE_EXTERNAL_MEMBERSHIP/u
  );
});

test("system grant census trusts only the explicit bootstrap boundary", () => {
  assert.deepEqual(
    validateNoSystemGrants([{
      grantee: "cluster_admin",
      privilege_type: "VIEWACTIVITY",
      grant_option: true
    }], { trustedPrincipals: ["cluster_admin"] }),
    { systemGrantCount: 0, censusSystemGrantCount: 1 }
  );
  for (const grantee of ["external_operator", "tp_authorizer_role"]) {
    assert.throws(
      () => validateNoSystemGrants([{
        grantee,
        privilege_type: "VIEWACTIVITY",
        grant_option: false
      }], {
        trustedPrincipals: ["cluster_admin"],
        managedPrincipals: [...SPEC.roles, ...SPEC.users],
        managedPrefixes: SPEC.managedPrefixes
      }),
      /DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE/u
    );
  }
});

test("object grant census rejects direct, grantable, external, and stale capability", () => {
  const unsafe = [
    {
      row: {
        database_name: "tideproof",
        schema_name: "tp_api",
        object_name: "g1_spend_authority_v1(uuid)",
        object_type: "function",
        grantee: "tp_authorizer_user",
        privilege_type: "EXECUTE",
        is_grantable: false
      },
      code: /DATABASE_POSTURE_DIRECT_USER_GRANT/u
    },
    {
      row: {
        database_name: "tideproof",
        schema_name: "tp_api",
        object_name: "g1_spend_authority_v1(uuid)",
        object_type: "function",
        grantee: "tp_authorizer_role",
        privilege_type: "EXECUTE",
        is_grantable: true
      },
      code: /DATABASE_POSTURE_GRANT_OPTION_UNSAFE/u
    },
    {
      row: {
        database_name: "tideproof",
        schema_name: "tp_private",
        object_name: "g1_resources",
        object_type: "table",
        grantee: "external_reader",
        privilege_type: "SELECT",
        is_grantable: false
      },
      code: /DATABASE_POSTURE_EXTERNAL_OBJECT_GRANT/u
    },
    {
      row: {
        database_name: "tideproof",
        schema_name: "tp_api",
        object_name: "g1_spend_authority_v1(uuid)",
        object_type: "function",
        grantee: "tp_retired_role",
        privilege_type: "EXECUTE",
        is_grantable: false
      },
      code: /DATABASE_POSTURE_STALE_PRINCIPAL/u
    }
  ];
  for (const entry of unsafe) {
    assert.throws(
      () => validateManagedObjectGrants(
        [entry.row],
        { ...OBJECT_OPTIONS, allowMissingExpected: true }
      ),
      entry.code
    );
  }
});

test("managed grant census rejects unexpected and missing capabilities", () => {
  assert.throws(
    () => validateManagedObjectGrants([{
      database_name: "tideproof",
      schema_name: "tp_private",
      object_name: "g1_resources",
      object_type: "table",
      grantee: "tp_authorizer_role",
      privilege_type: "SELECT",
      is_grantable: false
    }], { ...OBJECT_OPTIONS, allowMissingExpected: true }),
    /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
  );
  assert.throws(
    () => validateManagedObjectGrants([], OBJECT_OPTIONS),
    /DATABASE_POSTURE_MANAGED_GRANT_MISSING/u
  );
  assert.throws(
    () => validateManagedObjectGrants([{
      database_name: "tideproof",
      schema_name: "tp_api",
      object_name: "g1_spend_authority_v1(string)",
      object_type: "function",
      grantee: "tp_authorizer_role",
      privilege_type: "EXECUTE",
      is_grantable: false
    }], OBJECT_OPTIONS),
    /DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED/u
  );
});

test("routine census canonicalizes CockroachDB v26.2 identity aliases", () => {
  assert.deepEqual(
    validateManagedObjectGrants([{
      database_name: "tideproof",
      schema_name: "tp_api",
      object_name: "alias_probe(text, bigint, timestamptz)",
      object_type: "function",
      grantee: "tp_authorizer_role",
      privilege_type: "EXECUTE",
      is_grantable: false
    }], {
      ...OBJECT_OPTIONS,
      roleGrantPolicies: {
        tp_authorizer_role: {
          functions: ["alias_probe(STRING, INT8, TIMESTAMPTZ)"]
        }
      },
      allowMissingExpected: true
    }),
    { objectGrantCount: 1, censusObjectGrantCount: 1 }
  );
});

test("default grant census rejects inherited future capability", () => {
  assert.throws(
    () => validateDefaultGrants([{
      database_name: "tideproof",
      schema_name: "tp_private",
      role: "tp_owner",
      for_all_roles: false,
      object_type: "tables",
      grantee: "external_reader",
      privilege_type: "SELECT",
      is_grantable: false
    }], {
      databaseName: SPEC.databaseName,
      managedSchemas: SPEC.managedSchemas,
      managedPrincipals: [...SPEC.roles, ...SPEC.users],
      ownerRoles: SPEC.ownerRoles,
      trustedPrincipals: ["cluster_admin"],
      managedPrefixes: SPEC.managedPrefixes
    }),
    /DATABASE_POSTURE_DEFAULT_GRANT_UNSAFE/u
  );
  for (const row of [
    {
      database_name: "tideproof",
      schema_name: "tp_private",
      role: "tp_owner",
      for_all_roles: false,
      object_type: "tables",
      grantee: "tp_owner",
      privilege_type: "ALL",
      is_grantable: true
    },
    {
      database_name: "tideproof",
      schema_name: null,
      role: "tp_owner",
      for_all_roles: false,
      object_type: "tables",
      grantee: "tp_owner",
      privilege_type: "ALL",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: "tp_api",
      role: "tp_owner",
      for_all_roles: false,
      object_type: "routines",
      grantee: "public",
      privilege_type: "EXECUTE",
      is_grantable: true
    },
    {
      database_name: "tideproof",
      schema_name: "tp_api",
      role: null,
      for_all_roles: true,
      object_type: "types",
      grantee: "public",
      privilege_type: "USAGE",
      is_grantable: false
    },
    {
      database_name: "tideproof",
      schema_name: "unmanaged_schema",
      role: "tp_owner",
      for_all_roles: false,
      object_type: "tables",
      grantee: "tp_owner",
      privilege_type: "SELECT",
      is_grantable: false
    }
  ]) {
    assert.throws(
      () => validateDefaultGrants([row], {
        databaseName: SPEC.databaseName,
        managedSchemas: SPEC.managedSchemas,
        managedPrincipals: [...SPEC.roles, ...SPEC.users],
        ownerRoles: SPEC.ownerRoles,
        trustedPrincipals: ["cluster_admin"],
        managedPrefixes: SPEC.managedPrefixes
      }),
      /DATABASE_POSTURE_(?:DEFAULT_GRANT_UNSAFE|OUT_OF_SCOPE_GRANT)/u
    );
  }
});

test("preflight permits only missing expected state and documented bootstrap defaults", () => {
  const result = validateDatabaseSecurityPosture({
    session: CLEAN.session,
    principals: [{ username: "cluster_admin", options: [] }],
    memberships: [CLEAN.memberships[0]],
    systemGrants: [],
    objectGrants: [
      {
        database_name: "tideproof",
        schema_name: null,
        object_name: null,
        object_type: "database",
        grantee: "public",
        privilege_type: "CONNECT",
        is_grantable: false
      },
      {
        database_name: "tideproof",
        schema_name: null,
        object_name: null,
        object_type: "database",
        grantee: "public",
        privilege_type: "TEMPORARY",
        is_grantable: false
      },
      {
        database_name: "tideproof",
        schema_name: "public",
        object_name: null,
        object_type: "schema",
        grantee: "public",
        privilege_type: "CREATE",
        is_grantable: false
      }
    ],
    defaultGrants: [{
      database_name: "tideproof",
      schema_name: null,
      role: "cluster_admin",
      for_all_roles: false,
      object_type: "routines",
      grantee: "public",
      privilege_type: "EXECUTE",
      is_grantable: false
    }]
  }, SPEC, {
    allowMissingPrincipals: true,
    allowMissingExpectedCapabilities: true,
    allowBootstrapDefaults: true
  });
  assert.equal(result.principalCount, 0);
});

test("bootstrap defaults are rejected once a managed principal or surface exists", () => {
  const publicConnect = {
    database_name: "tideproof",
    schema_name: null,
    object_name: null,
    object_type: "database",
    grantee: "public",
    privilege_type: "CONNECT",
    is_grantable: false
  };
  const options = {
    allowMissingPrincipals: true,
    allowMissingExpectedCapabilities: true,
    allowBootstrapDefaults: true
  };
  for (const posture of [
    {
      session: CLEAN.session,
      principals: [
        { username: "cluster_admin", options: [] },
        { username: "tp_owner", options: ["NOLOGIN"] }
      ],
      memberships: [CLEAN.memberships[0]],
      systemGrants: [],
      objectGrants: [publicConnect],
      defaultGrants: []
    },
    {
      session: CLEAN.session,
      principals: [{ username: "cluster_admin", options: [] }],
      memberships: [CLEAN.memberships[0]],
      systemGrants: [],
      objectGrants: [
        publicConnect,
        {
          database_name: "tideproof",
          schema_name: "tp_private",
          object_name: "g1_resources",
          object_type: "table",
          grantee: "cluster_admin",
          privilege_type: "ALL",
          is_grantable: true
        }
      ],
      defaultGrants: []
    }
  ]) {
    assert.throws(
      () => validateDatabaseSecurityPosture(posture, SPEC, options),
      /DATABASE_POSTURE_EXTERNAL_OBJECT_GRANT/u
    );
  }
});

test("sibling database principals are recognized but remain capability-free", () => {
  const siblingSpec = {
    ...SPEC,
    optionalRoles: ["tp_recovery_publisher_role"],
    optionalUsers: ["tp_recovery_publisher_user"],
    optionalBindings: [[
      "tp_recovery_publisher_role",
      "tp_recovery_publisher_user"
    ]]
  };
  const siblingPrincipals = [
    { username: "tp_recovery_publisher_role", options: ["NOLOGIN"] },
    { username: "tp_recovery_publisher_user", options: [] }
  ];
  const siblingMembership = {
    role_name: "tp_recovery_publisher_role",
    member: "tp_recovery_publisher_user",
    is_admin: false
  };
  const accepted = validateDatabaseSecurityPosture({
    ...CLEAN,
    principals: [...CLEAN.principals, ...siblingPrincipals],
    memberships: [...CLEAN.memberships, siblingMembership]
  }, siblingSpec);
  assert.equal(accepted.principalCount, 3);
  assert.equal(accepted.knownPrincipalCount, 5);

  assert.throws(
    () => validateDatabaseSecurityPosture({
      ...CLEAN,
      principals: [...CLEAN.principals, ...siblingPrincipals],
      memberships: [...CLEAN.memberships, siblingMembership],
      objectGrants: [
        ...CLEAN.objectGrants,
        {
          database_name: "tideproof",
          schema_name: "tp_api",
          object_name: "g1_receipt_audit_v1",
          object_type: "view",
          grantee: "tp_recovery_publisher_role",
          privilege_type: "SELECT",
          is_grantable: false
        }
      ]
    }, siblingSpec),
    /DATABASE_POSTURE_CROSS_BOUNDARY_GRANT/u
  );
});

test("posture rejects role switching or a wrong database", () => {
  for (const session of [
    [{
      database_name: "tideproof",
      current_user_name: "admin",
      session_user_name: "cluster_admin",
      database_version: "CockroachDB CCL v26.2.1"
    }],
    [{
      database_name: "defaultdb",
      current_user_name: "cluster_admin",
      session_user_name: "cluster_admin",
      database_version: "CockroachDB CCL v26.2.1"
    }],
    [{
      database_name: "tideproof",
      current_user_name: "cluster_admin",
      session_user_name: "cluster_admin",
      database_version: "CockroachDB CCL v26.3.0"
    }]
  ]) {
    assert.throws(
      () => validateDatabaseSecurityPosture({ ...CLEAN, session }, SPEC),
      /DATABASE_POSTURE_BOOTSTRAP_SESSION_UNSAFE/u
    );
  }
});

test("collector uses one read-only transaction with cache-versioned role introspection", async () => {
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      return { rows: [] };
    }
  };
  await collectDatabaseSecurityPosture(client);
  assert.equal(queries.length, 8);
  assert.match(
    queries[0],
    /BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY/u
  );
  assert.equal(queries.at(-1), "COMMIT");
  const source = queries.join("\n");
  assert.match(source, /version\(\) AS database_version/u);
  assert.match(source, /FROM \[SHOW USERS\]/u);
  assert.match(source, /FROM \[SHOW GRANTS ON ROLE\]/u);
  assert.match(source, /FROM \[SHOW SYSTEM GRANTS\]/u);
  assert.match(source, /SELECT grantee, privilege_type, is_grantable/u);
  assert.match(source, /object_name,\s+object_type,/u);
  assert.match(source, /WHERE database_name = current_database\(\)/u);
  assert.match(source, /schema_name NOT IN/u);
  assert.match(source, /FROM \[SHOW DEFAULT PRIVILEGES\]/u);
  assert.match(source, /current_database\(\) AS database_name/u);
  assert.match(source, /NULL::STRING AS schema_name/u);
  assert.match(source, /schema_name,\s+role,\s+for_all_roles,/u);
  assert.doesNotMatch(source, /WHERE (?:username|role_name|grantee) IN/u);
});

test("collector rolls back a failed census snapshot", async () => {
  const queries = [];
  const client = {
    async query(sql) {
      queries.push(sql);
      if (sql.includes("FROM [SHOW GRANTS ON ROLE]")) {
        throw new Error("catalog unavailable");
      }
      return { rows: [] };
    }
  };
  await assert.rejects(
    collectDatabaseSecurityPosture(client),
    /catalog unavailable/u
  );
  assert.equal(queries.at(-1), "ROLLBACK");
  assert.equal(queries.includes("COMMIT"), false);
});

function clusterClientFactory({ grantsByDatabase, secondDatabaseNames }) {
  let databaseEnumeration = 0;
  return (databaseName) => ({
    async connect() {},
    async end() {},
    async query(sql) {
      if (databaseName === null) {
        if (sql.includes("current_user AS current_user_name")) {
          return { rows: [{
            current_user_name: "cluster_admin",
            session_user_name: "cluster_admin",
            database_version: "CockroachDB CCL v26.2.1"
          }] };
        }
        if (sql.includes("FROM [SHOW GRANTS ON ROLE]")) {
          return { rows: [CLEAN.memberships[0]] };
        }
        if (sql.includes("FROM [SHOW DATABASES]")) {
          databaseEnumeration += 1;
          const names = databaseEnumeration === 1
            ? ["analytics", "tideproof", "tideproof_recovery"]
            : secondDatabaseNames ?? [
                "analytics",
                "tideproof",
                "tideproof_recovery"
              ];
          return { rows: names.map((name) => ({ database_name: name })) };
        }
      }
      if (sql.includes("current_database() AS database_name")) {
        return { rows: [{
          database_name: databaseName,
          current_user_name: "cluster_admin",
          session_user_name: "cluster_admin",
          database_version: "CockroachDB CCL v26.2.1"
        }] };
      }
      if (sql.includes("FROM [SHOW GRANTS]")) {
        return { rows: grantsByDatabase[databaseName] ?? [] };
      }
      return { rows: [] };
    }
  });
}

test("cluster census enforces database isolation with matching barriers", async () => {
  const principalDatabases = {
    tp_authorizer_role: "tideproof",
    tp_recovery_publisher_role: "tideproof_recovery"
  };
  const result = await collectClusterManagedGrantPosture({
    adminConnectionString: "postgresql://unused.invalid/tideproof",
    principalDatabases,
    createClient: clusterClientFactory({
      grantsByDatabase: {
        tideproof: [{
          database_name: "tideproof",
          schema_name: null,
          object_name: null,
          object_type: "database",
          grantee: "tp_authorizer_role",
          privilege_type: "CONNECT",
          is_grantable: false
        }],
        tideproof_recovery: [{
          database_name: "tideproof_recovery",
          schema_name: null,
          object_name: null,
          object_type: "database",
          grantee: "tp_recovery_publisher_role",
          privilege_type: "CONNECT",
          is_grantable: false
        }],
        analytics: [{
          database_name: "analytics",
          schema_name: "public",
          object_name: "events",
          object_type: "table",
          grantee: "external_analyst",
          privilege_type: "SELECT",
          is_grantable: false
        }]
      }
    })
  });
  assert.equal(result.databaseNames.length, 3);
  assert.equal(result.managedObjectGrants.length, 2);
  assert.match(result.postureDigest, /^[a-f0-9]{64}$/u);

  await assert.rejects(
    collectClusterManagedGrantPosture({
      adminConnectionString: "postgresql://unused.invalid/tideproof",
      principalDatabases,
      createClient: clusterClientFactory({
        grantsByDatabase: {
          analytics: [{
            database_name: "analytics",
            schema_name: "public",
            object_name: "events",
            object_type: "table",
            grantee: "tp_authorizer_role",
            privilege_type: "SELECT",
            is_grantable: false
          }]
        }
      })
    }),
    /DATABASE_POSTURE_OUT_OF_SCOPE_GRANT/u
  );
});

test("cluster census rejects database-set drift", async () => {
  await assert.rejects(
    collectClusterManagedGrantPosture({
      adminConnectionString: "postgresql://unused.invalid/tideproof",
      principalDatabases: { tp_authorizer_role: "tideproof" },
      createClient: clusterClientFactory({
        grantsByDatabase: {},
        secondDatabaseNames: [
          "analytics",
          "new_database",
          "tideproof",
          "tideproof_recovery"
        ]
      })
    }),
    /DATABASE_POSTURE_DATABASE_SET_CHANGED/u
  );
});

test("bootstrap owner identifiers are quoted rather than trusted", () => {
  assert.equal(quoteIdentifier("reviewer"), '"reviewer"');
  assert.equal(quoteIdentifier('review"owner'), '"review""owner"');
  assert.throws(() => quoteIdentifier(""), /IDENTIFIER_INVALID/u);
});
