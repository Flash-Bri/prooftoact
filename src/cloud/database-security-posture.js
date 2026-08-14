import { createHash } from "node:crypto";
import { Client } from "pg";
import { connectionStringForDatabase } from "./authority-store.js";
import { bootstrapDatabaseConfig } from "./database-runtime.js";

const DEFAULT_TRUSTED_PRINCIPALS = Object.freeze(["admin", "root", "node"]);
const TESTED_DATABASE_VERSION = /\bCockroachDB(?: CCL)? v26\.2(?:\.\d+)?\b/u;

function stablePostureError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

function text(value) {
  return typeof value === "string" ? value.trim() : "";
}

function boolean(value) {
  if (value === true || value === "true" || value === "YES") return true;
  if (value === false || value === "false" || value === "NO") return false;
  throw stablePostureError("DATABASE_POSTURE_BOOLEAN_INVALID");
}

function optionSet(value) {
  if (Array.isArray(value)) {
    return new Set(value.map((entry) => text(entry).toUpperCase()));
  }
  if (value === null || value === undefined || value === "" || value === "{}") {
    return new Set();
  }
  if (typeof value !== "string") {
    throw stablePostureError("DATABASE_POSTURE_OPTIONS_INVALID");
  }
  const stripped = value.replace(/^\{|\}$/gu, "");
  return new Set(
    stripped === ""
      ? []
      : stripped.split(",").map((entry) => text(entry).toUpperCase())
  );
}

function exactSet(actual, expected) {
  return (
    actual.size === expected.size &&
    [...actual].every((entry) => expected.has(entry))
  );
}

function canonical(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, nested]) => `${JSON.stringify(key)}:${canonical(nested)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isManagedName(value, managedPrefixes) {
  return managedPrefixes.some((prefix) => value.startsWith(prefix));
}

function requireRows(rows, code) {
  if (!Array.isArray(rows)) {
    throw stablePostureError(code);
  }
  return rows;
}

function normalizedObjectGrant(row) {
  return {
    databaseName: text(row?.database_name),
    schemaName: text(row?.schema_name),
    objectName: text(row?.object_name ?? row?.name),
    objectType: text(row?.object_type ?? row?.type).toUpperCase(),
    grantee: text(row?.grantee),
    privilegeType: text(row?.privilege_type).toUpperCase(),
    isGrantable: boolean(row?.is_grantable ?? row?.grant_option ?? false)
  };
}

function normalizedDefaultGrant(row) {
  return {
    databaseName: text(row?.database_name),
    schemaName: text(row?.schema_name),
    role: text(row?.role),
    forAllRoles: boolean(row?.for_all_roles ?? false),
    objectType: text(row?.object_type).toUpperCase(),
    grantee: text(row?.grantee),
    privilegeType: text(row?.privilege_type).toUpperCase(),
    isGrantable: boolean(row?.is_grantable ?? false)
  };
}

function canonicalRoutineIdentity(value, schemaName) {
  const signature = text(value)
    .replaceAll(/\s+/gu, "")
    .toLowerCase()
    .replaceAll(/\bstring\b/gu, "text")
    .replaceAll(/\bbigint\b/gu, "int8")
    .replaceAll(/\btimestampwithtimezone\b/gu, "timestamptz")
    .replaceAll(/\btimestampwithouttimezone\b/gu, "timestamp");
  const prefix = `${text(schemaName).toLowerCase()}.`;
  return signature.startsWith(prefix)
    ? signature.slice(prefix.length)
    : signature;
}

function roleGrantKey(grant, databaseName, apiSchema, managedSchemas) {
  if (
    grant.databaseName === databaseName &&
    grant.objectType === "DATABASE" &&
    grant.schemaName === "" &&
    grant.objectName === "" &&
    grant.privilegeType === "CONNECT"
  ) {
    return "DATABASE:CONNECT";
  }
  if (
    grant.databaseName === databaseName &&
    grant.objectType === "SCHEMA" &&
    managedSchemas.has(grant.schemaName) &&
    grant.objectName === "" &&
    grant.privilegeType === "USAGE"
  ) {
    return `SCHEMA:${grant.schemaName}:USAGE`;
  }
  if (
    grant.databaseName === databaseName &&
    ["FUNCTION", "ROUTINE"].includes(grant.objectType) &&
    grant.schemaName === apiSchema &&
    grant.privilegeType === "EXECUTE"
  ) {
    return `FUNCTION:${apiSchema}.${canonicalRoutineIdentity(
      grant.objectName,
      apiSchema
    )}:EXECUTE`;
  }
  if (
    grant.databaseName === databaseName &&
    ["TABLE", "VIEW"].includes(grant.objectType) &&
    grant.schemaName === apiSchema &&
    grant.privilegeType === "SELECT"
  ) {
    return `RELATION:${apiSchema}.${grant.objectName}:SELECT`;
  }
  return "";
}

function expectedRoleGrantKeys(policy, apiSchema) {
  return new Set([
    "DATABASE:CONNECT",
    ...(policy?.schemas ?? [apiSchema]).map(
      (schemaName) => `SCHEMA:${schemaName}:USAGE`
    ),
    ...(policy?.functions ?? []).map(
      (name) =>
        `FUNCTION:${apiSchema}.${canonicalRoutineIdentity(name, apiSchema)}:EXECUTE`
    ),
    ...(policy?.relations ?? []).map(
      (name) => `RELATION:${apiSchema}.${name}:SELECT`
    )
  ]);
}

function normalizedRows(rows, mapper) {
  return rows
    .map(mapper)
    .sort((left, right) => canonical(left).localeCompare(canonical(right)));
}

export function validatePrincipalOptions(
  rows,
  {
    roles,
    users,
    optionalRoles = [],
    optionalUsers = [],
    managedPrefixes = ["tp_"],
    trustedPrincipals = [],
    allowMissing = false
  }
) {
  requireRows(rows, "DATABASE_POSTURE_PRINCIPAL_CENSUS_INVALID");
  const required = new Map([
    ...roles.map((name) => [name, new Set(["NOLOGIN"])]),
    ...users.map((name) => [name, new Set()])
  ]);
  const optional = new Map([
    ...optionalRoles.map((name) => [name, new Set(["NOLOGIN"])]),
    ...optionalUsers.map((name) => [name, new Set()])
  ]);
  const expected = new Map([...required, ...optional]);
  const trusted = new Set(trustedPrincipals);
  const seen = new Set();
  const seenRequired = new Set();
  const seenKnown = new Set();
  for (const row of rows) {
    const username = text(row?.username);
    if (username === "" || seen.has(username)) {
      throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_SET_INVALID");
    }
    seen.add(username);
    if (!expected.has(username)) {
      if (isManagedName(username, managedPrefixes)) {
        throw stablePostureError("DATABASE_POSTURE_STALE_PRINCIPAL");
      }
      if (!trusted.has(username)) {
        const externalOptions = optionSet(row.options);
        if (!exactSet(externalOptions, new Set(["NOLOGIN"]))) {
          throw stablePostureError(
            "DATABASE_POSTURE_EXTERNAL_PRINCIPAL_CAPABILITY"
          );
        }
      }
      continue;
    }
    seenKnown.add(username);
    if (required.has(username)) seenRequired.add(username);
    if (!exactSet(optionSet(row.options), expected.get(username))) {
      throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE");
    }
  }
  if (!allowMissing && seenRequired.size !== required.size) {
    throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_MISSING");
  }
  return {
    principalCount: seenRequired.size,
    knownPrincipalCount: seenKnown.size,
    censusPrincipalCount: seen.size
  };
}

export function validateRoleMemberships(
  rows,
  {
    bindings,
    optionalBindings = [],
    managedPrincipals,
    managedPrefixes = ["tp_"],
    trustedPrincipals = [],
    allowMissing = false
  }
) {
  requireRows(rows, "DATABASE_POSTURE_MEMBERSHIP_CENSUS_INVALID");
  const managed = new Set(managedPrincipals);
  const trusted = new Set(trustedPrincipals);
  const expected = new Set(bindings.map(([role, member]) => `${role}\0${member}`));
  const allowed = new Set([
    ...expected,
    ...optionalBindings.map(([role, member]) => `${role}\0${member}`)
  ]);
  const observed = new Set();
  const census = new Set();
  for (const row of rows) {
    const role = text(row?.role_name);
    const member = text(row?.member);
    const key = `${role}\0${member}`;
    if (role === "" || member === "" || census.has(key)) {
      throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_DUPLICATE");
    }
    census.add(key);
    const relevant =
      managed.has(role) ||
      managed.has(member) ||
      isManagedName(role, managedPrefixes) ||
      isManagedName(member, managedPrefixes) ||
      trusted.has(role) ||
      trusted.has(member);
    if (!relevant) continue;
    if (
      (trusted.has(role) || trusted.has(member)) &&
      !(trusted.has(role) && trusted.has(member))
    ) {
      throw stablePostureError("DATABASE_POSTURE_EXTERNAL_MEMBERSHIP");
    }
    if (trusted.has(role) && trusted.has(member)) continue;
    if (!managed.has(role) || !managed.has(member)) {
      throw stablePostureError("DATABASE_POSTURE_EXTERNAL_MEMBERSHIP");
    }
    if (boolean(row?.is_admin)) {
      throw stablePostureError("DATABASE_POSTURE_ADMIN_MEMBERSHIP");
    }
    if (!allowed.has(key)) {
      throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_UNEXPECTED");
    }
    if (expected.has(key)) observed.add(key);
  }
  if (
    !allowMissing &&
    (observed.size !== expected.size ||
      [...expected].some((entry) => !observed.has(entry)))
  ) {
    throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_MISSING");
  }
  return {
    membershipCount: observed.size,
    censusMembershipCount: census.size
  };
}

export function validateBootstrapAdministrator(rows, bootstrapPrincipal) {
  requireRows(rows, "DATABASE_POSTURE_MEMBERSHIP_CENSUS_INVALID");
  if (["admin", "root"].includes(bootstrapPrincipal)) {
    return { bootstrapAdministrator: true };
  }
  const directAdminMemberships = rows.filter((row) =>
    text(row?.role_name) === "admin" &&
    text(row?.member) === bootstrapPrincipal
  );
  if (directAdminMemberships.length !== 1) {
    throw stablePostureError("DATABASE_POSTURE_BOOTSTRAP_ADMIN_REQUIRED");
  }
  return { bootstrapAdministrator: true };
}

export function validateNoSystemGrants(
  rows,
  {
    trustedPrincipals = [],
    managedPrincipals = [],
    managedPrefixes = ["tp_"]
  } = {}
) {
  requireRows(rows, "DATABASE_POSTURE_SYSTEM_GRANT_CENSUS_INVALID");
  const trusted = new Set(trustedPrincipals);
  const managed = new Set(managedPrincipals);
  const seen = new Set();
  for (const row of rows) {
    const grantee = text(row?.grantee);
    const privilege = text(row?.privilege_type).toUpperCase();
    const grantable = boolean(row?.grant_option ?? row?.is_grantable ?? false);
    const key = `${grantee}\0${privilege}\0${grantable}`;
    if (grantee === "" || privilege === "" || seen.has(key)) {
      throw stablePostureError("DATABASE_POSTURE_SYSTEM_GRANT_CENSUS_INVALID");
    }
    seen.add(key);
    if (
      managed.has(grantee) ||
      isManagedName(grantee, managedPrefixes) ||
      !trusted.has(grantee)
    ) {
      throw stablePostureError("DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE");
    }
  }
  return {
    systemGrantCount: 0,
    censusSystemGrantCount: seen.size
  };
}

export function validateManagedObjectGrants(
  rows,
  {
    databaseName,
    managedSchemas,
    runtimeUsers,
    knownManagedPrincipals = [],
    roleGrantPolicies = {},
    ownerRoles = [],
    managedPrefixes = ["tp_"],
    trustedPrincipals = [],
    apiSchema,
    allowMissingExpected = false,
    allowBootstrapDefaults = false
  }
) {
  requireRows(rows, "DATABASE_POSTURE_OBJECT_GRANT_CENSUS_INVALID");
  const schemas = new Set(managedSchemas);
  const users = new Set(runtimeUsers);
  const runtimeRoles = new Set(Object.keys(roleGrantPolicies));
  const owners = new Set(ownerRoles);
  const managed = new Set([...runtimeRoles, ...owners, ...users]);
  const knownManaged = new Set([...managed, ...knownManagedPrincipals]);
  const trusted = new Set(trustedPrincipals);
  const expected = new Map(
    Object.entries(roleGrantPolicies).map(([role, policy]) => [
      role,
      expectedRoleGrantKeys(policy, apiSchema)
    ])
  );
  const observed = new Map(
    [...runtimeRoles].map((role) => [role, new Set()])
  );
  const census = new Set();
  for (const row of rows) {
    const grant = normalizedObjectGrant(row);
    const rawKey = canonical(grant);
    if (
      grant.databaseName === "" ||
      grant.grantee === "" ||
      grant.privilegeType === "" ||
      grant.objectType === "" ||
      census.has(rawKey)
    ) {
      throw stablePostureError("DATABASE_POSTURE_OBJECT_GRANT_CENSUS_INVALID");
    }
    census.add(rawKey);
    if (
      isManagedName(grant.grantee, managedPrefixes) &&
      !knownManaged.has(grant.grantee)
    ) {
      throw stablePostureError("DATABASE_POSTURE_STALE_PRINCIPAL");
    }
    if (users.has(grant.grantee)) {
      throw stablePostureError("DATABASE_POSTURE_DIRECT_USER_GRANT");
    }
    if (managed.has(grant.grantee) && grant.databaseName !== databaseName) {
      throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
    }
    if (owners.has(grant.grantee)) {
      if (
        grant.databaseName !== databaseName ||
        (grant.schemaName !== "" && !schemas.has(grant.schemaName))
      ) {
        throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
      }
      continue;
    }
    if (runtimeRoles.has(grant.grantee)) {
      if (grant.isGrantable) {
        throw stablePostureError("DATABASE_POSTURE_GRANT_OPTION_UNSAFE");
      }
      const key = roleGrantKey(grant, databaseName, apiSchema, schemas);
      if (key === "" || !expected.get(grant.grantee).has(key)) {
        throw stablePostureError("DATABASE_POSTURE_MANAGED_GRANT_UNEXPECTED");
      }
      if (observed.get(grant.grantee).has(key)) {
        throw stablePostureError("DATABASE_POSTURE_MANAGED_GRANT_DUPLICATE");
      }
      observed.get(grant.grantee).add(key);
      continue;
    }
    if (knownManaged.has(grant.grantee)) {
      throw stablePostureError("DATABASE_POSTURE_CROSS_BOUNDARY_GRANT");
    }
    if (grant.databaseName !== databaseName) continue;
    if (trusted.has(grant.grantee)) continue;
    const publicSchemaUsage =
      grant.grantee === "public" &&
      grant.objectType === "SCHEMA" &&
      grant.schemaName === "public" &&
      grant.objectName === "" &&
      grant.privilegeType === "USAGE" &&
      !grant.isGrantable;
    const bootstrapPublicDefault =
      allowBootstrapDefaults &&
      grant.grantee === "public" &&
      !grant.isGrantable &&
      (
        (
          grant.objectType === "DATABASE" &&
          grant.schemaName === "" &&
          grant.objectName === "" &&
          ["CONNECT", "TEMPORARY"].includes(grant.privilegeType)
        ) ||
        (
          grant.objectType === "SCHEMA" &&
          grant.schemaName === "public" &&
          grant.objectName === "" &&
          grant.privilegeType === "CREATE"
        )
      );
    if (!publicSchemaUsage && !bootstrapPublicDefault) {
      throw stablePostureError("DATABASE_POSTURE_EXTERNAL_OBJECT_GRANT");
    }
  }
  if (!allowMissingExpected) {
    for (const role of runtimeRoles) {
      if (!exactSet(observed.get(role), expected.get(role))) {
        throw stablePostureError("DATABASE_POSTURE_MANAGED_GRANT_MISSING");
      }
    }
  }
  return {
    objectGrantCount: [...observed.values()].reduce(
      (total, grants) => total + grants.size,
      0
    ),
    censusObjectGrantCount: census.size
  };
}

export function validateDefaultGrants(
  rows,
  {
    databaseName,
    managedSchemas,
    managedPrincipals,
    ownerRoles,
    trustedPrincipals,
    managedPrefixes = ["tp_"],
    allowBootstrapDefaults = false
  }
) {
  requireRows(rows, "DATABASE_POSTURE_DEFAULT_GRANT_CENSUS_INVALID");
  const managed = new Set(managedPrincipals);
  const schemas = new Set(managedSchemas);
  const owners = new Set(ownerRoles);
  const trusted = new Set(trustedPrincipals);
  const seen = new Set();
  for (const row of rows) {
    const grant = normalizedDefaultGrant(row);
    const key = canonical(grant);
    if (
      grant.databaseName !== databaseName ||
      (grant.forAllRoles && grant.role !== "") ||
      (!grant.forAllRoles && grant.role === "") ||
      grant.grantee === "" ||
      grant.objectType === "" ||
      grant.privilegeType === "" ||
      seen.has(key)
    ) {
      throw stablePostureError("DATABASE_POSTURE_DEFAULT_GRANT_CENSUS_INVALID");
    }
    seen.add(key);
    if (
      (grant.role !== "" &&
        isManagedName(grant.role, managedPrefixes) &&
        !managed.has(grant.role)) ||
      (isManagedName(grant.grantee, managedPrefixes) &&
        !managed.has(grant.grantee))
    ) {
      throw stablePostureError("DATABASE_POSTURE_STALE_PRINCIPAL");
    }
    const selfOwnerDefault =
      grant.role !== "" &&
      grant.role === grant.grantee &&
      grant.schemaName === "" &&
      ["FUNCTIONS", "ROUTINES", "SCHEMAS", "SEQUENCES", "TABLES", "TYPES"]
        .includes(grant.objectType) &&
      grant.privilegeType === "ALL" &&
      grant.isGrantable;
    const publicTypeUsage =
      grant.grantee === "public" &&
      grant.schemaName === "" &&
      grant.objectType === "TYPES" &&
      grant.privilegeType === "USAGE" &&
      !grant.isGrantable;
    const synthesizedAllRoleRoutineBaseline =
      grant.forAllRoles &&
      grant.role === "" &&
      grant.schemaName === "" &&
      grant.grantee === "public" &&
      ["FUNCTIONS", "ROUTINES"].includes(grant.objectType) &&
      grant.privilegeType === "EXECUTE" &&
      !grant.isGrantable;
    if (
      selfOwnerDefault ||
      publicTypeUsage ||
      synthesizedAllRoleRoutineBaseline
    ) continue;
    const relevant =
      grant.forAllRoles ||
      managed.has(grant.role) ||
      managed.has(grant.grantee) ||
      owners.has(grant.role) ||
      (allowBootstrapDefaults && trusted.has(grant.role));
    if (!relevant) continue;
    if (grant.schemaName !== "" && !schemas.has(grant.schemaName)) {
      throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
    }
    const bootstrapRoutineDefault =
      allowBootstrapDefaults &&
      grant.grantee === "public" &&
      ["FUNCTIONS", "ROUTINES"].includes(grant.objectType) &&
      grant.privilegeType === "EXECUTE" &&
      !grant.isGrantable;
    if (!bootstrapRoutineDefault) {
      throw stablePostureError("DATABASE_POSTURE_DEFAULT_GRANT_UNSAFE");
    }
  }
  return {
    defaultGrantCount: 0,
    censusDefaultGrantCount: seen.size
  };
}

export function postureDigest(summary) {
  return digest(canonical(summary));
}

export function quoteIdentifier(value) {
  const name = text(value);
  if (name === "" || Buffer.byteLength(name, "utf8") > 128) {
    throw stablePostureError("DATABASE_POSTURE_IDENTIFIER_INVALID");
  }
  return `"${name.replaceAll('"', '""')}"`;
}

export async function collectDatabaseSecurityPosture(client) {
  if (typeof client?.query !== "function") {
    throw new TypeError("DATABASE_POSTURE_CLIENT_REQUIRED");
  }
  let transactionStarted = false;
  try {
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    transactionStarted = true;
    const sessionRows = await client.query(`
      SELECT
        current_database() AS database_name,
        current_user AS current_user_name,
        session_user AS session_user_name,
        version() AS database_version
    `);
    const principalRows = await client.query(`
      SELECT username, options
      FROM [SHOW USERS]
      ORDER BY username
    `);
    const membershipRows = await client.query(`
      SELECT role_name, member, is_admin
      FROM [SHOW GRANTS ON ROLE]
      ORDER BY role_name, member
    `);
    const systemGrantRows = await client.query(`
      SELECT grantee, privilege_type, is_grantable
      FROM [SHOW SYSTEM GRANTS]
      ORDER BY grantee, privilege_type, is_grantable
    `);
    const objectGrantRows = await client.query(`
      SELECT
        database_name,
        schema_name,
        object_name,
        object_type,
        grantee,
        privilege_type,
        is_grantable
      FROM [SHOW GRANTS]
      WHERE database_name = current_database()
        AND (
          schema_name IS NULL
          OR schema_name NOT IN (
            'crdb_internal',
            'information_schema',
            'pg_catalog',
            'pg_extension'
          )
        )
      ORDER BY
        database_name,
        schema_name,
        object_name,
        object_type,
        grantee,
        privilege_type,
        is_grantable
    `);
    const defaultGrantRows = await client.query(`
      SELECT
        current_database() AS database_name,
        NULL::STRING AS schema_name,
        role,
        for_all_roles,
        object_type,
        grantee,
        privilege_type,
        is_grantable
      FROM [SHOW DEFAULT PRIVILEGES]
      ORDER BY
        database_name,
        schema_name,
        role,
        for_all_roles,
        object_type,
        grantee,
        privilege_type,
        is_grantable
    `);
    await client.query("COMMIT");
    transactionStarted = false;
    return {
      session: sessionRows.rows,
      principals: principalRows.rows,
      memberships: membershipRows.rows,
      systemGrants: systemGrantRows.rows,
      objectGrants: objectGrantRows.rows,
      defaultGrants: defaultGrantRows.rows
    };
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }
    throw error;
  }
}

function normalizedDatabaseNames(rows) {
  const names = requireRows(
    rows,
    "DATABASE_POSTURE_DATABASE_CENSUS_INVALID"
  ).map((row) => text(row?.database_name));
  if (
    names.length === 0 ||
    names.some((name) => name === "") ||
    new Set(names).size !== names.length
  ) {
    throw stablePostureError("DATABASE_POSTURE_DATABASE_CENSUS_INVALID");
  }
  return names.filter((name) => name !== "system").sort();
}

async function scanDatabaseManagedGrants(client, databaseName) {
  let transactionStarted = false;
  try {
    await client.query(
      "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY"
    );
    transactionStarted = true;
    const sessionResult = await client.query(`
      SELECT
        current_database() AS database_name,
        current_user AS current_user_name,
        session_user AS session_user_name,
        version() AS database_version
    `);
    if (
      sessionResult.rows.length !== 1 ||
      text(sessionResult.rows[0]?.database_name) !== databaseName ||
      text(sessionResult.rows[0]?.current_user_name) === "" ||
      text(sessionResult.rows[0]?.current_user_name) !==
        text(sessionResult.rows[0]?.session_user_name) ||
      !TESTED_DATABASE_VERSION.test(
        text(sessionResult.rows[0]?.database_version)
      )
    ) {
      throw stablePostureError("DATABASE_POSTURE_BOOTSTRAP_SESSION_UNSAFE");
    }
    const grantResult = await client.query(`
      SELECT
        database_name,
        schema_name,
        object_name,
        object_type,
        grantee,
        privilege_type,
        is_grantable
      FROM [SHOW GRANTS]
      WHERE database_name = current_database()
      ORDER BY
        database_name,
        schema_name,
        object_name,
        object_type,
        grantee,
        privilege_type,
        is_grantable
    `);
    await client.query("COMMIT");
    transactionStarted = false;
    return {
      session: sessionResult.rows[0],
      grants: grantResult.rows
    };
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }
    throw error;
  }
}

export async function collectClusterManagedGrantPosture({
  adminConnectionString,
  principalDatabases,
  managedPrefixes = ["tp_"],
  createClient = (databaseName) => new Client(bootstrapDatabaseConfig({
    connectionString: databaseName === null
      ? adminConnectionString
      : connectionStringForDatabase(adminConnectionString, databaseName),
    max: 1,
    applicationName: "tideproof-cluster-security-posture"
  }))
}) {
  if (
    typeof adminConnectionString !== "string" ||
    adminConnectionString === "" ||
    !principalDatabases ||
    typeof principalDatabases !== "object" ||
    Object.keys(principalDatabases).length === 0 ||
    typeof createClient !== "function"
  ) {
    throw new TypeError("DATABASE_POSTURE_CLUSTER_OPTIONS_REQUIRED");
  }
  const coordinator = createClient(null);
  const databaseScans = [];
  let firstDatabaseNames;
  let bootstrapPrincipal;
  let databaseVersion;
  try {
    await coordinator.connect();
    const sessionResult = await coordinator.query(`
      SELECT
        current_user AS current_user_name,
        session_user AS session_user_name,
        version() AS database_version
    `);
    if (
      sessionResult.rows.length !== 1 ||
      text(sessionResult.rows[0]?.current_user_name) === "" ||
      text(sessionResult.rows[0]?.current_user_name) !==
        text(sessionResult.rows[0]?.session_user_name) ||
      !TESTED_DATABASE_VERSION.test(
        text(sessionResult.rows[0]?.database_version)
      )
    ) {
      throw stablePostureError("DATABASE_POSTURE_BOOTSTRAP_SESSION_UNSAFE");
    }
    bootstrapPrincipal = text(sessionResult.rows[0]?.session_user_name);
    databaseVersion = text(sessionResult.rows[0]?.database_version);
    const membershipResult = await coordinator.query(`
      SELECT role_name, member, is_admin
      FROM [SHOW GRANTS ON ROLE]
      ORDER BY role_name, member
    `);
    validateBootstrapAdministrator(
      membershipResult.rows,
      bootstrapPrincipal
    );
    const firstDatabaseResult = await coordinator.query(`
      SELECT database_name
      FROM [SHOW DATABASES]
      WHERE database_name <> 'system'
      ORDER BY database_name
    `);
    firstDatabaseNames = normalizedDatabaseNames(firstDatabaseResult.rows);
    for (const databaseName of firstDatabaseNames) {
      const databaseClient = createClient(databaseName);
      try {
        await databaseClient.connect();
        databaseScans.push({
          databaseName,
          ...await scanDatabaseManagedGrants(databaseClient, databaseName)
        });
      } finally {
        await databaseClient.end().catch(() => {});
      }
    }
    const secondDatabaseResult = await coordinator.query(`
      SELECT database_name
      FROM [SHOW DATABASES]
      WHERE database_name <> 'system'
      ORDER BY database_name
    `);
    const secondDatabaseNames = normalizedDatabaseNames(
      secondDatabaseResult.rows
    );
    if (!exactSet(
      new Set(firstDatabaseNames),
      new Set(secondDatabaseNames)
    )) {
      throw stablePostureError("DATABASE_POSTURE_DATABASE_SET_CHANGED");
    }
  } finally {
    await coordinator.end().catch(() => {});
  }

  const principalDatabaseMap = new Map(Object.entries(principalDatabases));
  const managedGrants = [];
  for (const scan of databaseScans) {
    for (const row of scan.grants) {
      const grant = normalizedObjectGrant(row);
      if (!isManagedName(grant.grantee, managedPrefixes)) continue;
      const expectedDatabase = principalDatabaseMap.get(grant.grantee);
      if (!expectedDatabase) {
        throw stablePostureError("DATABASE_POSTURE_STALE_PRINCIPAL");
      }
      if (grant.databaseName !== expectedDatabase) {
        throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
      }
      managedGrants.push(grant);
    }
  }
  const summary = {
    databaseNames: firstDatabaseNames,
    managedObjectGrants: managedGrants.sort((left, right) =>
      canonical(left).localeCompare(canonical(right))
    ),
    bootstrapPrincipalDigest: digest(bootstrapPrincipal),
    databaseVersionDigest: digest(databaseVersion)
  };
  return {
    ...summary,
    postureDigest: postureDigest(summary)
  };
}

function validateDatabaseSession(rows, spec) {
  requireRows(rows, "DATABASE_POSTURE_SESSION_CENSUS_INVALID");
  if (rows.length !== 1) {
    throw stablePostureError("DATABASE_POSTURE_SESSION_CENSUS_INVALID");
  }
  const databaseName = text(rows[0]?.database_name);
  const currentUser = text(rows[0]?.current_user_name);
  const sessionUser = text(rows[0]?.session_user_name);
  const databaseVersion = text(rows[0]?.database_version);
  if (
    databaseName !== spec.databaseName ||
    currentUser === "" ||
    sessionUser === "" ||
    !TESTED_DATABASE_VERSION.test(databaseVersion) ||
    currentUser !== sessionUser ||
    isManagedName(sessionUser, spec.managedPrefixes)
  ) {
    throw stablePostureError("DATABASE_POSTURE_BOOTSTRAP_SESSION_UNSAFE");
  }
  return {
    bootstrapPrincipal: sessionUser,
    bootstrapPrincipalDigest: digest(`${databaseName}\0${sessionUser}`),
    databaseVersionDigest: digest(databaseVersion)
  };
}

function postureCensusForDigest(posture) {
  return {
    session: normalizedRows(posture.session, (row) => ({
      databaseName: text(row?.database_name),
      currentUser: text(row?.current_user_name),
      sessionUser: text(row?.session_user_name),
      databaseVersion: text(row?.database_version)
    })),
    principals: normalizedRows(posture.principals, (row) => ({
      username: text(row?.username),
      options: [...optionSet(row?.options)].sort()
    })),
    memberships: normalizedRows(posture.memberships, (row) => ({
      roleName: text(row?.role_name),
      member: text(row?.member),
      isAdmin: boolean(row?.is_admin)
    })),
    systemGrants: normalizedRows(posture.systemGrants, (row) => ({
      grantee: text(row?.grantee),
      privilegeType: text(row?.privilege_type).toUpperCase(),
      grantOption: boolean(row?.grant_option ?? row?.is_grantable ?? false)
    })),
    objectGrants: normalizedRows(posture.objectGrants, normalizedObjectGrant),
    defaultGrants: normalizedRows(posture.defaultGrants, normalizedDefaultGrant)
  };
}

export function validateDatabaseSecurityPosture(
  posture,
  spec,
  {
    allowMissingPrincipals = false,
    allowMissingExpectedCapabilities = false,
    allowBootstrapDefaults = false
  } = {}
) {
  const acceptedSpec = {
    ...spec,
    managedPrefixes: spec.managedPrefixes ?? ["tp_"],
    ownerRoles: spec.ownerRoles ?? [],
    roleGrantPolicies: spec.roleGrantPolicies ?? {},
    optionalRoles: spec.optionalRoles ?? [],
    optionalUsers: spec.optionalUsers ?? [],
    optionalBindings: spec.optionalBindings ?? [],
    trustedPrincipals:
      spec.trustedPrincipals ?? DEFAULT_TRUSTED_PRINCIPALS
  };
  const session = validateDatabaseSession(posture.session, acceptedSpec);
  const trustedPrincipals = [
    ...new Set([
      ...acceptedSpec.trustedPrincipals,
      session.bootstrapPrincipal
    ])
  ];
  const managedPrincipals = [
    ...acceptedSpec.roles,
    ...acceptedSpec.users,
    ...acceptedSpec.optionalRoles,
    ...acceptedSpec.optionalUsers
  ];
  const principalSummary = validatePrincipalOptions(posture.principals, {
    roles: acceptedSpec.roles,
    users: acceptedSpec.users,
    optionalRoles: acceptedSpec.optionalRoles,
    optionalUsers: acceptedSpec.optionalUsers,
    managedPrefixes: acceptedSpec.managedPrefixes,
    trustedPrincipals,
    allowMissing: allowMissingPrincipals
  });
  const managedSchemas = new Set(acceptedSpec.managedSchemas);
  const objectGrantRows = requireRows(
    posture.objectGrants,
    "DATABASE_POSTURE_OBJECT_GRANT_CENSUS_INVALID"
  );
  const managedApplicationSurfacePresent = objectGrantRows.some((row) => {
    const grant = normalizedObjectGrant(row);
    return (
      grant.databaseName === acceptedSpec.databaseName &&
      managedSchemas.has(grant.schemaName)
    );
  });
  const bootstrapDefaultsAccepted =
    allowBootstrapDefaults &&
    principalSummary.principalCount === 0 &&
    !managedApplicationSurfacePresent;
  const summary = {
    bootstrapPrincipalDigest: session.bootstrapPrincipalDigest,
    databaseVersionDigest: session.databaseVersionDigest,
    ...validateBootstrapAdministrator(
      posture.memberships,
      session.bootstrapPrincipal
    ),
    ...principalSummary,
    ...validateRoleMemberships(posture.memberships, {
      bindings: acceptedSpec.bindings,
      optionalBindings: acceptedSpec.optionalBindings,
      managedPrincipals,
      managedPrefixes: acceptedSpec.managedPrefixes,
      trustedPrincipals,
      allowMissing: allowMissingExpectedCapabilities
    }),
    ...validateNoSystemGrants(posture.systemGrants, {
      trustedPrincipals,
      managedPrincipals,
      managedPrefixes: acceptedSpec.managedPrefixes
    }),
    ...validateManagedObjectGrants(objectGrantRows, {
      databaseName: acceptedSpec.databaseName,
      managedSchemas: acceptedSpec.managedSchemas,
      runtimeUsers: acceptedSpec.users,
      knownManagedPrincipals: managedPrincipals,
      roleGrantPolicies: acceptedSpec.roleGrantPolicies,
      ownerRoles: acceptedSpec.ownerRoles,
      managedPrefixes: acceptedSpec.managedPrefixes,
      trustedPrincipals,
      apiSchema: acceptedSpec.apiSchema,
      allowMissingExpected: allowMissingExpectedCapabilities,
      allowBootstrapDefaults: bootstrapDefaultsAccepted
    }),
    ...validateDefaultGrants(posture.defaultGrants, {
      databaseName: acceptedSpec.databaseName,
      managedSchemas: acceptedSpec.managedSchemas,
      managedPrincipals,
      ownerRoles: acceptedSpec.ownerRoles,
      trustedPrincipals,
      managedPrefixes: acceptedSpec.managedPrefixes,
      allowBootstrapDefaults: bootstrapDefaultsAccepted
    })
  };
  return {
    ...summary,
    postureDigest: postureDigest({
      summary,
      census: postureCensusForDigest(posture)
    })
  };
}
