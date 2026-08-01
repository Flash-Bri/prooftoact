import { createHash } from "node:crypto";

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

export function validatePrincipalOptions(
  rows,
  { roles, users, allowMissing = false }
) {
  const expected = new Map([
    ...roles.map((name) => [name, new Set(["NOLOGIN"])]),
    ...users.map((name) => [name, new Set()])
  ]);
  const seen = new Set();
  for (const row of rows) {
    const username = text(row?.username);
    if (!expected.has(username) || seen.has(username)) {
      throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_SET_INVALID");
    }
    seen.add(username);
    if (!exactSet(optionSet(row.options), expected.get(username))) {
      throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_OPTIONS_UNSAFE");
    }
  }
  if (!allowMissing && seen.size !== expected.size) {
    throw stablePostureError("DATABASE_POSTURE_PRINCIPAL_MISSING");
  }
  return { principalCount: seen.size };
}

export function validateRoleMemberships(
  rows,
  { bindings, managedPrincipals, allowManagedDrift = false }
) {
  const managed = new Set(managedPrincipals);
  const expected = new Set(bindings.map(([role, member]) => `${role}\0${member}`));
  const observed = new Set();
  for (const row of rows) {
    const role = text(row?.role_name);
    const member = text(row?.member);
    if (!managed.has(role) || !managed.has(member)) {
      throw stablePostureError("DATABASE_POSTURE_EXTERNAL_MEMBERSHIP");
    }
    if (boolean(row?.is_admin)) {
      throw stablePostureError("DATABASE_POSTURE_ADMIN_MEMBERSHIP");
    }
    const key = `${role}\0${member}`;
    if (observed.has(key)) {
      throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_DUPLICATE");
    }
    observed.add(key);
    if (!allowManagedDrift && !expected.has(key)) {
      throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_UNEXPECTED");
    }
  }
  if (
    !allowManagedDrift &&
    (observed.size !== expected.size ||
      [...expected].some((entry) => !observed.has(entry)))
  ) {
    throw stablePostureError("DATABASE_POSTURE_MEMBERSHIP_MISSING");
  }
  return { membershipCount: observed.size };
}

export function validateNoSystemGrants(rows) {
  if (rows.length !== 0) {
    throw stablePostureError("DATABASE_POSTURE_SYSTEM_GRANT_UNSAFE");
  }
  return { systemGrantCount: 0 };
}

export function validateManagedObjectGrants(
  rows,
  {
    databaseName,
    managedSchemas,
    runtimeUsers,
    allowManagedDrift = false
  }
) {
  const schemas = new Set([...managedSchemas, "public", ""]);
  const users = new Set(runtimeUsers);
  for (const row of rows) {
    const database = text(row?.database_name);
    const schema = text(row?.schema_name);
    const grantee = text(row?.grantee);
    if (database && database !== databaseName) {
      throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
    }
    if (!schemas.has(schema)) {
      throw stablePostureError("DATABASE_POSTURE_OUT_OF_SCOPE_GRANT");
    }
    if (!allowManagedDrift && users.has(grantee)) {
      throw stablePostureError("DATABASE_POSTURE_DIRECT_USER_GRANT");
    }
    const grantable = row?.is_grantable ?? row?.grant_option ?? false;
    if (!allowManagedDrift && boolean(grantable)) {
      throw stablePostureError("DATABASE_POSTURE_GRANT_OPTION_UNSAFE");
    }
  }
  return { objectGrantCount: rows.length };
}

export function postureDigest(summary) {
  return createHash("sha256").update(canonical(summary)).digest("hex");
}

export function quoteIdentifier(value) {
  const name = text(value);
  if (name === "" || Buffer.byteLength(name, "utf8") > 128) {
    throw stablePostureError("DATABASE_POSTURE_IDENTIFIER_INVALID");
  }
  return `"${name.replaceAll('"', '""')}"`;
}

function sqlLiteralList(values) {
  if (!Array.isArray(values) || values.length === 0) {
    throw stablePostureError("DATABASE_POSTURE_SPEC_INVALID");
  }
  return values
    .map((value) => `'${text(value).replaceAll("'", "''")}'`)
    .join(", ");
}

export async function collectDatabaseSecurityPosture(client, spec) {
  if (typeof client?.query !== "function") {
    throw new TypeError("DATABASE_POSTURE_CLIENT_REQUIRED");
  }
  const principals = [...spec.roles, ...spec.users];
  const list = sqlLiteralList(principals);
  const principalRows = await client.query(`
    SELECT username, options
    FROM [SHOW USERS]
    WHERE username IN (${list})
    ORDER BY username
  `);
  const membershipRows = await client.query(`
    SELECT role_name, member, is_admin
    FROM [SHOW GRANTS ON ROLE]
    WHERE role_name IN (${list}) OR member IN (${list})
    ORDER BY role_name, member
  `);
  const systemGrantRows = await client.query(`
    SELECT grantee, privilege_type, grant_option
    FROM [SHOW SYSTEM GRANTS]
    WHERE grantee IN (${list})
    ORDER BY grantee, privilege_type
  `);
  const objectGrantRows = await client.query(`
    SELECT
      database_name,
      schema_name,
      name,
      type,
      grantee,
      privilege_type,
      is_grantable
    FROM [SHOW GRANTS]
    WHERE grantee IN (${list})
    ORDER BY database_name, schema_name, name, type, grantee, privilege_type
  `);
  return {
    principals: principalRows.rows,
    memberships: membershipRows.rows,
    systemGrants: systemGrantRows.rows,
    objectGrants: objectGrantRows.rows
  };
}

export function validateDatabaseSecurityPosture(
  posture,
  spec,
  { allowMissing = false, allowManagedDrift = false } = {}
) {
  const managedPrincipals = [...spec.roles, ...spec.users];
  const summary = {
    ...validatePrincipalOptions(posture.principals, {
      roles: spec.roles,
      users: spec.users,
      allowMissing
    }),
    ...validateRoleMemberships(posture.memberships, {
      bindings: spec.bindings,
      managedPrincipals,
      allowManagedDrift
    }),
    ...validateNoSystemGrants(posture.systemGrants),
    ...validateManagedObjectGrants(posture.objectGrants, {
      databaseName: spec.databaseName,
      managedSchemas: spec.managedSchemas,
      runtimeUsers: spec.users,
      allowManagedDrift
    })
  };
  return { ...summary, postureDigest: postureDigest(summary) };
}
