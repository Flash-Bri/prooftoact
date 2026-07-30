import { Client } from "pg";

const DATABASE_NAME = "tideproof";
const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const INCIDENT_ID = "22222222-2222-4222-8222-222222222222";
const ROW_COUNT = 10_000;
const BATCH_SIZE = 500;
const INDEX_NAME = "gate1_vector_embedding_idx";
const TABLE_NAME = "gate1_vector_evidence";

function requiredDatabaseUrl() {
  const value = process.env.DATABASE_URL;
  if (!value) {
    throw new Error("DATABASE_URL is required");
  }
  return value;
}

function withDatabase(connectionString, databaseName) {
  const url = new URL(connectionString);
  url.pathname = `/${databaseName}`;
  return url.toString();
}

function embeddingFor(ordinal) {
  const first = ((ordinal * 17) % 997) / 997;
  const second = ((ordinal * 31) % 991) / 991;
  const third = ((ordinal * 47) % 983) / 983;
  return `[${first.toFixed(8)},${second.toFixed(8)},${third.toFixed(8)}]`;
}

async function connect(connectionString) {
  const client = new Client({ connectionString });
  await client.connect();
  return client;
}

async function ensureDatabase(connectionString) {
  const admin = await connect(connectionString);
  try {
    await admin.query(`CREATE DATABASE IF NOT EXISTS ${DATABASE_NAME}`);
  } finally {
    await admin.end();
  }
}

async function createFixture(client) {
  await client.query(`DROP TABLE IF EXISTS ${TABLE_NAME}`);
  await client.query(`
    CREATE TABLE ${TABLE_NAME} (
      tenant_id UUID NOT NULL,
      incident_id UUID NOT NULL,
      evidence_id UUID NOT NULL DEFAULT gen_random_uuid(),
      ordinal INT8 NOT NULL,
      admitted BOOL NOT NULL,
      embedding VECTOR(3) NOT NULL,
      PRIMARY KEY (tenant_id, incident_id, evidence_id),
      UNIQUE (tenant_id, incident_id, ordinal)
    )
  `);

  for (let start = 1; start <= ROW_COUNT; start += BATCH_SIZE) {
    const end = Math.min(start + BATCH_SIZE - 1, ROW_COUNT);
    const values = [];
    const parameters = [];

    for (let ordinal = start; ordinal <= end; ordinal += 1) {
      const offset = parameters.length;
      values.push(
        `($${offset + 1}::UUID, $${offset + 2}::UUID, $${offset + 3}::INT8, true, $${offset + 4}::VECTOR(3))`
      );
      parameters.push(
        TENANT_ID,
        INCIDENT_ID,
        ordinal,
        embeddingFor(ordinal)
      );
    }

    await client.query(
      `
        INSERT INTO ${TABLE_NAME}
          (tenant_id, incident_id, ordinal, admitted, embedding)
        VALUES ${values.join(", ")}
      `,
      parameters
    );
  }

  await client.query(`
    CREATE VECTOR INDEX ${INDEX_NAME}
    ON ${TABLE_NAME}
      (tenant_id, incident_id, admitted, embedding vector_cosine_ops)
  `);
  await client.query(`ANALYZE ${TABLE_NAME}`);
}

async function explainVectorSearch(client) {
  const queryVector = embeddingFor(9_999);
  const result = await client.query(`
    EXPLAIN (VERBOSE)
    SELECT evidence_id, ordinal
    FROM ${TABLE_NAME}
    WHERE tenant_id = '${TENANT_ID}'::UUID
      AND incident_id = '${INCIDENT_ID}'::UUID
      AND admitted = true
    ORDER BY embedding <=> '${queryVector}'::VECTOR(3)
    LIMIT 5
  `);

  return result.rows
    .map((row) => Object.values(row).join(" "))
    .join("\n");
}

async function expectVectorRejected(client, label, query, values) {
  try {
    await client.query(query, values);
  } catch (error) {
    return {
      label,
      applicationCode: "VECTOR_INPUT_INVALID",
      sqlstate: error.code ?? null,
      rejected: true
    };
  }
  throw new Error(`${label} vector input was unexpectedly accepted`);
}

async function proveInvalidVectorsFailClosed(client) {
  const before = await client.query(
    `SELECT count(*)::INT8 AS count FROM ${TABLE_NAME}`
  );
  const malformed = [
    ["zero-dimension", "[]"],
    ["two-dimension", "[0.1,0.2]"],
    ["four-dimension", "[0.1,0.2,0.3,0.4]"],
    ["not-a-number", "[NaN,0.2,0.3]"],
    ["positive-infinity", "[Infinity,0.2,0.3]"],
    ["malformed", "definitely-not-a-vector"]
  ];
  const ingest = [];
  const query = [];

  for (let index = 0; index < malformed.length; index += 1) {
    const [label, value] = malformed[index];
    ingest.push(
      await expectVectorRejected(
        client,
        `ingest-${label}`,
        `
          INSERT INTO ${TABLE_NAME}
            (tenant_id, incident_id, ordinal, admitted, embedding)
          VALUES ($1::UUID, $2::UUID, $3::INT8, true, $4::VECTOR(3))
        `,
        [TENANT_ID, INCIDENT_ID, -(index + 1), value]
      )
    );
    query.push(
      await expectVectorRejected(
        client,
        `query-${label}`,
        `
          SELECT evidence_id
          FROM ${TABLE_NAME}
          WHERE tenant_id = $1::UUID
            AND incident_id = $2::UUID
            AND admitted = true
          ORDER BY embedding <=> $3::VECTOR(3)
          LIMIT 5
        `,
        [TENANT_ID, INCIDENT_ID, value]
      )
    );
  }

  const after = await client.query(
    `SELECT count(*)::INT8 AS count FROM ${TABLE_NAME}`
  );
  if (before.rows[0].count !== after.rows[0].count) {
    throw new Error("invalid vector ingest left a partial evidence row");
  }
  return {
    ingest,
    query,
    rowCountBefore: before.rows[0].count,
    rowCountAfter: after.rows[0].count,
    fallbackRankingOccurred: false
  };
}

async function run() {
  const baseUrl = requiredDatabaseUrl();
  await ensureDatabase(baseUrl);

  const client = await connect(withDatabase(baseUrl, DATABASE_NAME));
  try {
    const version = await client.query(
      "SELECT version() AS version, current_database() AS database"
    );
    await createFixture(client);

    const count = await client.query(
      `SELECT count(*)::INT8 AS count FROM ${TABLE_NAME}`
    );
    const indexes = await client.query(
      `SHOW INDEXES FROM ${TABLE_NAME}`
    );
    const invalidVectors = await proveInvalidVectorsFailClosed(client);
    const plan = await explainVectorSearch(client);

    const vectorIndexPresent = indexes.rows.some(
      (row) => row.index_name === INDEX_NAME || row.indexName === INDEX_NAME
    );
    const vectorSearchUsed =
      plan.toLowerCase().includes("vector search") &&
      plan.includes(INDEX_NAME);

    const receipt = {
      gate: "distributed-vector-index",
      database: version.rows[0].database,
      databaseVersion: version.rows[0].version,
      rowCount: Number(count.rows[0].count),
      indexName: INDEX_NAME,
      vectorIndexPresent,
      vectorSearchUsed,
      invalidVectors,
      plan
    };

    console.log(JSON.stringify(receipt, null, 2));

    if (receipt.rowCount !== ROW_COUNT) {
      throw new Error(`expected ${ROW_COUNT} rows; found ${receipt.rowCount}`);
    }
    if (!vectorIndexPresent) {
      throw new Error(`vector index ${INDEX_NAME} was not created`);
    }
    if (!vectorSearchUsed) {
      throw new Error("EXPLAIN did not prove use of the vector index");
    }
  } finally {
    await client.end();
  }
}

run().catch((error) => {
  console.error(
    JSON.stringify({
      gate: "distributed-vector-index",
      passed: false,
      name: error.name,
      code: error.code,
      message: error.message
    })
  );
  process.exitCode = 1;
});
