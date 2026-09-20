/**
 * PostgreSQL connection pool (Supabase free tier).
 *
 * Serverless note: Vercel may run many concurrent instances of this
 * process, and each one would otherwise open its own pool. Supabase's
 * free tier has a small direct-connection limit, so we:
 *   1. point DATABASE_URL at Supabase's **transaction pooler** (port 6543),
 *   2. cap this pool at a couple of connections,
 *   3. reuse the pool across warm invocations via globalThis.
 */

const { Pool } = require("pg");

/**
 * Note on failure behaviour: this used to throw at import time when
 * DATABASE_URL was missing, which killed the whole serverless function —
 * including the static frontend — and gave a bare 500 with no clue why.
 * The check now happens on first query instead, so the app still boots,
 * /api/health can report exactly which variables are missing, and only
 * database-backed routes fail.
 */
function isConfigured() {
  return Boolean(process.env.DATABASE_URL);
}

function createPool() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error(
      "DATABASE_URL is not set. On Vercel: Settings → Environment Variables, " +
        "add it for Production, Preview and Development, then redeploy."
    );
  }

  return new Pool({
    connectionString,
    // Supabase requires TLS. Its certificate chain is not in Node's default
    // trust store for the pooler host, hence rejectUnauthorized: false —
    // the connection is still encrypted.
    ssl: { rejectUnauthorized: false },
    max: Number(process.env.PG_POOL_MAX || 2),
    idleTimeoutMillis: 10_000,
    connectionTimeoutMillis: 10_000,
    // The transaction pooler does not support server-side prepared
    // statements; node-postgres only uses them for *named* queries, and
    // we never name ours, so parameterised queries work as normal.
  });
}

/** Built on first use, then reused across warm serverless invocations. */
function getPool() {
  if (!globalThis.__secureidPool) {
    const p = createPool();
    p.on("error", (err) => console.error("[db] idle client error:", err.message));
    globalThis.__secureidPool = p;
  }
  return globalThis.__secureidPool;
}

/** Run a parameterised query. Never interpolate user input into SQL. */
async function query(text, params) {
  return getPool().query(text, params);
}

/** Convenience: first row or null. */
async function queryOne(text, params) {
  const { rows } = await getPool().query(text, params);
  return rows[0] || null;
}

/** Run several statements inside a transaction. */
async function withTransaction(fn) {
  const client = await getPool().connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { getPool, isConfigured, query, queryOne, withTransaction };
