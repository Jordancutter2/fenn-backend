require('dotenv').config({ quiet: true });
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Explicit, not just pg's own defaults left implicit - max/idleTimeoutMillis happen to
  // match what pg already defaults to, but connectionTimeoutMillis doesn't (pg's own
  // default is 0, meaning a request waiting on a connection when the pool's exhausted
  // hangs indefinitely instead of failing fast with a clear error). Matters more now that
  // syncOneItem's per-item transaction upsert is a single batched query instead of one
  // query per transaction (a real fix, not hypothetical - confirmed via a performance audit
  // it used to hold a connection open across up to 400 serial round-trips on a big backfill)
  // - connections are held far more briefly now, but a hard ceiling is still worth having
  // rather than relying on that alone.
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// node-postgres emits 'error' on the Pool when an idle client hits a connection-level
// problem (a Neon restart, a network blip) - with no listener, Node treats that as an
// uncaught exception and crashes the whole process, taking every user down until Railway
// restarts the container. A pool-level error isn't tied to any one in-flight query (those
// already reject and get caught by their own route's try/catch), so there's nothing to do
// here but log it and let the pool reconnect on the next query.
pool.on('error', (err) => {
  console.error('Unexpected Postgres pool error', err);
});

module.exports = pool;
