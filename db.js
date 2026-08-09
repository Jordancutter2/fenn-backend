require('dotenv').config({ quiet: true });
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
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
