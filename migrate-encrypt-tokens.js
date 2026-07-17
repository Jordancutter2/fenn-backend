// One-time data migration: encrypts any plaid_items.access_token still stored in plaintext
// from before token encryption was added. Safe to run more than once - rows already
// encrypted (don't match the Plaid token prefix) are left untouched.
require('dotenv').config({ quiet: true });
const pool = require('./db');
const { encryptToken, decryptToken, looksLikePlaintextPlaidToken } = require('./tokenCrypto');

async function main() {
  const result = await pool.query('SELECT id, access_token FROM plaid_items');
  let migrated = 0;
  let skipped = 0;

  for (const row of result.rows) {
    if (!looksLikePlaintextPlaidToken(row.access_token)) {
      skipped++;
      continue;
    }
    const original = row.access_token;
    const encrypted = encryptToken(original);
    await pool.query('UPDATE plaid_items SET access_token = $1 WHERE id = $2', [encrypted, row.id]);

    // Read the just-written row back and decrypt it - don't trust the write succeeded
    // correctly just because the query didn't throw, for real bank-connection data.
    const check = await pool.query('SELECT access_token FROM plaid_items WHERE id = $1', [row.id]);
    const roundTripped = decryptToken(check.rows[0].access_token);
    if (roundTripped !== original) {
      throw new Error(`Verification failed for plaid_items.id=${row.id} - decrypted value doesn't match original`);
    }
    migrated++;
  }

  console.log(`Migrated ${migrated} row(s), skipped ${skipped} already-encrypted row(s). All migrated rows verified.`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
