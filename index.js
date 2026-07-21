require('dotenv').config({ quiet: true });
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const plaidClient = require('./plaidClient');
const pool = require('./db');
const { encryptToken, decryptToken } = require('./tokenCrypto');
const { register, login, loginWithApple, logout, requireAuth, changePassword } = require('./auth');
const { PRIVACY_POLICY, TERMS_OF_SERVICE } = require('./legalContent');

const app = express();
// Required for express-rate-limit (and req.ip generally) to see the real client IP rather
// than one of Railway's own internal proxy hops - without this every request looks like
// it's coming from the same (or, worse, a rotating pool of) address, which breaks per-IP
// rate limiting entirely. A temporary debug endpoint showed Railway's internal hop count
// isn't a fixed number worth hardcoding (a hop's own IP changed between two otherwise
// identical requests, implying a pool of edge nodes, not one stable proxy) - trusting the
// whole forwarded chain is the standard fix for platforms like this. Safe specifically
// because Railway is the only possible ingress to this container: nothing reaches it
// without passing through Railway's edge first, and a legitimate reverse proxy always
// overwrites (never appends to) any X-Forwarded-For a client tries to supply, so the
// leftmost entry this app ends up trusting is one Railway itself observed, not one a
// client could forge.
app.set('trust proxy', true);

app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use((req, res, next) => {
  console.log(`[request] ${req.method} ${req.originalUrl}`);
  next();
});

// Publicly hosted versions of the same Terms/Privacy Policy shown in-app before signup -
// needed as a reviewable link for Plaid's production application, since Fenn has no
// separate marketing website to host these on.
function renderLegalDocHtml(doc) {
  const sections = doc.sections
    .map((s) => `<section><h2>${s.heading}</h2><p>${s.body}</p></section>`)
    .join('\n');
  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Fenn ${doc.title}</title>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; max-width: 640px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }
  h1 { font-size: 24px; }
  h2 { font-size: 16px; margin-top: 28px; margin-bottom: 6px; }
  p { font-size: 14px; color: #333; }
</style>
</head>
<body>
<h1>Fenn ${doc.title}</h1>
${sections}
</body>
</html>`;
}

app.get('/privacy', (req, res) => {
  res.send(renderLegalDocHtml(PRIVACY_POLICY));
});

app.get('/terms', (req, res) => {
  res.send(renderLegalDocHtml(TERMS_OF_SERVICE));
});

// Bcrypt's own cost factor already slows down a single guess, but that's not the same as
// capping how many guesses an attacker gets - without this, nothing stops a sustained
// brute-force run against a specific email over hours. Keyed by IP, not by email, so it
// can't be used to lock a real user out by deliberately failing their login from elsewhere.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again later.' },
});

// node-postgres parses DATE columns into JS Date objects using the *local* timezone of
// this process, not UTC. Reading the date back out with local getters (not toISOString,
// which is UTC) correctly reverses that regardless of what timezone this server runs in.
function toDateOnly(d) {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, marketing_consent, tos_accepted } = req.body;
    if (!email || !EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'A valid email is required.' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }
    if (!tos_accepted) {
      return res.status(400).json({ error: 'You must accept the Terms of Service and Privacy Policy.' });
    }
    const { token, user } = await register({ email, password, marketingConsent: marketing_consent });
    res.json({ token, user });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to register' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const { token, user } = await login({ email, password });
    res.json({ token, user });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to log in' });
  }
});

app.post('/api/auth/apple', authLimiter, async (req, res) => {
  try {
    const { identity_token, email, marketing_consent, tos_accepted } = req.body;
    if (!identity_token) {
      return res.status(400).json({ error: 'identity_token is required.' });
    }
    const { token, user } = await loginWithApple({
      identityToken: identity_token,
      email,
      marketingConsent: marketing_consent,
      tosAccepted: tos_accepted,
    });
    res.json({ token, user });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to sign in with Apple' });
  }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  const header = req.headers.authorization || '';
  await logout(header.slice(7));
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  // has_password (not the hash itself, which never leaves the server) lets the frontend
  // decide whether "Change password" makes sense to show at all - an Apple-only account
  // has no password to change.
  const result = await pool.query(
    'SELECT id, email, tier, created_at, (password_hash IS NOT NULL) AS has_password FROM users WHERE id = $1',
    [req.userId]
  );
  res.json(result.rows[0] || null);
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current and new password are required.' });
    }
    if (new_password.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    await changePassword(req.userId, current_password, new_password);
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to change password' });
  }
});

// Self-service, immediate, no grace period - per the spec. Plaid Items are removed on
// Plaid's side first (so we stop being billed for them), then the user row is deleted,
// which cascades to every other table (transactions, budgets, expenses, bills, sessions).
app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    const items = await pool.query('SELECT access_token FROM plaid_items WHERE user_id = $1', [req.userId]);
    for (const item of items.rows) {
      try {
        await plaidClient.itemRemove({ access_token: decryptToken(item.access_token) });
      } catch (err) {
        console.error(err.response ? err.response.data : err);
      }
    }

    await pool.query('DELETE FROM users WHERE id = $1', [req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Everything below this point requires a valid session.
app.use('/api', requireAuth);

// Free tier is manual-entry only per the spec - Plaid sync is the paid feature.
async function requirePaidTier(req, res, next) {
  const result = await pool.query('SELECT tier FROM users WHERE id = $1', [req.userId]);
  if (result.rows[0]?.tier !== 'paid') {
    return res.status(403).json({ error: 'Connecting a bank requires the paid tier.' });
  }
  next();
}

// Step 1: front-end asks us for a link_token, which is what initializes Plaid Link.
//
// If item_id is provided, this instead creates a link_token in "update mode" for that
// specific existing connection - used to re-authenticate a bank that broke (expired
// login, MFA change, etc.) rather than creating a brand new connection.
// Most real banks (Chase, Bank of America, Wells Fargo, etc.) require Plaid Link's OAuth
// flow, which needs a registered universal-link redirect URI. Sandbox's test institutions
// don't use OAuth, and passing a redirect_uri that isn't registered for that environment
// would make linkTokenCreate reject the request outright - so this only applies once
// PLAID_ENV is actually 'production', leaving Sandbox testing untouched.
const PLAID_OAUTH_REDIRECT_URI =
  process.env.PLAID_ENV === 'production' ? 'https://fenn-backend-production.up.railway.app/plaid-oauth' : undefined;

// Proves to iOS that this domain is allowed to hand off to the Fenn app for a given path -
// required for Plaid's OAuth bank redirect (a plain custom URL scheme isn't accepted for
// this flow, only a verified universal link) - see PLAID_OAUTH_REDIRECT_URI above.
app.get('/.well-known/apple-app-site-association', (req, res) => {
  res.json({
    applinks: {
      apps: [],
      details: [
        {
          appID: 'T335XBZWJR.com.fennapp.fenn',
          appIDs: ['T335XBZWJR.com.fennapp.fenn'],
          paths: ['/plaid-oauth'],
        },
      ],
    },
  });
});

// Where Plaid sends the user back after completing a bank's OAuth login. iOS intercepts
// this as a universal link and hands off to the app before this ever renders for a user
// who has Fenn installed - this page is just the fallback for the rare moment it doesn't.
app.get('/plaid-oauth', (req, res) => {
  res.send('<p>Redirecting back to Fenn&hellip; you can close this window.</p>');
});

app.post('/api/create_link_token', requirePaidTier, async (req, res) => {
  try {
    const { item_id } = req.body || {};

    if (item_id) {
      const item = await pool.query('SELECT access_token FROM plaid_items WHERE id = $1 AND user_id = $2', [
        item_id,
        req.userId,
      ]);
      if (item.rows.length === 0) {
        return res.status(404).json({ error: 'Bank connection not found' });
      }
      const response = await plaidClient.linkTokenCreate({
        user: { client_user_id: String(req.userId) },
        client_name: 'Fenn',
        access_token: decryptToken(item.rows[0].access_token),
        country_codes: ['US'],
        language: 'en',
        ...(PLAID_OAUTH_REDIRECT_URI && { redirect_uri: PLAID_OAUTH_REDIRECT_URI }),
      });
      return res.json({ link_token: response.data.link_token });
    }

    const response = await plaidClient.linkTokenCreate({
      user: { client_user_id: String(req.userId) },
      client_name: 'Fenn',
      products: ['transactions'],
      country_codes: ['US'],
      language: 'en',
      ...(PLAID_OAUTH_REDIRECT_URI && { redirect_uri: PLAID_OAUTH_REDIRECT_URI }),
    });
    res.json({ link_token: response.data.link_token });
  } catch (err) {
    console.error(err.response ? err.response.data : err);
    res.status(500).json({ error: 'Failed to create link token' });
  }
});

// Called after a successful update-mode Link session - the access_token doesn't change,
// we just clear the flag so the reconnect banner goes away.
app.post('/api/plaid_items/:id/reconnected', async (req, res) => {
  try {
    await pool.query('UPDATE plaid_items SET needs_reconnect = false WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.userId,
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update bank connection' });
  }
});

// Disconnects one linked bank without touching the rest of the account - the only other
// way to remove a bank connection is deleting the whole account, which is too heavy a
// hammer for "I connected the wrong bank." Removed on Plaid's side first (so billing
// stops), then the row is deleted, which cascades to that bank's transactions and
// recurring bills only.
app.delete('/api/plaid_items/:id', async (req, res) => {
  try {
    const item = await pool.query('SELECT access_token FROM plaid_items WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.userId,
    ]);
    if (item.rows.length === 0) {
      return res.status(404).json({ error: 'Bank connection not found' });
    }

    try {
      await plaidClient.itemRemove({ access_token: decryptToken(item.rows[0].access_token) });
    } catch (err) {
      console.error(err.response ? err.response.data : err);
    }

    await pool.query('DELETE FROM plaid_items WHERE id = $1 AND user_id = $2', [req.params.id, req.userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to remove bank connection' });
  }
});

// Step 2: once the user finishes Plaid Link, the front-end sends us the public_token.
// We exchange it for a long-lived access_token and save it against the user's row.
app.post('/api/exchange_public_token', requirePaidTier, async (req, res) => {
  try {
    const { public_token, institution_name } = req.body;
    const response = await plaidClient.itemPublicTokenExchange({ public_token });
    const userId = req.userId;

    await pool.query(
      `INSERT INTO plaid_items (user_id, plaid_item_id, access_token, institution_name)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (plaid_item_id) DO UPDATE SET access_token = EXCLUDED.access_token`,
      [userId, response.data.item_id, encryptToken(response.data.access_token), institution_name || null]
    );

    res.json({ item_id: response.data.item_id });
  } catch (err) {
    console.error(err.response ? err.response.data : err);
    res.status(500).json({ error: 'Failed to exchange public token' });
  }
});

// How far back to keep Plaid's historical backfill on a brand new Item - separate from,
// and much more permissive than, streak eligibility (which stays anchored to the account's
// actual created_at everywhere it's used - see RingScreen.js and HistoryScreen.js on the
// frontend). The two are deliberately different concepts now: this window gives context
// (History, and lets recurring-bill detection work right away instead of waiting for a
// pattern to naturally emerge post-signup) without letting old data inflate a streak.
const DATA_IMPORT_LOOKBACK_DAYS = 90;

// Pulls transactions for one bank connection via Plaid's sync endpoint and upserts them
// into our own transactions table. Returns how many were added/modified/removed.
async function syncOneItem(item, userId) {
  const accessToken = decryptToken(item.access_token);
  // A brand new Item's first sync backfills Plaid's own historical window (which can span
  // months on some institutions) - only the most recent DATA_IMPORT_LOOKBACK_DAYS of that
  // is kept, in the same local-calendar-date-key format as transactions.date (see
  // toDateOnly's comment for why that matters).
  const connectedDate = new Date(item.created_at);
  const importStartDate = new Date(connectedDate);
  importStartDate.setDate(importStartDate.getDate() - DATA_IMPORT_LOOKBACK_DAYS);
  const importStartDateKey = toDateOnly(importStartDate);
  let cursor = item.cursor;
  let added = [];
  let modified = [];
  let removed = [];
  let hasMore = true;

  while (hasMore) {
    const response = await plaidClient.transactionsSync({
      access_token: accessToken,
      cursor: cursor || undefined,
    });
    added = added.concat(response.data.added);
    modified = modified.concat(response.data.modified);
    removed = removed.concat(response.data.removed);
    hasMore = response.data.has_more;
    cursor = response.data.next_cursor;
  }

  for (const txn of added.concat(modified)) {
    if (txn.date < importStartDateKey) continue;
    const pfc = txn.personal_finance_category || {};
    await pool.query(
      `INSERT INTO transactions
         (plaid_item_id, user_id, plaid_transaction_id, account_id, amount, iso_currency_code, date, name, merchant_name, pending, pfc_primary, pfc_detailed, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
       ON CONFLICT (plaid_transaction_id) DO UPDATE SET
         amount = EXCLUDED.amount,
         date = EXCLUDED.date,
         name = EXCLUDED.name,
         merchant_name = EXCLUDED.merchant_name,
         pending = EXCLUDED.pending,
         pfc_primary = EXCLUDED.pfc_primary,
         pfc_detailed = EXCLUDED.pfc_detailed,
         updated_at = now()`,
      [
        item.id,
        userId,
        txn.transaction_id,
        txn.account_id,
        txn.amount,
        txn.iso_currency_code,
        txn.date,
        txn.name,
        txn.merchant_name,
        txn.pending,
        pfc.primary || null,
        pfc.detailed || null,
      ]
    );
  }

  if (removed.length > 0) {
    const removedIds = removed.map((r) => r.transaction_id);
    await pool.query('DELETE FROM transactions WHERE plaid_transaction_id = ANY($1)', [removedIds]);
  }

  await pool.query('UPDATE plaid_items SET cursor = $1 WHERE id = $2', [cursor, item.id]);

  return { added: added.length, modified: modified.length, removed: removed.length };
}

// Step 3: pull transactions for every bank connection this user has.
app.post('/api/sync_transactions', async (req, res) => {
  try {
    const userId = req.userId;
    const items = await pool.query(
      'SELECT id, plaid_item_id, access_token, cursor, created_at FROM plaid_items WHERE user_id = $1',
      [userId]
    );

    if (items.rows.length === 0) {
      return res.status(400).json({ error: 'No linked account yet. Connect a bank first.' });
    }

    let totalAdded = 0;
    let totalModified = 0;
    let totalRemoved = 0;
    const needsReconnect = [];

    for (const item of items.rows) {
      // One bank's connection breaking (expired login, MFA change, etc.) shouldn't stop
      // the others from syncing - catch per-item so a single bad Item doesn't fail the
      // whole request for someone with several banks connected.
      try {
        const counts = await syncOneItem(item, userId);
        totalAdded += counts.added;
        totalModified += counts.modified;
        totalRemoved += counts.removed;
      } catch (err) {
        const errorCode = err.response?.data?.error_code;
        if (errorCode === 'ITEM_LOGIN_REQUIRED') {
          await pool.query('UPDATE plaid_items SET needs_reconnect = true WHERE id = $1', [item.id]);
          needsReconnect.push(item.id);
        } else {
          console.error(err.response ? err.response.data : err);
        }
      }
    }

    res.json({ added: totalAdded, modified: totalModified, removed: totalRemoved, needsReconnect });
  } catch (err) {
    console.error(err.response ? err.response.data : err);
    res.status(500).json({ error: 'Failed to sync transactions' });
  }
});

// Plaid categories that should never count toward daily spend, per the spec:
// transfers between the user's own accounts, and credit card bill payments
// (the underlying purchases were already counted when they happened).
const AUTO_EXCLUDED_PFC_PRIMARY = ['TRANSFER_IN', 'TRANSFER_OUT'];
const AUTO_EXCLUDED_PFC_DETAILED = ['LOAN_PAYMENTS_CREDIT_CARD_PAYMENT'];

// Read-only view of what's actually in our database now, for testing/verification.
app.get('/api/transactions', async (req, res) => {
  try {
    const { date, start, end } = req.query;
    const userId = req.userId;

    if (date || (start && end)) {
      // Returns every transaction in range, not just the ones counted in the total, so
      // the app can show excluded ones too (dimmed, with a toggle to bring them back)
      // instead of them silently vanishing.
      //
      // user_excluded is a tri-state override: NULL defers to the automatic category
      // rules below (a transfer, a credit card payment, or a recurring bill is excluded by
      // default), true always excludes regardless of category, and false always includes
      // regardless of category - which is what actually lets someone count one specific
      // recurring bill without a separate settings toggle. Refunds (amount <= 0) are the
      // one exception with no override in either direction: letting a refund subtract from
      // spend can push a day/period negative, creating artificial budget headroom for the
      // rest of it, which is a real problem independent of anyone's intent to include it.
      const rangeStart = date || start;
      const rangeEnd = date || end;

      const result = await pool.query(
        // to_char, not a bare column - pg's driver otherwise serializes a raw DATE column
        // as a full ISO timestamp shifted by the server's local timezone (e.g.
        // "2026-07-13T06:00:00.000Z" for Mountain Time), not the plain "2026-07-13" every
        // date-string helper in the app (parseDateKey, etc.) expects.
        `SELECT t.id, to_char(t.date, 'YYYY-MM-DD') AS date, t.name, t.merchant_name, t.amount, t.pending,
           CASE
             WHEN t.amount <= 0 THEN true
             WHEN t.user_excluded IS NOT NULL THEN t.user_excluded
             ELSE (
               COALESCE(t.pfc_primary, '') = ANY($3) OR COALESCE(t.pfc_detailed, '') = ANY($4)
               OR t.is_recurring_bill
             )
           END AS excluded
         FROM transactions t
         WHERE t.user_id = $1 AND t.date BETWEEN $2 AND $5
         ORDER BY t.date DESC, t.id`,
        [userId, rangeStart, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED, rangeEnd]
      );
      return res.json(result.rows);
    }

    const result = await pool.query(
      `SELECT id, date, name, merchant_name, amount, pending, pfc_primary, pfc_detailed, user_excluded
       FROM transactions WHERE user_id = $1 ORDER BY date DESC LIMIT 100`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

app.get('/api/plaid_items', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      'SELECT id, institution_name, needs_reconnect, created_at FROM plaid_items WHERE user_id = $1 ORDER BY created_at',
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch linked banks' });
  }
});

// Fetches recurring transaction streams from Plaid for every linked bank and stores the
// outflow ones (recurring bills - rent, subscriptions, utilities). Not called on every
// regular sync; it's a heavier Plaid call, meant to be triggered when the Bills view loads.
app.post('/api/sync_recurring', async (req, res) => {
  try {
    const userId = req.userId;
    const items = await pool.query('SELECT id, access_token FROM plaid_items WHERE user_id = $1', [userId]);

    for (const item of items.rows) {
      const response = await plaidClient.transactionsRecurringGet({ access_token: decryptToken(item.access_token) });

      for (const stream of response.data.outflow_streams) {
        // Belt-and-suspenders: outflow_streams should already exclude income/refunds
        // (those land in inflow_streams, which we never fetch), but never store a
        // stream that isn't a genuine positive-amount recurring expense.
        if (!(stream.average_amount?.amount > 0)) continue;

        const billResult = await pool.query(
          `INSERT INTO recurring_bills
             (user_id, plaid_item_id, stream_id, merchant_name, description, average_amount, last_amount, frequency, last_date, is_active, pfc_primary, pfc_detailed, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
           ON CONFLICT (stream_id) DO UPDATE SET
             merchant_name = EXCLUDED.merchant_name,
             average_amount = EXCLUDED.average_amount,
             last_amount = EXCLUDED.last_amount,
             frequency = EXCLUDED.frequency,
             last_date = EXCLUDED.last_date,
             is_active = EXCLUDED.is_active,
             pfc_primary = EXCLUDED.pfc_primary,
             pfc_detailed = EXCLUDED.pfc_detailed,
             updated_at = now()
           RETURNING id, user_included`,
          [
            userId,
            item.id,
            stream.stream_id,
            stream.merchant_name,
            stream.description,
            stream.average_amount?.amount ?? null,
            stream.last_amount?.amount ?? null,
            stream.frequency,
            stream.last_date,
            stream.is_active,
            stream.personal_finance_category?.primary ?? null,
            stream.personal_finance_category?.detailed ?? null,
          ]
        );

        if (stream.transaction_ids.length > 0) {
          // A newly-linked transaction inherits the bill's include/exclude choice only if
          // it doesn't already have its own individual override (user_excluded IS NULL) -
          // this is what makes toggling a bill apply to future occurrences automatically,
          // without silently clobbering a one-off exception someone already set on a
          // specific past occurrence.
          await pool.query(
            `UPDATE transactions
             SET is_recurring_bill = true, recurring_bill_id = $2,
                 user_excluded = CASE WHEN user_excluded IS NULL AND $3 THEN false ELSE user_excluded END
             WHERE plaid_transaction_id = ANY($1)`,
            [stream.transaction_ids, billResult.rows[0].id, billResult.rows[0].user_included]
          );
        }
      }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err.response ? err.response.data : err);
    res.status(500).json({ error: 'Failed to sync recurring bills' });
  }
});

app.get('/api/bills', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      // Plaid's recurring-transaction detector picks up genuine transfers too (most
      // commonly a credit card payment that happens to recur monthly) - not a real "bill"
      // in any meaningful sense, so these are filtered out of this informational list
      // entirely. They can still be individually included from the expense list like any
      // other transaction, via the per-transaction override.
      //
      // Checked against the bill's own pfc_primary/pfc_detailed (populated directly from
      // Plaid's stream object in /api/sync_recurring), not a joined transaction - a join
      // depends on a linked transaction existing, and that link can legitimately be absent
      // (not yet synced, or - as happened once already - deleted for predating the
      // connection date), which silently made this filter find nothing to exclude instead
      // of failing loudly.
      //
      // rb.last_date's floor matches syncOneItem's DATA_IMPORT_LOOKBACK_DAYS window, not the
      // bare connection date - Plaid's recurring detector runs against its own full
      // historical view regardless of when the Item was actually connected, so without a
      // floor here a bill whose last real occurrence sits outside the window Fenn actually
      // imported transactions for would still show up, with nothing behind it to link to.
      `SELECT rb.id, rb.merchant_name, rb.description, rb.average_amount, rb.last_amount, rb.frequency, rb.last_date, rb.is_active, rb.user_included
       FROM recurring_bills rb
       JOIN plaid_items pi ON pi.id = rb.plaid_item_id
       WHERE rb.user_id = $1 AND rb.is_active = true AND rb.average_amount > 0
         AND rb.last_date >= pi.created_at::date - interval '${DATA_IMPORT_LOOKBACK_DAYS} days'
         AND COALESCE(rb.pfc_primary, '') != ALL($2)
         AND COALESCE(rb.pfc_detailed, '') != ALL($3)
       ORDER BY rb.average_amount DESC`,
      [userId, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch bills' });
  }
});

// Toggling a bill applies the same include/exclude choice to every transaction currently
// linked to it in one action - the whole point of this endpoint over just toggling
// transactions individually from Today/History. A transaction's own override, set
// afterward, still wins for that one occurrence (this only sets the baseline all of a
// bill's transactions share, not a hard, unoverridable rule).
app.patch('/api/bills/:id/include', async (req, res) => {
  try {
    const userId = req.userId;
    const included = !!req.body.included;

    const bill = await pool.query('SELECT id FROM recurring_bills WHERE id = $1 AND user_id = $2', [
      req.params.id,
      userId,
    ]);
    if (bill.rows.length === 0) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    await pool.query('UPDATE recurring_bills SET user_included = $1, updated_at = now() WHERE id = $2', [
      included,
      req.params.id,
    ]);

    // Un-including resets to NULL (defer to the automatic rule, which excludes a
    // recurring bill by default) rather than an explicit false - false would be
    // indistinguishable from "the user deliberately force-included this one occurrence
    // and then changed their mind," which isn't what un-including the whole bill means.
    await pool.query(
      `UPDATE transactions SET user_excluded = $1
       WHERE recurring_bill_id = $2 AND user_id = $3`,
      [included ? false : null, req.params.id, userId]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update bill' });
  }
});

app.get('/api/budget', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query('SELECT monthly_amount, week_start_day FROM budgets WHERE user_id = $1', [userId]);
    res.json(result.rows[0] || null);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch budget' });
  }
});

app.post('/api/budget', async (req, res) => {
  try {
    const { monthly_amount, week_start_day } = req.body;
    if (!monthly_amount || monthly_amount <= 0) {
      return res.status(400).json({ error: 'monthly_amount must be a positive number' });
    }
    const userId = req.userId;
    await pool.query(
      `INSERT INTO budgets (user_id, monthly_amount, week_start_day, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (user_id) DO UPDATE SET
         monthly_amount = EXCLUDED.monthly_amount,
         week_start_day = EXCLUDED.week_start_day,
         updated_at = now()`,
      [userId, monthly_amount, week_start_day ?? 0]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save budget' });
  }
});

app.get('/api/expenses', async (req, res) => {
  try {
    const { date, start, end } = req.query;
    if (!date && !(start && end)) {
      return res.status(400).json({ error: 'date, or start and end, query params (YYYY-MM-DD) are required' });
    }
    const userId = req.userId;
    const rangeStart = date || start;
    const rangeEnd = date || end;
    const result = await pool.query(
      // to_char, not a bare column - see the equivalent note on /api/transactions above.
      "SELECT id, amount, note, to_char(local_date, 'YYYY-MM-DD') AS local_date, occurred_at FROM manual_expenses WHERE user_id = $1 AND local_date BETWEEN $2 AND $3 ORDER BY occurred_at DESC",
      [userId, rangeStart, rangeEnd]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch expenses' });
  }
});

app.post('/api/expenses', async (req, res) => {
  try {
    const { amount, note, local_date, occurred_at } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'amount must be a positive number' });
    }
    if (!local_date) {
      return res.status(400).json({ error: 'local_date (YYYY-MM-DD, the device\'s local calendar date) is required' });
    }
    const userId = req.userId;
    const result = await pool.query(
      `INSERT INTO manual_expenses (user_id, amount, note, local_date, occurred_at)
       VALUES ($1, $2, $3, $4, COALESCE($5, now()))
       RETURNING id, amount, note, local_date, occurred_at`,
      [userId, amount, note || null, local_date, occurred_at || null]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add expense' });
  }
});

app.delete('/api/expenses/:id', async (req, res) => {
  try {
    const userId = req.userId;
    await pool.query('DELETE FROM manual_expenses WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete expense' });
  }
});

// Toggle whether a single synced transaction counts toward the budget
// (e.g. excluding a one-off flight). Plaid transactions are never deleted, only excluded.
app.patch('/api/transactions/:id/exclude', async (req, res) => {
  try {
    const { excluded } = req.body;
    const userId = req.userId;
    await pool.query('UPDATE transactions SET user_excluded = $1 WHERE id = $2 AND user_id = $3', [
      !!excluded,
      req.params.id,
      userId,
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update transaction' });
  }
});

// Total spend in a date range (inclusive), combining manual expenses and synced
// transactions, after applying the automatic category rules and any per-transaction
// override. The client supplies the date range so timezone/"what day is today" stays a
// device concern.
//
// user_excluded is a tri-state override: NULL defers to the automatic rules (a transfer,
// credit card payment, or recurring bill is excluded by default), false always counts a
// transaction regardless of category, true always excludes it. Refunds (amount <= 0) are
// the one exception with no override in either direction - see the comment above
// /api/transactions for why.
const COUNTS_TOWARD_SPEND = `
  (
    t.amount > 0
    AND (
      t.user_excluded = false
      OR (
        t.user_excluded IS NULL
        AND t.is_recurring_bill = false
        AND COALESCE(t.pfc_primary, '') != ALL($4)
        AND COALESCE(t.pfc_detailed, '') != ALL($5)
      )
    )
  )
`;

app.get('/api/spend', async (req, res) => {
  try {
    const { start, end } = req.query;
    if (!start || !end) {
      return res.status(400).json({ error: 'start and end query params (YYYY-MM-DD) are required' });
    }
    const userId = req.userId;

    const plaidResult = await pool.query(
      `SELECT COALESCE(SUM(t.amount), 0) AS total FROM transactions t
       WHERE t.user_id = $1
         AND t.date BETWEEN $2 AND $3
         AND ${COUNTS_TOWARD_SPEND}`,
      [userId, start, end, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED]
    );

    const manualResult = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total FROM manual_expenses
       WHERE user_id = $1 AND local_date BETWEEN $2 AND $3`,
      [userId, start, end]
    );

    const total = Number(plaidResult.rows[0].total) + Number(manualResult.rows[0].total);
    res.json({ start, end, spent: total });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute spend' });
  }
});

// Same spend calculation as /api/spend, but broken out per calendar day (including
// zero-spend days) for the streak/history views, which need to know under/over per day.
app.get('/api/spend/daily', async (req, res) => {
  try {
    const { start, end } = req.query;
    if (!start || !end) {
      return res.status(400).json({ error: 'start and end query params (YYYY-MM-DD) are required' });
    }
    const userId = req.userId;

    const result = await pool.query(
      `SELECT gs::date AS date, COALESCE(t.total, 0) + COALESCE(m.total, 0) AS spent
       FROM generate_series($2::date, $3::date, interval '1 day') AS gs
       LEFT JOIN (
         SELECT t.date, SUM(t.amount) AS total FROM transactions t
         WHERE t.user_id = $1
           AND ${COUNTS_TOWARD_SPEND}
         GROUP BY t.date
       ) t ON t.date = gs::date
       LEFT JOIN (
         SELECT local_date, SUM(amount) AS total FROM manual_expenses
         WHERE user_id = $1
         GROUP BY local_date
       ) m ON m.local_date = gs::date
       ORDER BY gs`,
      [userId, start, end, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED]
    );

    res.json(result.rows.map((r) => ({ date: toDateOnly(r.date), spent: Number(r.spent) })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute daily spend' });
  }
});

// Lets the History screen know when to stop offering "load earlier months" - not
// filtered by COUNTS_TOWARD_SPEND, since this is about whether there's any data at all
// for a month (even an excluded transfer/refund still means the bank connection had
// activity that month), not about spend totals specifically.
app.get('/api/spend/earliest-date', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      `SELECT LEAST(
         (SELECT MIN(date) FROM transactions WHERE user_id = $1),
         (SELECT MIN(local_date) FROM manual_expenses WHERE user_id = $1)
       ) AS earliest`,
      [userId]
    );
    const earliest = result.rows[0].earliest;
    res.json({ earliest: earliest ? toDateOnly(earliest) : null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to compute earliest date' });
  }
});

const PORT = process.env.PORT || 8000;
// Explicitly '0.0.0.0', not the default - on Railway (and similar container platforms)
// the app can print this exact "listening" line successfully while still binding in a way
// their edge proxy can't reach, producing a 502 "Application failed to respond" for every
// request despite the process being alive and healthy the whole time.
app.listen(PORT, '0.0.0.0', () => console.log(`Fenn backend listening on http://localhost:${PORT}`));
