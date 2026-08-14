require('dotenv').config({ quiet: true });
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const plaidClient = require('./plaidClient');
const pool = require('./db');
const { encryptToken, decryptToken } = require('./tokenCrypto');
const {
  register,
  login,
  loginWithApple,
  logout,
  requireAuth,
  changePassword,
  requestPasswordReset,
  resetPassword,
  setupMfa,
  confirmMfa,
  disableMfa,
  verifyMfaLogin,
  MIN_PASSWORD_LENGTH,
} = require('./auth');
const { PRIVACY_POLICY, TERMS_OF_SERVICE } = require('./legalContent');

// A real Plaid API error has err.response.data (safe - just Plaid's own error JSON). A
// network-level failure (timeout, DNS, ECONNRESET, TLS) has no .response at all, and the
// raw axios error object's own enumerable properties include `config` - which contains the
// exact outgoing request body (an access_token, in plaintext, for every Plaid call in this
// file) and `config.headers` (PLAID-SECRET, PLAID-CLIENT-ID, set globally in plaidClient.js).
// console.error(err) on that error would print all of it. err.message is always safe -
// every Plaid call site in this file must log through this, never the raw err or err.response.
function plaidErrorDetail(err) {
  return err.response?.data ? JSON.stringify(err.response.data) : err.message;
}

// Every date query param in this file (start/end/date on /api/transactions, /api/expenses,
// /api/spend, /api/spend/daily) expects this exact shape - previously unvalidated, so a
// malformed value (wrong format, or a syntactically-plausible-but-nonexistent date like
// '2026-13-40') fell straight through to Postgres, which threw a type-cast error caught by
// the generic handler and returned as a bare 500 instead of a clean 400. Same pattern
// target_date already used for savings goals, pulled out here so every date param uses it.
function isValidDateKey(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(new Date(value).getTime());
}

// Express route params are always strings - a non-numeric :id (typo'd, or someone poking
// at the endpoint) previously fell straight through to a parameterized query, which
// Postgres rejects as a type-cast error on an INTEGER column, caught generically as a bare
// 500 instead of a clean 400/404.
function isValidId(value) {
  return /^\d+$/.test(value);
}

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

// Baseline security headers (X-Content-Type-Options, X-Frame-Options, a default
// Content-Security-Policy, HSTS, etc.) on every response. The one incidental cost:
// public/index.html (an explicitly-labeled throwaway Plaid sandbox test harness, not part
// of the real app) loads an external Plaid CDN script and runs its own logic from inline
// <script> tags - helmet's default CSP (script-src 'self', no unsafe-inline) blocks both,
// so that page's buttons stop working. The real app never touches this route at all (it's
// a native client, not a browser), so this only affects a dev-only test page reached by
// manually visiting the backend's own root URL.
app.use(helmet());
app.use(cors());
// Stashes the raw request body bytes on every request (cheap - just a Buffer reference,
// not a copy) - needed specifically to verify the Plaid webhook's signature below, which
// requires hashing the *exact* bytes Plaid sent, not a re-serialized version of the
// already-parsed JSON (whitespace/key-order differences would change the hash).
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
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
//
// Two tiers, not one shared bucket across every auth route - a single 10-per-15-min limit
// covering login, register, Apple sign-in, password-reset request, password-reset submit,
// AND MFA verify all at once meant a normal (non-malicious) user who mistyped a password a
// couple of times, tapped "Forgot password," resent the code once, and fumbled an MFA
// entry could realistically hit the cap within minutes and get locked out of every one of
// those actions for 15 minutes - including the ones needed to actually get back in. Only
// login and MFA verify are genuinely guessable-secret endpoints where tight brute-force
// protection matters; the others don't get meaningfully weaker with more headroom (you
// can't brute-force your way into registering someone else's email, and a password reset
// still requires a real code that was emailed to the account's actual owner).
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
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
    if (!password || password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
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

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }
    const { token, user, mfaRequired } = await login({ email, password });
    res.json({ token, user, mfa_required: mfaRequired });
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
    const { token, user, mfaRequired } = await loginWithApple({
      identityToken: identity_token,
      email,
      marketingConsent: marketing_consent,
      tosAccepted: tos_accepted,
    });
    res.json({ token, user, mfa_required: mfaRequired });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to sign in with Apple' });
  }
});

// Always the same response regardless of whether the email matched an account or the
// email actually sent - see requestPasswordReset's own comment in auth.js for why. Rate
// limited the same as login/register, since this is otherwise a free way to trigger an
// email send (and, without a limit, to brute-force-probe which addresses have accounts).
app.post('/api/auth/request-password-reset', authLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (email) await requestPasswordReset(email);
  } catch (err) {
    console.error(err);
  }
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  try {
    const { email, code, new_password } = req.body || {};
    if (!email || !code || !new_password) {
      return res.status(400).json({ error: 'Email, code, and new password are required.' });
    }
    await resetPassword({ email, code, newPassword: new_password });
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to reset password' });
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
    'SELECT id, email, tier, created_at, (password_hash IS NOT NULL) AS has_password, mfa_enabled FROM users WHERE id = $1',
    [req.userId]
  );
  res.json(result.rows[0] || null);
});

// loginLimiter, not authLimiter - this compares a real password via bcrypt, the same
// "genuinely guessable-secret" category login/mfa-verify-login are already tightly limited
// for (see the comment on loginLimiter above). A stolen/leaked session token would
// otherwise let an attacker throw unlimited password guesses at this endpoint.
app.post('/api/auth/change-password', requireAuth, loginLimiter, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!current_password || !new_password) {
      return res.status(400).json({ error: 'Current and new password are required.' });
    }
    if (new_password.length < MIN_PASSWORD_LENGTH) {
      return res.status(400).json({ error: `New password must be at least ${MIN_PASSWORD_LENGTH} characters.` });
    }
    // Same header re-parse as logout above - requireAuth already validated this is a
    // well-formed Bearer token matching an active session, so this is safe to trust here.
    const currentSessionToken = (req.headers.authorization || '').slice(7);
    await changePassword(req.userId, current_password, new_password, currentSessionToken);
    res.json({ ok: true });
  } catch (err) {
    res
      .status(err.status || 500)
      .json({ error: err.status ? err.message : 'Failed to change password', code: err.code });
  }
});

// Step 1 of turning on MFA: returns a QR code for the user's authenticator app. Doesn't
// take effect until /api/auth/mfa/confirm proves the user actually saved it.
app.post('/api/auth/mfa/setup', requireAuth, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
    const { qrDataUrl, manualEntryKey } = await setupMfa(req.userId, userResult.rows[0].email);
    res.json({ qr_data_url: qrDataUrl, manual_entry_key: manualEntryKey });
  } catch (err) {
    if (!err.status) console.error(`mfa/setup failed for user ${req.userId}:`, err);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to start MFA setup' });
  }
});

app.post('/api/auth/mfa/confirm', requireAuth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: 'Code is required.' });
    const { backupCodes } = await confirmMfa(req.userId, code);
    res.json({ backup_codes: backupCodes });
  } catch (err) {
    if (!err.status) console.error(`mfa/confirm failed for user ${req.userId}:`, err);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to confirm MFA setup' });
  }
});

// loginLimiter, same reasoning as change-password above - this also compares a real
// password via bcrypt (disableMfa's own check), so it belongs in the tightly-limited tier
// too, not left uncapped like the other requireAuth-only MFA routes above it.
app.post('/api/auth/mfa/disable', requireAuth, loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password is required.' });
    await disableMfa(req.userId, password);
    res.json({ ok: true });
  } catch (err) {
    if (!err.status) console.error(`mfa/disable failed for user ${req.userId}:`, err);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to disable MFA' });
  }
});

// Deliberately not behind requireAuth - the session token this is called with is still
// mfa_verified=false at this point, which requireAuth would reject. The token is supplied
// explicitly in the body (not the Authorization header) for the same reason: the app
// shouldn't persist this token as "the" session until this call actually succeeds.
app.post('/api/auth/mfa/verify-login', loginLimiter, async (req, res) => {
  try {
    const { token, code } = req.body;
    if (!token || !code) return res.status(400).json({ error: 'Token and code are required.' });
    const { user } = await verifyMfaLogin(token, code);
    res.json({ token, user });
  } catch (err) {
    // Never log the token or code themselves - both are bearer credentials for this
    // request, same reasoning as never logging a password.
    if (!err.status) console.error('mfa/verify-login failed:', err);
    res.status(err.status || 500).json({ error: err.status ? err.message : 'Failed to verify code' });
  }
});

// Self-service, immediate, no grace period - per the spec. Plaid Items are removed on
// Plaid's side first (so we stop being billed for them), then the user row is deleted,
// which cascades to every other table (transactions, budgets, expenses, bills, sessions).
// webhook_log isn't a foreign key (see its schema comment), so it needs its own explicit
// cleanup here - otherwise Plaid-derived data would linger with no remaining business need.
app.delete('/api/account', requireAuth, async (req, res) => {
  try {
    const items = await pool.query('SELECT access_token, plaid_item_id FROM plaid_items WHERE user_id = $1', [
      req.userId,
    ]);
    // Parallel, not sequential - this used to await each bank's itemRemove one at a time,
    // so someone with several linked banks and one slow Plaid response could push the
    // whole request past the client's timeout. The client would then show "failed, try
    // again" while this handler kept running server-side and actually finished deleting
    // the account - a retry then hit a dead session and got silently bounced to login,
    // with no confirmation the deletion (which the "failed" message told them didn't
    // happen) had, in fact, already happened. allSettled, not all - one bank's itemRemove
    // failing must not stop the others or block account deletion itself, same isolation
    // the original sequential loop already had per-item.
    await Promise.allSettled(
      items.rows.map((item) =>
        plaidClient
          .itemRemove({ access_token: decryptToken(item.access_token) })
          .catch((err) =>
            // Loud and greppable on purpose - once the account row below is deleted, this
            // Item's access_token is gone for good (cascaded with it), so a failure here
            // means it can never be cleaned up on Plaid's side again except by hand. No
            // automatic retry queue exists yet (a deliberate call - this is a rare,
            // transient-outage-only failure mode, not worth a new table + migration for
            // pre-launch), so this line is the only record that it ever happened.
            console.error(
              `[ORPHANED PLAID ITEM] itemRemove failed during account deletion - user ${req.userId}, plaid_item_id ${item.plaid_item_id}. This Item is now unreachable from Fenn and needs manual cleanup on Plaid's dashboard:`,
              plaidErrorDetail(err)
            )
          )
      )
    );
    if (items.rows.length > 0) {
      await pool.query('DELETE FROM webhook_log WHERE item_id = ANY($1)', [items.rows.map((i) => i.plaid_item_id)]);
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

// Unlike the OAuth redirect_uri, a webhook URL doesn't need to be pre-registered anywhere -
// safe to send in both Sandbox and Production.
const PLAID_WEBHOOK_URL = 'https://fenn-backend-production.up.railway.app/plaid-webhook';

// New data ready for an Item - the Transactions "core workflow" Plaid documents means
// responding to these by actually calling /transactions/sync, not just logging them.
// SYNC_UPDATES_AVAILABLE is the modern code for /sync-based integrations; the others are
// the older lifecycle codes Plaid can still send for the same underlying event - handling
// all of them covers either case rather than guessing which one production will use.
const TRANSACTIONS_UPDATE_CODES = new Set([
  'SYNC_UPDATES_AVAILABLE',
  'DEFAULT_UPDATE',
  'INITIAL_UPDATE',
  'HISTORICAL_UPDATE',
]);

// Plaid can fire several of the above for the same underlying update within seconds of
// each other (observed directly: INITIAL_UPDATE, SYNC_UPDATES_AVAILABLE, and
// HISTORICAL_UPDATE all within 3 seconds of one bank linking) - skip a resync that just
// happened rather than repeat the same live Plaid call and insert loop for nothing new.
const TRANSACTIONS_SYNC_DEBOUNCE_MS = 10_000;

// Plaid signs every webhook with a JWT (ES256) in the Plaid-Verification header, keyed by
// a `kid` that identifies which of Plaid's public keys signed it - fetched via
// webhookVerificationKeyGet and cached, since Plaid explicitly documents these as stable
// and cacheable. Without this, /plaid-webhook (below) has no way to tell a genuine Plaid
// call apart from anyone who POSTs a matching item_id - Plaid's item_id values aren't
// secret, so this isn't a hypothetical: it's the only thing standing between "Plaid told
// us this" and "anyone on the internet told us this."
const plaidWebhookKeyCache = new Map(); // kid -> KeyObject
const PLAID_WEBHOOK_MAX_AGE_SECONDS = 5 * 60; // rejects a replayed old JWT, per Plaid's own docs

async function getPlaidWebhookVerificationKey(kid, { forceRefresh = false } = {}) {
  if (!forceRefresh && plaidWebhookKeyCache.has(kid)) return plaidWebhookKeyCache.get(kid);
  const response = await plaidClient.webhookVerificationKeyGet({ key_id: kid });
  // Plaid's key is JSON Web Key (EC/P-256) - Node's own crypto module converts this
  // directly into a usable key object, no extra dependency (like jwk-to-pem) needed.
  const keyObject = crypto.createPublicKey({ key: response.data.key, format: 'jwk' });
  plaidWebhookKeyCache.set(kid, keyObject);
  return keyObject;
}

// Verifies both that the JWT itself is genuinely signed by Plaid (not just well-formed)
// and that it actually attests to *this* request's body - a valid signature over a
// different, older payload would otherwise let a captured webhook be replayed with
// different data spliced in. Returns nothing on success; throws with a short, specific
// reason on any failure so a rejected webhook is easy to diagnose from logs alone.
async function verifyPlaidWebhook(req) {
  const signedJwt = req.headers['plaid-verification'];
  if (!signedJwt) throw new Error('missing Plaid-Verification header');

  const decoded = jwt.decode(signedJwt, { complete: true });
  const kid = decoded?.header?.kid;
  if (!kid) throw new Error('could not read kid from JWT header');

  let payload;
  try {
    const key = await getPlaidWebhookVerificationKey(kid);
    payload = jwt.verify(signedJwt, key, { algorithms: ['ES256'], maxAge: PLAID_WEBHOOK_MAX_AGE_SECONDS });
  } catch (err) {
    // The cached key could just be stale (Plaid rotates these occasionally) - retry once
    // against a freshly-fetched key before actually giving up, per Plaid's own guidance.
    const key = await getPlaidWebhookVerificationKey(kid, { forceRefresh: true });
    payload = jwt.verify(signedJwt, key, { algorithms: ['ES256'], maxAge: PLAID_WEBHOOK_MAX_AGE_SECONDS });
  }

  if (!req.rawBody) throw new Error('no raw body captured to verify');
  const actualBodyHash = crypto.createHash('sha256').update(req.rawBody).digest('hex');
  if (actualBodyHash !== payload.request_body_sha256) throw new Error('request_body_sha256 mismatch');
}

// Where Plaid sends server-to-server notifications (new transactions ready, an Item
// breaking, etc.). Every webhook is logged to webhook_log regardless of type; transaction-
// update codes additionally trigger a real resync of that Item. Public (no requireAuth):
// Plaid calls this directly, with no user session - verifyPlaidWebhook above is what
// stands in for that, checked before anything else here runs.
// Everything here runs BEFORE responding to Plaid, not after - Railway doesn't guarantee
// background work continues once a request's HTTP response has been sent, which silently
// dropped the Transactions resync in production (confirmed: it ran correctly every time
// locally, and the much cheaper single-row needs_reconnect update after it in the same
// handler kept succeeding in production even when the resync didn't - work started after
// res.sendStatus() just wasn't reliably finishing). Plaid tolerates several seconds before
// treating a webhook as failed, so doing the work synchronously here is well within that.
app.post('/plaid-webhook', async (req, res) => {
  try {
    await verifyPlaidWebhook(req);
  } catch (err) {
    console.error('[plaid webhook] rejected - failed verification:', err.message);
    return res.sendStatus(401);
  }

  const { webhook_type, webhook_code, item_id } = req.body || {};
  console.log(`[plaid webhook] ${webhook_type}/${webhook_code} for item ${item_id}`);
  let webhookLogId = null;
  try {
    const inserted = await pool.query(
      'INSERT INTO webhook_log (webhook_type, webhook_code, item_id, payload) VALUES ($1, $2, $3, $4) RETURNING id',
      [webhook_type, webhook_code, item_id, JSON.stringify(req.body)]
    );
    webhookLogId = inserted.rows[0].id;
  } catch (err) {
    console.error('Failed to log webhook', err);
  }

  if (webhook_type === 'TRANSACTIONS' && TRANSACTIONS_UPDATE_CODES.has(webhook_code) && item_id) {
    try {
      const result = await pool.query(
        'SELECT id, user_id, access_token, cursor, created_at, last_synced_at FROM plaid_items WHERE plaid_item_id = $1',
        [item_id]
      );
      const item = result.rows[0];
      const msSinceLastSync = item?.last_synced_at ? Date.now() - new Date(item.last_synced_at).getTime() : Infinity;

      if (!item) {
        if (webhookLogId) await pool.query('UPDATE webhook_log SET sync_error = $1 WHERE id = $2', ['NO_MATCHING_ITEM', webhookLogId]);
      } else if (msSinceLastSync < TRANSACTIONS_SYNC_DEBOUNCE_MS) {
        console.log(`[plaid webhook] skipping sync for item ${item_id} - synced ${msSinceLastSync}ms ago`);
        if (webhookLogId) await pool.query('UPDATE webhook_log SET sync_error = $1 WHERE id = $2', ['SKIPPED_DEBOUNCE', webhookLogId]);
      } else {
        await syncOneItem(item, item.user_id);
        console.log(`[plaid webhook] synced item ${item_id} after ${webhook_code}`);
        if (webhookLogId) await pool.query('UPDATE webhook_log SET sync_error = $1 WHERE id = $2', ['OK', webhookLogId]);
      }
    } catch (err) {
      const message = plaidErrorDetail(err);
      console.error(`[plaid webhook] sync failed for item ${item_id}:`, message);
      if (webhookLogId) await pool.query('UPDATE webhook_log SET sync_error = $1 WHERE id = $2', [message, webhookLogId]);
    }
  }

  // Same needs_reconnect flag already set reactively when a foreground sync hits
  // ITEM_LOGIN_REQUIRED (see syncOneItem's caller) - this sets it proactively too, from
  // Plaid telling us in advance rather than waiting for the user to open the app and a
  // sync to fail. The existing reconnect entry point (LinkedBanks.js's update-mode Link
  // flow) is what actually resolves it - nothing new needed on that side.
  const isLoginRequiredError = webhook_type === 'ITEM' && webhook_code === 'ERROR' && req.body?.error?.error_code === 'ITEM_LOGIN_REQUIRED';
  const isPendingExpirationOrDisconnect =
    webhook_type === 'ITEM' && (webhook_code === 'PENDING_EXPIRATION' || webhook_code === 'PENDING_DISCONNECT');
  if ((isLoginRequiredError || isPendingExpirationOrDisconnect) && item_id) {
    try {
      await pool.query('UPDATE plaid_items SET needs_reconnect = true WHERE plaid_item_id = $1', [item_id]);
      console.log(`[plaid webhook] flagged item ${item_id} for reconnect (${webhook_code})`);
    } catch (err) {
      console.error(`[plaid webhook] failed to flag item ${item_id} for reconnect:`, err.message);
    }
  }

  // The mirror case - Plaid can detect a broken login fixed itself without the user ever
  // going through our update-mode flow (markReconnected, which clears this same flag on
  // the completion side). Without this, the reconnect banner would keep showing for a
  // connection that's actually already fine again.
  if (webhook_type === 'ITEM' && webhook_code === 'LOGIN_REPAIRED' && item_id) {
    try {
      await pool.query('UPDATE plaid_items SET needs_reconnect = false WHERE plaid_item_id = $1', [item_id]);
      console.log(`[plaid webhook] cleared reconnect flag for item ${item_id} (LOGIN_REPAIRED)`);
    } catch (err) {
      console.error(`[plaid webhook] failed to clear reconnect flag for item ${item_id}:`, err.message);
    }
  }

  // The connection itself is fine here (unlike needs_reconnect) - Plaid's just spotted an
  // account at that institution the user hasn't shared with us. create_link_token reads
  // this flag to decide whether to request account_selection_enabled for that item.
  if (webhook_type === 'ITEM' && webhook_code === 'NEW_ACCOUNTS_AVAILABLE' && item_id) {
    try {
      await pool.query('UPDATE plaid_items SET new_accounts_available = true WHERE plaid_item_id = $1', [item_id]);
      console.log(`[plaid webhook] flagged item ${item_id} - new accounts available`);
    } catch (err) {
      console.error(`[plaid webhook] failed to flag item ${item_id} for new accounts:`, err.message);
    }
  }

  res.sendStatus(200);
});

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
      const item = await pool.query(
        'SELECT access_token, new_accounts_available FROM plaid_items WHERE id = $1 AND user_id = $2',
        [item_id, req.userId]
      );
      if (item.rows.length === 0) {
        return res.status(404).json({ error: 'Bank connection not found' });
      }
      const response = await plaidClient.linkTokenCreate({
        user: { client_user_id: String(req.userId) },
        client_name: 'Fenn',
        access_token: decryptToken(item.rows[0].access_token),
        country_codes: ['US'],
        language: 'en',
        webhook: PLAID_WEBHOOK_URL,
        ...(PLAID_OAUTH_REDIRECT_URI && { redirect_uri: PLAID_OAUTH_REDIRECT_URI }),
        // Only requested when Plaid's actually told us new accounts are sitting there
        // (NEW_ACCOUNTS_AVAILABLE) - a plain broken-login reconnect doesn't need this.
        ...(item.rows[0].new_accounts_available && { update: { account_selection_enabled: true } }),
      });
      return res.json({ link_token: response.data.link_token });
    }

    const response = await plaidClient.linkTokenCreate({
      user: { client_user_id: String(req.userId) },
      client_name: 'Fenn',
      products: ['transactions'],
      country_codes: ['US'],
      language: 'en',
      webhook: PLAID_WEBHOOK_URL,
      ...(PLAID_OAUTH_REDIRECT_URI && { redirect_uri: PLAID_OAUTH_REDIRECT_URI }),
    });
    res.json({ link_token: response.data.link_token });
  } catch (err) {
    console.error(plaidErrorDetail(err));
    res.status(500).json({ error: 'Failed to create link token' });
  }
});

// Called after a successful update-mode Link session - the access_token doesn't change,
// we just clear the flag so the reconnect banner goes away.
app.post('/api/plaid_items/:id/reconnected', async (req, res) => {
  try {
    await pool.query(
      'UPDATE plaid_items SET needs_reconnect = false, new_accounts_available = false WHERE id = $1 AND user_id = $2',
      [req.params.id, req.userId]
    );
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
// recurring bills only - webhook_log needs its own explicit cleanup, same reasoning as
// account deletion above.
app.delete('/api/plaid_items/:id', async (req, res) => {
  try {
    const item = await pool.query('SELECT access_token, plaid_item_id FROM plaid_items WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.userId,
    ]);
    if (item.rows.length === 0) {
      return res.status(404).json({ error: 'Bank connection not found' });
    }

    try {
      await plaidClient.itemRemove({ access_token: decryptToken(item.rows[0].access_token) });
    } catch (err) {
      // Same "loud, no retry queue" tradeoff as account deletion above - once the row
      // below is gone, this Item's access_token is unrecoverable and needs manual
      // cleanup on Plaid's dashboard if this ever fires.
      console.error(
        `[ORPHANED PLAID ITEM] itemRemove failed removing a single bank connection - user ${req.userId}, plaid_item_id ${item.rows[0].plaid_item_id}. This Item is now unreachable from Fenn and needs manual cleanup on Plaid's dashboard:`,
        plaidErrorDetail(err)
      );
    }

    await pool.query('DELETE FROM webhook_log WHERE item_id = $1', [item.rows[0].plaid_item_id]);
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
    const { public_token, institution_name, institution_id } = req.body;
    const userId = req.userId;

    // Per Plaid's own duplicate-Item guidance: check before exchanging, not after - an
    // exchanged-then-discarded Item still counts as a connection for billing purposes.
    // institution_id (not the display name) is the reliable match key here.
    if (institution_id) {
      const existing = await pool.query(
        'SELECT id FROM plaid_items WHERE user_id = $1 AND institution_id = $2',
        [userId, institution_id]
      );
      if (existing.rows.length > 0) {
        return res.status(409).json({ error: 'You already have this bank connected.' });
      }
    }

    const response = await plaidClient.itemPublicTokenExchange({ public_token });

    try {
      await pool.query(
        `INSERT INTO plaid_items (user_id, plaid_item_id, access_token, institution_name, institution_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (plaid_item_id) DO UPDATE SET access_token = EXCLUDED.access_token`,
        [userId, response.data.item_id, encryptToken(response.data.access_token), institution_name || null, institution_id || null]
      );
    } catch (insertErr) {
      // idx_plaid_items_user_institution (schema.sql) - the real backstop for the race the
      // pre-check above can't fully close (a real Plaid network call sits between the
      // SELECT and this INSERT). The pre-check already covers the common case cheaply;
      // this only matters for the rare overlap, where it's the difference between a clean
      // "already connected" message and two rows silently double-counting the same bank's
      // spend going forward.
      if (insertErr.code === '23505') {
        return res.status(409).json({ error: 'You already have this bank connected.' });
      }
      throw insertErr;
    }

    res.json({ item_id: response.data.item_id });
  } catch (err) {
    console.error(plaidErrorDetail(err));
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

  await pool.query('UPDATE plaid_items SET cursor = $1, last_synced_at = now() WHERE id = $2', [cursor, item.id]);

  return { added: added.length, modified: modified.length, removed: removed.length };
}

// Step 3: pull transactions for every bank connection this user has.
app.post('/api/sync_transactions', async (req, res) => {
  try {
    const userId = req.userId;
    // Excludes items already flagged needs_reconnect - a broken Item's access_token is
    // guaranteed to fail with ITEM_LOGIN_REQUIRED until the user completes the reconnect
    // flow, so calling Plaid for it again on every sync (every session, every 10-minute
    // gate refresh, every pull-to-refresh) was a real, indefinitely-repeating wasted call.
    const items = await pool.query(
      'SELECT id, plaid_item_id, access_token, cursor, created_at, last_synced_at FROM plaid_items WHERE user_id = $1 AND needs_reconnect = false',
      [userId]
    );

    if (items.rows.length === 0) {
      return res.status(400).json({ error: 'No linked account yet. Connect a bank first.' });
    }

    let totalAdded = 0;
    let totalModified = 0;
    let totalRemoved = 0;
    const needsReconnect = [];

    // Parallel, not sequential - same reasoning as account deletion's itemRemove fan-out
    // above: with up to 5 banks and a first-time large historical backfill, syncing one at
    // a time could push the whole request past the client's timeout. One bank's connection
    // breaking (expired login, MFA change, etc.) still can't stop the others - each item's
    // own try/catch below means this never rejects, only ever resolves with a per-item
    // outcome, so allSettled is defensive rather than load-bearing here.
    const results = await Promise.allSettled(
      items.rows.map(async (item) => {
        // Server-side debounce, not just the client's own 10-minute gate - that gate is a
        // plain in-memory JS variable that resets on every cold start, and doesn't stop a
        // second concurrent/rapid-fire request (a relaunch storm, a modified client, two
        // tabs both becoming active within moments of each other) from reaching Plaid.
        // Same debounce window and reasoning as the webhook handler's own guard.
        const msSinceLastSync = item.last_synced_at ? Date.now() - new Date(item.last_synced_at).getTime() : Infinity;
        if (msSinceLastSync < TRANSACTIONS_SYNC_DEBOUNCE_MS) {
          return { item, counts: { added: 0, modified: 0, removed: 0 } };
        }
        try {
          return { item, counts: await syncOneItem(item, userId) };
        } catch (err) {
          const errorCode = err.response?.data?.error_code;
          if (errorCode === 'ITEM_LOGIN_REQUIRED') {
            await pool.query('UPDATE plaid_items SET needs_reconnect = true WHERE id = $1', [item.id]);
            return { item, needsReconnect: true };
          }
          console.error(`sync failed for item ${item.plaid_item_id}:`, plaidErrorDetail(err));
          return { item, failed: true };
        }
      })
    );

    for (const r of results) {
      if (r.status !== 'fulfilled') continue; // unreachable in practice - every path above resolves, never throws
      const { counts, needsReconnect: nr, item } = r.value;
      if (counts) {
        totalAdded += counts.added;
        totalModified += counts.modified;
        totalRemoved += counts.removed;
      }
      if (nr) needsReconnect.push(item.id);
    }

    res.json({ added: totalAdded, modified: totalModified, removed: totalRemoved, needsReconnect });
  } catch (err) {
    console.error(plaidErrorDetail(err));
    res.status(500).json({ error: 'Failed to sync transactions' });
  }
});

// Plaid categories that should never count toward daily spend, per the spec:
// transfers between the user's own accounts, and credit card bill payments
// (the underlying purchases were already counted when they happened).
const AUTO_EXCLUDED_PFC_PRIMARY = ['TRANSFER_IN', 'TRANSFER_OUT'];
const AUTO_EXCLUDED_PFC_DETAILED = ['LOAN_PAYMENTS_CREDIT_CARD_PAYMENT'];

// Carved out of the TRANSFER_OUT exclusion above - Plaid's own TRANSFER_IN/TRANSFER_OUT
// primary category lumps a genuine self-account transfer (checking -> savings) together
// with a peer-to-peer app payment (Venmo, Cash App, PayPal, Zelle), but paying a friend
// back for dinner is real spending, not moving your own money around. Plaid's detailed
// value is what actually distinguishes the two (confirmed live against real transaction
// data - a Venmo payment came back as pfc_primary: TRANSFER_OUT, pfc_detailed:
// TRANSFER_OUT_TRANSFER_OUT_FROM_APPS; a real self-transfer wouldn't carry that detailed
// value). Only the outflow side needs this - the inflow side (someone paying you back)
// still never counts toward spend either way, same as any other negative-amount
// transaction, it's just categorized differently for display (see categorizeExpenses in
// api.js on the frontend).
const PFC_DETAILED_P2P_OUT = 'TRANSFER_OUT_TRANSFER_OUT_FROM_APPS';

// Read-only view of what's actually in our database now, for testing/verification.
app.get('/api/transactions', async (req, res) => {
  try {
    const { date, start, end } = req.query;
    const userId = req.userId;

    if ((date && !isValidDateKey(date)) || (start && !isValidDateKey(start)) || (end && !isValidDateKey(end))) {
      return res.status(400).json({ error: 'date, start, and end must be valid YYYY-MM-DD dates' });
    }

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
        // This CASE must stay in exact lockstep with COUNTS_TOWARD_SPEND below (same
        // predicate, just inverted) - they drifted once already: a recurring P2P payment
        // (is_recurring_bill=true, pfc_detailed=P2P_OUT - a monthly Venmo rent-split, say)
        // came back excluded=false here (unconditionally not-excluded for any P2P_OUT
        // transaction, regardless of is_recurring_bill) while COUNTS_TOWARD_SPEND already
        // required is_recurring_bill=false before treating a P2P_OUT transaction as
        // counted - so the itemized list showed it as a normal counted expense while the
        // total silently didn't include it. is_recurring_bill is now checked before the
        // P2P_OUT carve-out, not folded into the fallback ELSE after it, so a recurring
        // P2P payment is excluded by default same as any other recurring bill.
        `SELECT t.id, to_char(t.date, 'YYYY-MM-DD') AS date, t.name, t.merchant_name, t.amount, t.pending, t.pfc_primary, t.pfc_detailed, t.is_recurring_bill, t.user_income_excluded, pi.institution_name,
           CASE
             WHEN t.amount <= 0 THEN true
             WHEN t.user_excluded IS NOT NULL THEN t.user_excluded
             WHEN t.is_recurring_bill THEN true
             WHEN t.pfc_detailed = $6 THEN false
             ELSE (
               COALESCE(t.pfc_primary, '') = ANY($3) OR COALESCE(t.pfc_detailed, '') = ANY($4)
             )
           END AS excluded
         FROM transactions t
         JOIN plaid_items pi ON pi.id = t.plaid_item_id
         WHERE t.user_id = $1 AND t.date BETWEEN $2 AND $5
         ORDER BY t.date DESC, t.id
         LIMIT 5000`,
        // 5000, not unbounded - every real caller asks for a day/week/month/quarter at
        // most, so this is purely a safety cap against a pathological range (or a modified
        // client) pulling down years of history in one response, same reasoning as the
        // fallback branch below already having its own LIMIT 100.
        [userId, rangeStart, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED, rangeEnd, PFC_DETAILED_P2P_OUT]
      );
      return res.json(result.rows);
    }

    const result = await pool.query(
      // to_char, not a bare column - same reasoning as the ranged branch above (a raw
      // DATE column serializes as a full ISO timestamp, not the plain 'YYYY-MM-DD' every
      // date-string helper in the app expects). This fallback branch (no date/start/end
      // query params) had been missed when that fix was made for the ranged branch.
      `SELECT id, to_char(date, 'YYYY-MM-DD') AS date, name, merchant_name, amount, pending, pfc_primary, pfc_detailed, user_excluded
       FROM transactions WHERE user_id = $1 ORDER BY date DESC LIMIT 100`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Searches merchant/transaction name and manual-expense notes, across a user's entire
// history (not scoped to a date range like /api/transactions) - the whole point is finding
// something you can't remember the date of. Same excluded CASE as /api/transactions above,
// kept in exact lockstep for the same reason documented there - a result showing up
// "included" here while /api/spend disagrees would be a confusing, silently-drifted bug.
app.get('/api/search', async (req, res) => {
  try {
    const userId = req.userId;
    // Capped, not just trimmed - no merchant name or note is ever remotely this long, so
    // anything past it is either accidental (paste) or someone poking at the endpoint, not
    // a real search a user typed. Bound requests are already parameterized (safe from SQL
    // injection either way), but there's no reason to run an ILIKE scan against an
    // unbounded string.
    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    if (q.length < 2) return res.json({ transactions: [], manual: [] });
    const like = `%${q}%`;

    const [txns, manual] = await Promise.all([
      pool.query(
        `SELECT t.id, to_char(t.date, 'YYYY-MM-DD') AS date, t.name, t.merchant_name, t.amount, t.pfc_primary, t.pfc_detailed, t.is_recurring_bill, t.user_income_excluded, pi.institution_name,
           CASE
             WHEN t.amount <= 0 THEN true
             WHEN t.user_excluded IS NOT NULL THEN t.user_excluded
             WHEN t.is_recurring_bill THEN true
             WHEN t.pfc_detailed = $5 THEN false
             ELSE (
               COALESCE(t.pfc_primary, '') = ANY($3) OR COALESCE(t.pfc_detailed, '') = ANY($4)
             )
           END AS excluded
         FROM transactions t
         JOIN plaid_items pi ON pi.id = t.plaid_item_id
         WHERE t.user_id = $1 AND (t.merchant_name ILIKE $2 OR t.name ILIKE $2)
         ORDER BY t.date DESC, t.id
         LIMIT 50`,
        [userId, like, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED, PFC_DETAILED_P2P_OUT]
      ),
      pool.query(
        `SELECT id, amount, note, to_char(local_date, 'YYYY-MM-DD') AS local_date, occurred_at
         FROM manual_expenses
         WHERE user_id = $1 AND note ILIKE $2
         ORDER BY occurred_at DESC
         LIMIT 50`,
        [userId, like]
      ),
    ]);

    res.json({ transactions: txns.rows, manual: manual.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Search failed' });
  }
});

app.get('/api/plaid_items', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      'SELECT id, institution_name, needs_reconnect, new_accounts_available, created_at FROM plaid_items WHERE user_id = $1 ORDER BY created_at',
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
    // Same needs_reconnect exclusion as sync_transactions - a broken Item is guaranteed to
    // fail here too until reconnected.
    const items = await pool.query(
      'SELECT id, plaid_item_id, access_token, recurring_synced_at FROM plaid_items WHERE user_id = $1 AND needs_reconnect = false',
      [userId]
    );

    // Parallel, not sequential - same reasoning as sync_transactions above (a slow bank
    // response with several linked accounts could otherwise push this past the client's
    // timeout). Each item's own try/catch below keeps the per-item isolation intact.
    await Promise.allSettled(
      items.rows.map(async (item) => {
      // Server-side debounce, same reasoning as sync_transactions' own guard above - the
      // client's 10-minute gate is in-memory and resets on cold start, so this is the only
      // thing standing between a relaunch storm and unbounded transactionsRecurringGet
      // calls (a heavier Plaid call than a plain sync, per this route's own file comment).
      const msSinceLastSync = item.recurring_synced_at
        ? Date.now() - new Date(item.recurring_synced_at).getTime()
        : Infinity;
      if (msSinceLastSync < TRANSACTIONS_SYNC_DEBOUNCE_MS) return;
      try {
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
               -- Records a price-increase alert when last_amount rose by at least $1 AND
               -- at least 2% (GREATEST picks whichever floor is higher for this bill's own
               -- size) - filters out cent-level noise from Plaid's own re-estimation on a
               -- big bill (rent going from $2000.00 to $2001.13 isn't a real increase to
               -- flag) while still catching a real jump on a small one (a $9.99
               -- subscription needs only a ~$1 hike, not 2% of $2000, to qualify). Only
               -- overwrites previous_amount when a NEW qualifying increase is seen this
               -- sync - an already-pending, not-yet-acknowledged alert from an earlier
               -- sync is left alone rather than silently cleared just because this
               -- particular run didn't see a fresh jump.
               previous_amount = CASE
                 WHEN EXCLUDED.last_amount IS NOT NULL
                  AND recurring_bills.last_amount IS NOT NULL
                  AND EXCLUDED.last_amount - recurring_bills.last_amount >= GREATEST(1, recurring_bills.last_amount * 0.02)
                 THEN recurring_bills.last_amount
                 ELSE recurring_bills.previous_amount
               END,
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
        await pool.query('UPDATE plaid_items SET recurring_synced_at = now() WHERE id = $1', [item.id]);
      } catch (err) {
        console.error(`sync_recurring failed for item ${item.plaid_item_id}:`, plaidErrorDetail(err));
      }
      })
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(plaidErrorDetail(err));
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
      // to_char, not a bare column - pg's driver otherwise serializes a raw DATE column as
      // a full ISO timestamp (e.g. "2026-07-13T06:00:00.000Z"), and the frontend's
      // parseDateKey splits on '-' expecting a plain 'YYYY-MM-DD' string - fed that ISO
      // string instead, it silently produces an Invalid Date (confirmed live: this was
      // showing "last Invalid Date - next ~Invalid Date" for every bill).
      `SELECT rb.id, rb.merchant_name, rb.description, rb.average_amount, rb.last_amount, rb.frequency, to_char(rb.last_date, 'YYYY-MM-DD') AS last_date, rb.is_active, rb.user_included, rb.pfc_primary, rb.previous_amount
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
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid bill id' });
    }
    const userId = req.userId;
    const included = !!req.body.included;

    const bill = await pool.query('SELECT id FROM recurring_bills WHERE id = $1 AND user_id = $2', [
      req.params.id,
      userId,
    ]);
    if (bill.rows.length === 0) {
      return res.status(404).json({ error: 'Bill not found' });
    }

    // AND user_id = $3, not just id = $2 - not currently reachable any other way (the
    // ownership-verifying SELECT right above already 404s a bill that isn't this user's
    // own), but every other :id-scoped UPDATE/DELETE in this file filters on user_id
    // directly rather than relying on a separate check beforehand, so this one should too.
    await pool.query('UPDATE recurring_bills SET user_included = $1, updated_at = now() WHERE id = $2 AND user_id = $3', [
      included,
      req.params.id,
      userId,
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

// Dismisses a pending price-increase alert - clears previous_amount back to null, same
// "was X, now Y" comparison a fresh sync would set it to again if the price goes up a
// second time. WHERE ... AND user_id = $2 in the same statement, not a separate existence
// check first - a bill that isn't this user's own simply matches zero rows and no-ops,
// rather than needing its own 404 branch.
//
// AND previous_amount = $3 (the exact value the client is acknowledging, sent back in the
// request body) is a compare-and-swap, not just an extra filter - without it, a sync
// racing this same request (e.g. a pull-to-refresh mid-tap) that detects a brand-new
// qualifying increase in between could have that fresh previous_amount silently clobbered
// back to null by this blind clear, permanently losing visibility into an increase the
// user never actually saw. If the stored value has already moved on by the time this
// runs, the WHERE clause simply matches nothing - acknowledged: false tells the frontend
// that happened, so it can reload instead of trusting its own optimistic clear.
app.patch('/api/bills/:id/acknowledge_increase', async (req, res) => {
  try {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid bill id' });
    }
    const result = await pool.query(
      'UPDATE recurring_bills SET previous_amount = NULL WHERE id = $1 AND user_id = $2 AND previous_amount = $3 RETURNING id',
      [req.params.id, req.userId, req.body.previous_amount]
    );
    res.json({ ok: true, acknowledged: result.rows.length > 0 });
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
    // Number(), not the raw body value - `!monthly_amount || monthly_amount <= 0` alone
    // only catches falsy/negative numbers, not a non-numeric string ("abc" <= 0 is false
    // in JS, so it passed straight through to Postgres and surfaced as a generic 500
    // instead of a clean 400).
    const amount = Number(monthly_amount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > MAX_MONEY_AMOUNT) {
      return res.status(400).json({ error: `monthly_amount must be a positive number up to ${MAX_MONEY_AMOUNT}` });
    }
    const weekStartDay = week_start_day ?? 0;
    if (!Number.isInteger(weekStartDay) || weekStartDay < 0 || weekStartDay > 6) {
      return res.status(400).json({ error: 'week_start_day must be an integer 0-6' });
    }
    const userId = req.userId;
    await pool.query(
      `INSERT INTO budgets (user_id, monthly_amount, week_start_day, updated_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (user_id) DO UPDATE SET
         monthly_amount = EXCLUDED.monthly_amount,
         week_start_day = EXCLUDED.week_start_day,
         updated_at = now()`,
      [userId, amount, weekStartDay]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save budget' });
  }
});

// One savings goal per user - see schema.sql for why progress isn't stored here (it's
// derived client-side from daily spend history since started_at).
const GOAL_NAME_MAX_LENGTH = 60;
// The actual ceiling of every NUMERIC(12,2) money column (budgets.monthly_amount,
// savings_goals.target_amount, manual_expenses.amount) - 12 total digits, 2 after the
// decimal, so 10 before it. Validation below only ever checked "positive," not this upper
// bound, so a value past it wasn't rejected with a clean 400 - it hit Postgres, which threw
// a numeric field overflow error caught by the generic handler and returned as a bare 500.
const MAX_MONEY_AMOUNT = 9999999999.99;
// No real manually-typed note is anywhere near this long - same reasoning as /api/search's
// own 100-char cap on its query param, which this route was missing entirely (note is an
// unbounded TEXT column, and /api/search's own ILIKE scan later matches against it).
const NOTE_MAX_LENGTH = 500;

function parseGoalFields(body) {
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > GOAL_NAME_MAX_LENGTH) {
    return { error: `name must be 1-${GOAL_NAME_MAX_LENGTH} characters` };
  }
  const targetAmount = Number(body.target_amount);
  if (!Number.isFinite(targetAmount) || targetAmount <= 0 || targetAmount > MAX_MONEY_AMOUNT) {
    return { error: `target_amount must be a positive number up to ${MAX_MONEY_AMOUNT}` };
  }
  let targetDate = null;
  if (body.target_date != null) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(body.target_date) || Number.isNaN(new Date(body.target_date).getTime())) {
      return { error: 'target_date must be a valid YYYY-MM-DD date' };
    }
    targetDate = body.target_date;
  }
  return { name, targetAmount, targetDate };
}

app.get('/api/savings-goal', async (req, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      `SELECT name, target_amount, to_char(target_date, 'YYYY-MM-DD') AS target_date, started_at
       FROM savings_goals WHERE user_id = $1`,
      [userId]
    );
    res.json(result.rows[0] || null);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch savings goal' });
  }
});

// Starts fresh: resets started_at to now, so progress (computed client-side from history
// since started_at) begins at zero. Used both for a first-time goal and for explicitly
// starting over/replacing an existing one.
app.post('/api/savings-goal', async (req, res) => {
  try {
    const parsed = parseGoalFields(req.body);
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    const userId = req.userId;
    await pool.query(
      `INSERT INTO savings_goals (user_id, name, target_amount, target_date, started_at, updated_at)
       VALUES ($1, $2, $3, $4, now(), now())
       ON CONFLICT (user_id) DO UPDATE SET
         name = EXCLUDED.name,
         target_amount = EXCLUDED.target_amount,
         target_date = EXCLUDED.target_date,
         started_at = now(),
         updated_at = now()`,
      [userId, parsed.name, parsed.targetAmount, parsed.targetDate]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save savings goal' });
  }
});

// Edits in place - unlike POST above, started_at is deliberately left untouched so
// changing the target or deadline doesn't reset progress already made toward it.
app.patch('/api/savings-goal', async (req, res) => {
  try {
    const parsed = parseGoalFields(req.body);
    if (parsed.error) return res.status(400).json({ error: parsed.error });
    const userId = req.userId;
    const result = await pool.query(
      `UPDATE savings_goals SET name = $2, target_amount = $3, target_date = $4, updated_at = now()
       WHERE user_id = $1`,
      [userId, parsed.name, parsed.targetAmount, parsed.targetDate]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: 'No savings goal to update' });
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update savings goal' });
  }
});

app.delete('/api/savings-goal', async (req, res) => {
  try {
    const userId = req.userId;
    await pool.query('DELETE FROM savings_goals WHERE user_id = $1', [userId]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete savings goal' });
  }
});

// Total, all-time count of manually-logged expenses - not scoped to any date range. Used
// on the free tier to power a one-time "you've logged N expenses by hand" upgrade nudge
// (see getManualExpenseCount/RingScreen.js) once someone has put in enough real, visible
// effort that automatic bank-linked tracking is an obviously compelling trade. A plain
// COUNT(*), not a route someone hits often - the frontend checks this at most once ever
// per free-tier account (gated behind a SecureStore "already shown" flag).
app.get('/api/expenses/count', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM manual_expenses WHERE user_id = $1', [req.userId]);
    res.json({ count: Number(result.rows[0].count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to count expenses' });
  }
});

app.get('/api/expenses', async (req, res) => {
  try {
    const { date, start, end } = req.query;
    if (!date && !(start && end)) {
      return res.status(400).json({ error: 'date, or start and end, query params (YYYY-MM-DD) are required' });
    }
    if ((date && !isValidDateKey(date)) || (start && !isValidDateKey(start)) || (end && !isValidDateKey(end))) {
      return res.status(400).json({ error: 'date, start, and end must be valid YYYY-MM-DD dates' });
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
    const { amount: rawAmount, note, local_date, occurred_at } = req.body;
    // Number(), not the raw body value - see the same fix on POST /api/budget above for
    // why (a non-numeric string slipped past the old `!amount || amount <= 0` check).
    const amount = Number(rawAmount);
    if (!Number.isFinite(amount) || amount <= 0 || amount > MAX_MONEY_AMOUNT) {
      return res.status(400).json({ error: `amount must be a positive number up to ${MAX_MONEY_AMOUNT}` });
    }
    if (!local_date) {
      return res.status(400).json({ error: 'local_date (YYYY-MM-DD, the device\'s local calendar date) is required' });
    }
    if (typeof note === 'string' && note.length > NOTE_MAX_LENGTH) {
      return res.status(400).json({ error: `note must be ${NOTE_MAX_LENGTH} characters or fewer` });
    }
    const userId = req.userId;
    const result = await pool.query(
      // to_char on the RETURNING clause too, not just GET /api/expenses's own SELECT -
      // local_date is the same raw DATE column either way, so without this the response
      // right after logging an expense carried a malformed date (a full ISO timestamp
      // instead of 'YYYY-MM-DD') until the next GET refetch corrected it.
      `INSERT INTO manual_expenses (user_id, amount, note, local_date, occurred_at)
       VALUES ($1, $2, $3, $4, COALESCE($5, now()))
       RETURNING id, amount, note, to_char(local_date, 'YYYY-MM-DD') AS local_date, occurred_at`,
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
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid expense id' });
    }
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
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid transaction id' });
    }
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

// Excludes (or re-includes) a specific P2P transfer-in (Venmo/Zelle/Cash App/PayPal) from
// income - these count as income by default, this is the escape hatch for the rare one
// that genuinely wasn't. Separate from the exclude toggle above, which only ever affects
// spend counting. Not restricted to a particular pfc_detailed value here - the frontend
// only ever shows this control on a P2P transfer-in, but there's no harm in the backend
// accepting it generically (same reasoning /exclude above doesn't check the transaction's
// own category either).
app.patch('/api/transactions/:id/exclude_income', async (req, res) => {
  try {
    if (!isValidId(req.params.id)) {
      return res.status(400).json({ error: 'Invalid transaction id' });
    }
    const { excluded } = req.body;
    const userId = req.userId;
    await pool.query('UPDATE transactions SET user_income_excluded = $1 WHERE id = $2 AND user_id = $3', [
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
        AND (
          t.pfc_detailed = $6
          OR (
            COALESCE(t.pfc_primary, '') != ALL($4)
            AND COALESCE(t.pfc_detailed, '') != ALL($5)
          )
        )
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
    if (!isValidDateKey(start) || !isValidDateKey(end)) {
      return res.status(400).json({ error: 'start and end must be valid YYYY-MM-DD dates' });
    }
    const userId = req.userId;

    // Independent queries (Plaid-synced transactions vs. manual expenses, different
    // tables) - run together instead of one after another.
    const [plaidResult, manualResult] = await Promise.all([
      pool.query(
        `SELECT COALESCE(SUM(t.amount), 0) AS total FROM transactions t
         WHERE t.user_id = $1
           AND t.date BETWEEN $2 AND $3
           AND ${COUNTS_TOWARD_SPEND}`,
        [userId, start, end, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED, PFC_DETAILED_P2P_OUT]
      ),
      pool.query(
        `SELECT COALESCE(SUM(amount), 0) AS total FROM manual_expenses
         WHERE user_id = $1 AND local_date BETWEEN $2 AND $3`,
        [userId, start, end]
      ),
    ]);

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
    if (!isValidDateKey(start) || !isValidDateKey(end)) {
      return res.status(400).json({ error: 'start and end must be valid YYYY-MM-DD dates' });
    }
    const userId = req.userId;

    const result = await pool.query(
      `SELECT gs::date AS date, COALESCE(t.total, 0) + COALESCE(m.total, 0) AS spent
       FROM generate_series($2::date, $3::date, interval '1 day') AS gs
       LEFT JOIN (
         SELECT t.date, SUM(t.amount) AS total FROM transactions t
         WHERE t.user_id = $1 AND t.date BETWEEN $2 AND $3
           AND ${COUNTS_TOWARD_SPEND}
         GROUP BY t.date
       ) t ON t.date = gs::date
       LEFT JOIN (
         SELECT local_date, SUM(amount) AS total FROM manual_expenses
         WHERE user_id = $1 AND local_date BETWEEN $2 AND $3
         GROUP BY local_date
       ) m ON m.local_date = gs::date
       ORDER BY gs`,
      [userId, start, end, AUTO_EXCLUDED_PFC_PRIMARY, AUTO_EXCLUDED_PFC_DETAILED, PFC_DETAILED_P2P_OUT]
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

// Every route above wraps its own body in try/catch and returns a JSON error - this is
// the fallback for anything that gets thrown outside of one of those (most notably
// requireAuth/requirePaidTier, which run before a route's own try/catch even starts).
// Without this, Express's default error handler takes over: an HTML error page instead
// of JSON (breaking every client call site's `res.json()`/error-shape assumptions), and
// - whenever NODE_ENV isn't explicitly 'production' - a stack trace in the response body.
// Must be registered last, after every route, and keep all four (err, req, res, next)
// params - that arity is what tells Express this is an error handler rather than a
// regular middleware.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal error' });
});

const PORT = process.env.PORT || 8000;
// Explicitly '0.0.0.0', not the default - on Railway (and similar container platforms)
// the app can print this exact "listening" line successfully while still binding in a way
// their edge proxy can't reach, producing a 502 "Application failed to respond" for every
// request despite the process being alive and healthy the whole time.
app.listen(PORT, '0.0.0.0', () => console.log(`Fenn backend listening on http://localhost:${PORT}`));
