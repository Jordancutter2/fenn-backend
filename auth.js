const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { generateSecret, verify: verifyTotp, generateURI } = require('otplib');
const qrcode = require('qrcode');
const pool = require('./db');
const { encryptToken, decryptToken } = require('./tokenCrypto');
const { sendPasswordResetEmail } = require('./emailClient');

const MFA_ISSUER = 'Fenn';
const BACKUP_CODE_COUNT = 8;
const RESET_CODE_EXPIRY_MS = 15 * 60 * 1000;
// Generous enough for a real person fat-fingering their 6-digit code a couple of times,
// tight enough to make a brute-force guess against its 900k-possibility keyspace
// impractical within the code's lifetime regardless of how many source IPs it's spread
// across (see the schema comment on password_reset_codes.attempts).
const MAX_RESET_CODE_ATTEMPTS = 5;

const MIN_PASSWORD_LENGTH = 8;

// A hash with no real account or code behind it - compared against on every "no such
// user"/"no such reset code" path below (login, resetPassword), so a nonexistent-account
// request takes roughly the same wall-clock time as a real one. bcrypt.compare is the
// dominant cost on these paths; JS's short-circuit && previously skipped it entirely when
// no user/code was found, and that timing gap leaked account/code existence even though
// both paths return the identical error message.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync('fenn-timing-safety-dummy', 10);

// Shared by register() and changePassword() - the only two places a password is ever set -
// so a weak password can't slip in through either path. Length only, not composition
// rules (uppercase/symbol requirements): NIST's current guidance is that length matters
// far more than forced complexity, which mostly just pushes people toward predictable
// substitutions ("Password1!") rather than actually stronger passwords.
function assertValidPassword(password) {
  if (!password || password.length < MIN_PASSWORD_LENGTH) {
    const err = new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    err.status = 400;
    throw err;
  }
}

const APPLE_ISSUER = 'https://appleid.apple.com';
const APPLE_AUDIENCE = process.env.APPLE_BUNDLE_ID || 'com.fennapp.fenn';
const appleJwks = jwksClient({ jwksUri: 'https://appleid.apple.com/auth/keys', cache: true, cacheMaxAge: 24 * 60 * 60 * 1000 });

function getAppleSigningKey(header, callback) {
  appleJwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

// Verifies the identityToken Apple's native sign-in flow hands back to the app - this is
// what actually proves the request came from Apple and identifies who signed in, rather
// than trusting whatever the client claims. Never skip this: without it, anyone could
// send a fabricated "I am user X" request and take over that account.
function verifyAppleIdentityToken(identityToken) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      identityToken,
      getAppleSigningKey,
      { algorithms: ['RS256'], issuer: APPLE_ISSUER, audience: APPLE_AUDIENCE },
      (err, payload) => (err ? reject(err) : resolve(payload))
    );
  });
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// mfaVerified defaults true (an ordinary, immediately-usable session) - only ever passed
// false for an account with MFA enabled, right after a correct password/Apple Sign-In but
// before a correct MFA code, so requireAuth can reject it everywhere except the one route
// that verifies the code.
async function createSession(userId, mfaVerified = true) {
  const token = generateToken();
  await pool.query('INSERT INTO sessions (user_id, token, mfa_verified) VALUES ($1, $2, $3)', [
    userId,
    token,
    mfaVerified,
  ]);
  return token;
}

async function register({ email, password, marketingConsent }) {
  assertValidPassword(password);
  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    const err = new Error('An account with that email already exists.');
    err.status = 409;
    throw err;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  let result;
  try {
    result = await pool.query(
      `INSERT INTO users (email, password_hash, tos_accepted_at, marketing_consent)
       VALUES ($1, $2, now(), $3) RETURNING id, email, tier, created_at`,
      [email, passwordHash, !!marketingConsent]
    );
  } catch (insertErr) {
    // The SELECT above only catches the common case - bcrypt.hash takes real time (10
    // rounds), long enough for two overlapping register requests (a double-tap, a client
    // timeout-then-retry) to both pass that check before either INSERT commits. Without
    // this, the loser hit the generic "Failed to register" 500 instead of the same clean
    // "already exists" message the pre-check gives everyone else.
    if (insertErr.code === '23505') {
      const err = new Error('An account with that email already exists.');
      err.status = 409;
      throw err;
    }
    throw insertErr;
  }
  const user = result.rows[0];
  const token = await createSession(user.id);
  return { token, user };
}

async function login({ email, password }) {
  const result = await pool.query(
    'SELECT id, email, password_hash, tier, mfa_enabled, created_at FROM users WHERE email = $1',
    [email]
  );
  const user = result.rows[0];

  // Always runs bcrypt.compare, even when no user (or no password_hash - an Apple-only
  // account) exists, against DUMMY_PASSWORD_HASH in that case - see its own comment above
  // for why. Same error for "no such user" and "wrong password" either way - don't reveal
  // which one it was.
  const passwordMatches = await bcrypt.compare(password, user?.password_hash || DUMMY_PASSWORD_HASH);
  if (!user || !user.password_hash || !passwordMatches) {
    const err = new Error('Invalid email or password.');
    err.status = 401;
    throw err;
  }

  const token = await createSession(user.id, !user.mfa_enabled);
  return {
    token,
    // created_at matters here, not just cosmetically - userCreatedAt (RingScreen.js,
    // HistoryScreen.js) bounds how far back streak history gets scanned, so that no day
    // from before the account existed reads as a fake "$0 spent, under budget" day. This
    // response used to omit it entirely, silently disabling that bound for anyone who
    // just went through a genuine login() call (as opposed to resuming a session via
    // getMe(), which already included it) - surfaced as an absurdly long streak (e.g.
    // 247 weeks) for an account with little real spending, the exact same underlying
    // failure mode already documented and fixed once for daily streaks specifically, just
    // via a different root cause this time.
    user: { id: user.id, email: user.email, tier: user.tier, created_at: user.created_at },
    mfaRequired: user.mfa_enabled,
  };
}

async function logout(token) {
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
}

// Only for accounts that already have a password set - an Apple-only account has no
// password_hash at all, and !user.password_hash correctly rejects that case the same way
// login() does rather than needing a separate check.
async function changePassword(userId, currentPassword, newPassword, currentSessionToken) {
  assertValidPassword(newPassword);
  const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
  const user = result.rows[0];

  if (!user || !user.password_hash || !(await bcrypt.compare(currentPassword, user.password_hash))) {
    // A precise, machine-checkable signal (not just the message string) - the frontend
    // uses this to tell "the server genuinely checked and the password was wrong" apart
    // from a network failure/timeout, where it's ambiguous whether this request actually
    // landed before the connection dropped (the change could have already gone through).
    const err = new Error('Current password is incorrect.');
    err.status = 401;
    err.code = 'WRONG_CURRENT_PASSWORD';
    throw err;
  }

  const newHash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, userId]);

  // A stolen session token should stop working the moment the legitimate owner changes
  // their password - without this, whoever had it keeps full access indefinitely,
  // regardless of the password change. Keeps the session making this very request alive
  // (excluded by token) so changing your own password doesn't immediately log out the
  // device you're sitting at right now.
  await pool.query('DELETE FROM sessions WHERE user_id = $1 AND token != $2', [userId, currentSessionToken]);
}

function generateResetCode() {
  // crypto.randomInt's range is inclusive-start/exclusive-end, so this is always exactly
  // 6 digits - no zero-padding ever needed, unlike Math.random-based approaches.
  return String(crypto.randomInt(100000, 1000000));
}

// Always resolves the same way regardless of whether the email matches an account - same
// "don't reveal which one it was" reasoning as login()'s identical error for "no such
// user" and "wrong password." A different response here (or skipping the email step for
// an unknown address) would let someone enumerate which emails have Fenn accounts just by
// watching how this endpoint responds. Also a silent no-op for an Apple-only account (no
// password_hash) - there's no password to reset, and emailing a code that could never
// actually be used anywhere would just be confusing, not helpful.
async function requestPasswordReset(email) {
  const result = await pool.query('SELECT id, password_hash FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user || !user.password_hash) return;

  const code = generateResetCode();
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + RESET_CODE_EXPIRY_MS);
  await pool.query('INSERT INTO password_reset_codes (user_id, code_hash, expires_at) VALUES ($1, $2, $3)', [
    user.id,
    codeHash,
    expiresAt,
  ]);

  try {
    await sendPasswordResetEmail(email, code);
  } catch (err) {
    // Swallowed, not thrown - this route always responds the same way regardless of
    // whether the account exists, so a real send failure (misconfigured API key, Resend
    // outage) can't become a second way to distinguish "no such account" from "something's
    // broken." Still logged so a genuine outage is visible on the server side.
    console.error('Failed to send password reset email:', err);
  }
}

// The email + code pair together identify which reset request this is. Only the most
// recently requested, not-yet-used, not-yet-expired code for that user is ever valid - a
// stale code from an earlier "resend" tap can't be replayed after a newer one's been sent,
// since ORDER BY created_at DESC LIMIT 1 always checks against the latest one only.
async function resetPassword({ email, code, newPassword }) {
  assertValidPassword(newPassword);

  const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  const user = userResult.rows[0];

  // Same generic error regardless of which part is wrong (no such user, no pending code,
  // expired code, wrong code) - same "don't reveal which one it was" reasoning as login().
  const invalidCodeError = () => {
    const err = new Error('Invalid or expired reset code.');
    err.status = 400;
    throw err;
  };

  // Always queries for a pending code and always runs bcrypt.compare, even when no user
  // exists (user?.id ?? -1 - a placeholder that matches zero real rows) - same timing-
  // safety reasoning as login() above (see DUMMY_PASSWORD_HASH's comment). This used to
  // short-circuit straight to invalidCodeError() on !user, skipping both the second query
  // and the bcrypt.compare entirely, which leaked account existence through response
  // latency despite the identical error message.
  const codeResult = await pool.query(
    `SELECT id, code_hash, attempts FROM password_reset_codes
     WHERE user_id = $1 AND used_at IS NULL AND expires_at > now()
     ORDER BY created_at DESC LIMIT 1`,
    [user?.id ?? -1]
  );
  const resetRow = codeResult.rows[0];
  const codeMatches = await bcrypt.compare(code, resetRow?.code_hash || DUMMY_PASSWORD_HASH);
  // Once a code is exhausted it's dead even if this particular guess happened to be right -
  // an IP-keyed rate limit alone doesn't stop a slow, patient guess spread across many
  // source IPs against this one code's fixed 900k-possibility keyspace (see the schema
  // comment on `attempts`), so the cap has to hold regardless of which guess lands.
  const exhausted = resetRow && resetRow.attempts >= MAX_RESET_CODE_ATTEMPTS;
  if (!user || !resetRow || !codeMatches || exhausted) {
    if (resetRow && !exhausted) {
      await pool.query('UPDATE password_reset_codes SET attempts = attempts + 1 WHERE id = $1', [resetRow.id]);
    }
    invalidCodeError();
  }

  const newHash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
  await pool.query('UPDATE password_reset_codes SET used_at = now() WHERE id = $1', [resetRow.id]);

  // Unlike changePassword above (which keeps the current device's session alive, since
  // that's the session making the request), there's no "current session" to preserve here
  // at all - whoever is resetting isn't authenticated yet, and a forgotten-password reset
  // is exactly the moment an account may have been compromised, so every existing session
  // ending here is the safer default, not an exception to carve out.
  await pool.query('DELETE FROM sessions WHERE user_id = $1', [user.id]);
}

// Apple only sends the user's email on the very first authorization ever for this app -
// every sign-in after that omits it, since Apple already told us once. The client passes
// along whatever it has from that first time; the server is the source of truth once a
// user row exists (matched by Apple's stable `sub` identifier, not email).
async function loginWithApple({ identityToken, email: emailFromClient, marketingConsent, tosAccepted }) {
  let payload;
  try {
    payload = await verifyAppleIdentityToken(identityToken);
  } catch (e) {
    const err = new Error('Could not verify Apple sign-in.');
    err.status = 401;
    throw err;
  }

  const appleUserId = payload.sub;
  const email = payload.email || emailFromClient || null;

  // created_at included in every branch below - see login()'s own comment for why it
  // has to be there, not just cosmetic.
  let result = await pool.query('SELECT id, email, tier, mfa_enabled, created_at FROM users WHERE apple_user_id = $1', [
    appleUserId,
  ]);
  if (result.rows.length > 0) {
    const user = result.rows[0];
    const token = await createSession(user.id, !user.mfa_enabled);
    return {
      token,
      user: { id: user.id, email: user.email, tier: user.tier, created_at: user.created_at },
      mfaRequired: user.mfa_enabled,
    };
  }

  // First time this Apple account has signed in here - link it to an existing
  // email/password account with the same email if there is one, rather than
  // silently creating a duplicate account for the same person.
  if (email) {
    result = await pool.query('SELECT id, email, tier, mfa_enabled, created_at FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      await pool.query('UPDATE users SET apple_user_id = $1 WHERE id = $2', [appleUserId, user.id]);
      const token = await createSession(user.id, !user.mfa_enabled);
      return {
        token,
        user: { id: user.id, email: user.email, tier: user.tier, created_at: user.created_at },
        mfaRequired: user.mfa_enabled,
      };
    }
  }

  if (!email) {
    // Apple only ever discloses the real email on the very first authorization for this
    // bundle ID, ever - independent of Fenn's own DB state. A user who deletes their Fenn
    // account and later tries to sign back in with the same Apple ID has already "used"
    // that one-time disclosure, so this isn't recoverable by simply retrying - the message
    // has to point at the actual fix (Apple's own re-authorization reset) or an alternate
    // path in, or this is a permanent dead end for that person.
    const err = new Error(
      "Apple didn't share an email for this sign-in - this can happen if you've signed into Fenn with this Apple ID before. Try email/password instead, or on your device go to Settings > [your name] > Sign in with Apple > Fenn and remove it, then try Apple sign-in again."
    );
    err.status = 400;
    throw err;
  }
  if (!tosAccepted) {
    const err = new Error('You must accept the Terms of Service and Privacy Policy.');
    err.status = 400;
    throw err;
  }

  let insertResult;
  try {
    insertResult = await pool.query(
      `INSERT INTO users (email, apple_user_id, tos_accepted_at, marketing_consent)
       VALUES ($1, $2, now(), $3) RETURNING id, email, tier, created_at`,
      [email, appleUserId, !!marketingConsent]
    );
  } catch (insertErr) {
    // Same overlapping-request race as register() above, just harder to trigger here
    // (Apple's own native sheet largely serializes the flow) - both apple_user_id and
    // email are UNIQUE, so a genuine double-submit lands here rather than creating two
    // rows. The account this collided with was just created by the other request a
    // moment ago, so asking for a retry (which will now hit the apple_user_id lookup at
    // the top of this function and log them in) is correct, not just a generic failure.
    if (insertErr.code === '23505') {
      const err = new Error('Something else was signing you in - try again.');
      err.status = 409;
      throw err;
    }
    throw insertErr;
  }
  const user = insertResult.rows[0];
  const token = await createSession(user.id);
  return { token, user };
}

// otplib throws (rather than returning { valid: false }) for a malformed code - notably
// anything that isn't exactly 6 digits, which includes every backup code by design. Without
// this wrapper, a backup-code attempt would crash instead of falling through to actually
// check backup codes.
async function safeVerifyTotp(secret, code) {
  try {
    return await verifyTotp({ secret, token: code });
  } catch (err) {
    return { valid: false };
  }
}

function generateBackupCode() {
  // 10 hex chars, uppercased for readability (e.g. "3F9A2B7C1D") - not meant to be typed
  // often, just once in the rare case an authenticator device is lost.
  return crypto.randomBytes(5).toString('hex').toUpperCase();
}

// Step 1 of enabling MFA: generates a secret and returns it as a QR code (plus the raw key
// for manual entry) for the user to add to their authenticator app. Stored as
// mfa_pending_secret, not mfa_secret - MFA isn't actually turned on until confirmMfa proves
// the user really did save it somewhere, so an abandoned setup can't silently lock anyone
// out or leave a secret enabled that was never actually recorded by an authenticator app.
async function setupMfa(userId, email) {
  const secret = generateSecret();
  await pool.query('UPDATE users SET mfa_pending_secret = $1 WHERE id = $2', [encryptToken(secret), userId]);
  const uri = generateURI({ issuer: MFA_ISSUER, label: email, secret });
  const qrDataUrl = await qrcode.toDataURL(uri);
  return { qrDataUrl, manualEntryKey: secret };
}

// Step 2: user submits a code from their authenticator app, proving setup actually worked.
// Promotes the pending secret to the real one, turns MFA on, and issues backup codes -
// shown to the caller this one time only, never retrievable again (only their bcrypt hash
// is kept). Re-running setup+confirm (e.g. switching authenticator apps) replaces both the
// secret and all backup codes, invalidating the old ones.
async function confirmMfa(userId, code) {
  const result = await pool.query('SELECT mfa_pending_secret FROM users WHERE id = $1', [userId]);
  const encryptedSecret = result.rows[0]?.mfa_pending_secret;
  if (!encryptedSecret) {
    const err = new Error('No MFA setup in progress. Start setup again.');
    err.status = 400;
    throw err;
  }

  const secret = decryptToken(encryptedSecret);
  const { valid } = await safeVerifyTotp(secret, code);
  if (!valid) {
    const err = new Error('Incorrect code. Try again.');
    err.status = 400;
    throw err;
  }

  await pool.query(
    'UPDATE users SET mfa_secret = $1, mfa_pending_secret = NULL, mfa_enabled = true WHERE id = $2',
    [encryptedSecret, userId]
  );

  await pool.query('DELETE FROM mfa_backup_codes WHERE user_id = $1', [userId]);
  const backupCodes = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const backupCode = generateBackupCode();
    backupCodes.push(backupCode);
    const hash = await bcrypt.hash(backupCode, 10);
    await pool.query('INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)', [userId, hash]);
  }
  return { backupCodes };
}

// Requires the current password (not just being logged in) so a hijacked but not-yet-MFA'd
// session can't turn off the one thing standing between it and full account takeover.
async function disableMfa(userId, password) {
  const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
  const user = result.rows[0];
  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
    const err = new Error('Current password is incorrect.');
    err.status = 401;
    throw err;
  }

  await pool.query(
    'UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_pending_secret = NULL WHERE id = $1',
    [userId]
  );
  await pool.query('DELETE FROM mfa_backup_codes WHERE user_id = $1', [userId]);
}

// Called with the still mfa_verified=false session token a successful password/Apple
// Sign-In just issued, plus either a TOTP code or one of the user's backup codes. On
// success, flips that same session to verified rather than issuing a new one - the client
// already has the right token, it just couldn't use it for anything else yet.
async function verifyMfaLogin(token, code) {
  const result = await pool.query(
    `SELECT s.id AS session_id, s.mfa_verified, u.id AS user_id, u.email, u.tier, u.mfa_secret, u.created_at
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = $1`,
    [token]
  );
  const row = result.rows[0];
  if (!row) {
    const err = new Error('Session not found. Log in again.');
    err.status = 401;
    throw err;
  }

  // created_at included here too - see login()'s own comment for why it has to be, not
  // just cosmetic.
  const user = { id: row.user_id, email: row.email, tier: row.tier, created_at: row.created_at };
  if (row.mfa_verified) {
    // Already verified (e.g. a retried request) - idempotent success, not an error.
    return { user };
  }

  const secret = decryptToken(row.mfa_secret);
  const { valid } = await safeVerifyTotp(secret, code);
  if (valid) {
    await pool.query('UPDATE sessions SET mfa_verified = true WHERE id = $1', [row.session_id]);
    return { user };
  }

  // Not a valid TOTP code - fall back to checking unused backup codes.
  const backupCodes = await pool.query(
    'SELECT id, code_hash FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL',
    [row.user_id]
  );
  for (const backupCode of backupCodes.rows) {
    if (await bcrypt.compare(code, backupCode.code_hash)) {
      await pool.query('UPDATE mfa_backup_codes SET used_at = now() WHERE id = $1', [backupCode.id]);
      await pool.query('UPDATE sessions SET mfa_verified = true WHERE id = $1', [row.session_id]);
      return { user };
    }
  }

  const err = new Error('Incorrect code.');
  err.status = 401;
  throw err;
}

// Sliding expiration on top of (not instead of) the biometric app lock - see the comment
// on sessions.last_used_at in schema.sql for why this exists.
const SESSION_LIFETIME_DAYS = 90;
// Only bump last_used_at when it's at least this stale, not on literally every request -
// still gives a same-day-or-more-recent sliding window without a write on every request.
const SESSION_REFRESH_THRESHOLD_DAYS = 1;

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  // code: 'SESSION_INVALID' on these two specifically (not the mfaRequired one below,
  // which is a normal, expected mid-login state, not a dead session) - a precise,
  // machine-checkable signal the frontend uses to tell "this session token used to be
  // valid and no longer is" apart from every OTHER 401 in the app that happens to share
  // the same status code for an unrelated reason (a wrong current password on
  // /api/auth/change-password, a wrong code on /api/auth/mfa/verify-login, a wrong
  // password on /api/auth/login itself) - none of which should force a logout.
  if (!token) return res.status(401).json({ error: 'Not authenticated', code: 'SESSION_INVALID' });

  const result = await pool.query(
    `SELECT user_id, mfa_verified FROM sessions
     WHERE token = $1 AND last_used_at > now() - interval '${SESSION_LIFETIME_DAYS} days'`,
    [token]
  );
  if (result.rows.length === 0) return res.status(401).json({ error: 'Not authenticated', code: 'SESSION_INVALID' });

  // A session created right after a correct password/Apple Sign-In for an MFA-enabled
  // account, but before the correct code - can't be used for anything else until then.
  if (!result.rows[0].mfa_verified) {
    return res.status(401).json({ error: 'MFA verification required', mfaRequired: true });
  }

  req.userId = result.rows[0].user_id;

  // Fire-and-forget - bumping the sliding window isn't worth adding latency to every
  // authenticated request for, and a failure here isn't worth failing the request over.
  pool
    .query(
      `UPDATE sessions SET last_used_at = now()
       WHERE token = $1 AND last_used_at < now() - interval '${SESSION_REFRESH_THRESHOLD_DAYS} days'`,
      [token]
    )
    .catch((err) => console.error('Failed to refresh session last_used_at:', err));

  next();
}

module.exports = {
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
};
