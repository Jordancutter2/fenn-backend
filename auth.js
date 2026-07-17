const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const pool = require('./db');

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

async function createSession(userId) {
  const token = generateToken();
  await pool.query('INSERT INTO sessions (user_id, token) VALUES ($1, $2)', [userId, token]);
  return token;
}

async function register({ email, password, marketingConsent }) {
  const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    const err = new Error('An account with that email already exists.');
    err.status = 409;
    throw err;
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const result = await pool.query(
    `INSERT INTO users (email, password_hash, tos_accepted_at, marketing_consent)
     VALUES ($1, $2, now(), $3) RETURNING id, email, tier`,
    [email, passwordHash, !!marketingConsent]
  );
  const user = result.rows[0];
  const token = await createSession(user.id);
  return { token, user };
}

async function login({ email, password }) {
  const result = await pool.query('SELECT id, email, password_hash, tier FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  // Same error for "no such user" and "wrong password" - don't reveal which one it was.
  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) {
    const err = new Error('Invalid email or password.');
    err.status = 401;
    throw err;
  }

  const token = await createSession(user.id);
  return { token, user: { id: user.id, email: user.email, tier: user.tier } };
}

async function logout(token) {
  await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
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

  let result = await pool.query('SELECT id, email, tier FROM users WHERE apple_user_id = $1', [appleUserId]);
  if (result.rows.length > 0) {
    const user = result.rows[0];
    const token = await createSession(user.id);
    return { token, user };
  }

  // First time this Apple account has signed in here - link it to an existing
  // email/password account with the same email if there is one, rather than
  // silently creating a duplicate account for the same person.
  if (email) {
    result = await pool.query('SELECT id, email, tier FROM users WHERE email = $1', [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      await pool.query('UPDATE users SET apple_user_id = $1 WHERE id = $2', [appleUserId, user.id]);
      const token = await createSession(user.id);
      return { token, user };
    }
  }

  if (!email) {
    const err = new Error('Apple did not provide an email for this sign-in.');
    err.status = 400;
    throw err;
  }
  if (!tosAccepted) {
    const err = new Error('You must accept the Terms of Service and Privacy Policy.');
    err.status = 400;
    throw err;
  }

  const insertResult = await pool.query(
    `INSERT INTO users (email, apple_user_id, tos_accepted_at, marketing_consent)
     VALUES ($1, $2, now(), $3) RETURNING id, email, tier`,
    [email, appleUserId, !!marketingConsent]
  );
  const user = insertResult.rows[0];
  const token = await createSession(user.id);
  return { token, user };
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
  if (!token) return res.status(401).json({ error: 'Not authenticated' });

  const result = await pool.query(
    `SELECT user_id FROM sessions
     WHERE token = $1 AND last_used_at > now() - interval '${SESSION_LIFETIME_DAYS} days'`,
    [token]
  );
  if (result.rows.length === 0) return res.status(401).json({ error: 'Not authenticated' });

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

module.exports = { register, login, loginWithApple, logout, requireAuth };
