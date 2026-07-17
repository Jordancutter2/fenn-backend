require('dotenv').config({ quiet: true });
const crypto = require('crypto');

// AES-256-GCM: authenticated encryption, so a tampered ciphertext fails to decrypt rather
// than silently producing garbage. The key never lives in the database alongside the data
// it protects - only in this process's environment (ENCRYPTION_KEY), same as the Plaid
// credentials themselves.
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function getKey() {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex) {
    throw new Error('ENCRYPTION_KEY is not set - required to encrypt/decrypt Plaid access tokens.');
  }
  const key = Buffer.from(hex, 'hex');
  if (key.length !== 32) {
    throw new Error('ENCRYPTION_KEY must be 32 bytes (64 hex characters).');
  }
  return key;
}

// A fresh random IV per call (never reused with the same key) plus the auth tag GCM
// produces are prepended to the ciphertext and stored together as one opaque base64
// string, so callers don't need to separately track/store either alongside it.
function encryptToken(plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64');
}

function decryptToken(ciphertext) {
  const data = Buffer.from(ciphertext, 'base64');
  const iv = data.subarray(0, IV_LENGTH);
  const authTag = data.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const encrypted = data.subarray(IV_LENGTH + AUTH_TAG_LENGTH);
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// Plaid access tokens always start with this prefix (access-sandbox-/development-/
// production-). Used only by the one-time migration script to tell an already-migrated
// (encrypted, base64-opaque) row apart from one that still needs encrypting - not used
// anywhere in normal request handling, which always knows which direction it needs.
function looksLikePlaintextPlaidToken(value) {
  return typeof value === 'string' && value.startsWith('access-');
}

module.exports = { encryptToken, decryptToken, looksLikePlaintextPlaidToken };
