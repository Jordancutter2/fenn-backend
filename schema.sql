-- One row per person with a Fenn account.
-- password_hash is null for accounts that only ever use Apple/Google Sign-In (not built yet).
-- tier is set to 'paid' by real in-app-purchase receipt validation once that's wired up
-- (needs a native IAP SDK) - nothing today sets it besides direct DB access for testing.
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  tos_accepted_at TIMESTAMPTZ,
  marketing_consent BOOLEAN NOT NULL DEFAULT false,
  tier TEXT NOT NULL DEFAULT 'free',
  apple_user_id TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tos_accepted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS marketing_consent BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'free';
-- Apple's stable per-user identifier (the JWT `sub` claim), null for email/password-only accounts.
ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_user_id TEXT UNIQUE;
-- TOTP secret, encrypted at rest the same way as Plaid access tokens (see tokenCrypto.js).
-- mfa_pending_secret holds a newly-generated secret during setup, before the user has
-- proven they actually scanned it by submitting a valid code - only promoted to mfa_secret
-- (and mfa_enabled set true) on confirmation, so a setup flow abandoned partway through
-- never silently turns on MFA with a secret the user never actually saved anywhere.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_pending_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT false;

-- One-time-use recovery codes for when someone loses their authenticator device. Hashed
-- with bcrypt like passwords, never stored or logged in plaintext - shown to the user
-- exactly once, at the moment MFA setup is confirmed.
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Postgres doesn't auto-index a foreign key column the way it does PRIMARY KEY/UNIQUE
-- ones - auth.js queries this table by user_id directly (checking/consuming backup codes,
-- clearing them on MFA disable/regenerate), which was a full table scan without this.
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);

-- Emailed 6-digit codes for "forgot password" - same hashed-at-rest, single-use shape as
-- mfa_backup_codes above, plus expires_at since unlike a backup code (valid until spent),
-- a reset code that's never used should stop being usable after a short window rather
-- than sitting valid forever. Old rows for a user aren't deleted when a new one's
-- requested - requestPasswordReset (auth.js) just treats only the newest as current,
-- so a second "resend code" tap can't strand someone on an email with a code that no
-- longer matches what the server considers active.
CREATE TABLE IF NOT EXISTS password_reset_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Queried by user_id every time a reset code is requested or checked.
CREATE INDEX IF NOT EXISTS idx_password_reset_codes_user ON password_reset_codes(user_id);
-- Superseded by a per-transaction override (transactions.user_excluded, tri-state) - a
-- single global toggle plus a separate per-bill flag couldn't actually let someone include
-- one specific transaction (a bill that's secretly a transfer, a refund, etc.), which was
-- the whole point. Dropped instead of left dead since nothing reads it anymore.
ALTER TABLE users DROP COLUMN IF EXISTS include_recurring_bills;

-- Opaque bearer tokens. Deleted on logout. Originally left with no expiry at all - the
-- spec figured the biometric app lock already covered that ground - but that's only one
-- control (someone who never enabled Face ID lock, or a token that leaks through some
-- other channel like a log, isn't covered by it). last_used_at below adds a sliding
-- expiration on top of, not instead of, the biometric lock.
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Sliding window: bumped (throttled to at most once/day per session, see requireAuth) on
-- every authenticated request, so daily use never expires a session - only one that's
-- genuinely been abandoned or leaked eventually stops working.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ NOT NULL DEFAULT now();
-- Defaults true so every existing session, and every login for an account without MFA
-- enabled, is unaffected. Only set false for the brief window between a correct password
-- (or Apple Sign-In) and a correct MFA code, for an account with MFA turned on - requireAuth
-- rejects a session in this state for every route except the one that verifies the code.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mfa_verified BOOLEAN NOT NULL DEFAULT true;
-- token's own UNIQUE constraint already indexes the requireAuth lookup path (every
-- authenticated request). This is for the separate by-user queries - invalidating every
-- other session on a password change, and clearing all of a user's sessions on delete.
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- One row per bank connection (a Plaid "Item"). A user can have up to 5 per the spec.
CREATE TABLE IF NOT EXISTS plaid_items (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plaid_item_id TEXT UNIQUE NOT NULL,
  access_token TEXT NOT NULL,
  institution_name TEXT,
  cursor TEXT,
  needs_reconnect BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS needs_reconnect BOOLEAN NOT NULL DEFAULT false;
-- Set from the NEW_ACCOUNTS_AVAILABLE webhook - distinct from needs_reconnect (a broken
-- login) since this means the connection is fine, but Plaid has spotted an account at that
-- same institution the user hasn't shared with us yet.
ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS new_accounts_available BOOLEAN NOT NULL DEFAULT false;
-- Lets the webhook handler skip a redundant /transactions/sync call when Plaid fires
-- several webhook codes for the same underlying update in quick succession (observed:
-- INITIAL_UPDATE, SYNC_UPDATES_AVAILABLE, and HISTORICAL_UPDATE all within a few seconds
-- of one bank linking).
ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMPTZ;
-- Plaid's own institution identifier (e.g. 'ins_109508') - distinct from institution_name,
-- which is just a display string. Used to detect a user re-linking a bank they already
-- have connected, per Plaid's own duplicate-Item prevention guidance.
ALTER TABLE plaid_items ADD COLUMN IF NOT EXISTS institution_id TEXT;
-- Queried by user_id directly on essentially every app load (getPlaidItems), plus
-- sync_transactions and account deletion - same missing-FK-index gap as the other tables
-- indexed below.
CREATE INDEX IF NOT EXISTS idx_plaid_items_user ON plaid_items(user_id);
-- Backstops /api/exchange_public_token's own duplicate-bank check, which only ran as a
-- SELECT-then-later-INSERT with a real Plaid network round trip in between - not atomic,
-- so two overlapping requests (a client timeout-then-retry, an impatient double-tap) could
-- both pass the check and insert two rows for the same real bank, which would then get
-- synced going forward and double-count every one of that bank's transactions in spend
-- totals. A partial index (not a plain UNIQUE column) because institution_id can be null,
-- and null values must stay unlimited - there's nothing to dedupe against without knowing
-- which institution a connection is for.
CREATE UNIQUE INDEX IF NOT EXISTS idx_plaid_items_user_institution ON plaid_items(user_id, institution_id) WHERE institution_id IS NOT NULL;

-- Cached copy of transactions pulled from Plaid via /transactions/sync.
CREATE TABLE IF NOT EXISTS transactions (
  id SERIAL PRIMARY KEY,
  plaid_item_id INTEGER NOT NULL REFERENCES plaid_items(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plaid_transaction_id TEXT UNIQUE NOT NULL,
  account_id TEXT NOT NULL,
  amount NUMERIC(12, 2) NOT NULL,
  iso_currency_code TEXT,
  date DATE NOT NULL,
  name TEXT,
  merchant_name TEXT,
  pending BOOLEAN NOT NULL DEFAULT false,
  pfc_primary TEXT,
  pfc_detailed TEXT,
  user_excluded BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Columns added after the transactions table already existed in some environments.
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS pfc_primary TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS pfc_detailed TEXT;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS user_excluded BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS is_recurring_bill BOOLEAN NOT NULL DEFAULT false;

-- user_excluded is now a tri-state override, not a plain "manually excluded" flag: NULL
-- means no override (defer to the automatic category rules - transfers, credit card
-- payments, refunds, and recurring bills are excluded by default), true forces a
-- transaction to never count, and false forces it to always count - overriding any
-- auto-exclusion category. That last case (force-include something auto-excluded) is new;
-- previously a recurring bill, transfer, or refund could never be individually turned back
-- on. Existing false rows only ever meant "not manually excluded" under the old
-- single-direction toggle, so they become NULL (defer to auto rules, the same real
-- behavior); existing true rows keep their meaning unchanged.
ALTER TABLE transactions ALTER COLUMN user_excluded DROP DEFAULT;
ALTER TABLE transactions ALTER COLUMN user_excluded DROP NOT NULL;
UPDATE transactions SET user_excluded = NULL WHERE user_excluded = false;

CREATE INDEX IF NOT EXISTS idx_transactions_user_date ON transactions(user_id, date);

-- Recurring bills, detected via Plaid's /transactions/recurring/get (outflow streams only -
-- recurring income isn't a "bill"). Excluded from daily spend per the spec, shown in their
-- own view instead. Refreshed by calling /api/sync_recurring, not on every regular sync -
-- it's a separate, heavier Plaid call that doesn't need to run as often as transaction sync.
CREATE TABLE IF NOT EXISTS recurring_bills (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  plaid_item_id INTEGER NOT NULL REFERENCES plaid_items(id) ON DELETE CASCADE,
  stream_id TEXT UNIQUE NOT NULL,
  merchant_name TEXT,
  description TEXT,
  average_amount NUMERIC(12, 2),
  last_amount NUMERIC(12, 2),
  frequency TEXT,
  last_date DATE,
  is_active BOOLEAN NOT NULL DEFAULT true,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Superseded by transactions.user_excluded's tri-state override - see the comment there.
ALTER TABLE recurring_bills DROP COLUMN IF EXISTS included_in_spend;

-- Plaid's recurring-stream object carries its own personal_finance_category directly (the
-- same shape as a transaction's), so "is this bill secretly a transfer/credit-card
-- payment" can be checked without joining to a linked transaction. That join was the only
-- way to do this before, and it silently broke the moment a bill's linked transactions
-- were absent for any reason (deleted, not yet synced, pre-connection cleanup) - with
-- nothing to join against, the filter would just find nothing to exclude, quietly showing
-- bills that should have been hidden as transfers.
ALTER TABLE recurring_bills ADD COLUMN IF NOT EXISTS pfc_primary TEXT;
ALTER TABLE recurring_bills ADD COLUMN IF NOT EXISTS pfc_detailed TEXT;

-- Bill-level convenience on top of (not a replacement for) transactions.user_excluded -
-- toggling this from the Bills tab applies the same include/exclude choice to every
-- transaction currently linked to the bill in one action, and to future ones as they're
-- linked during /api/sync_recurring, rather than requiring each occurrence to be found
-- and toggled individually from Today/History. A per-transaction toggle done afterward
-- still wins for that one occurrence - this only sets the baseline, not a hard override.
ALTER TABLE recurring_bills ADD COLUMN IF NOT EXISTS user_included BOOLEAN NOT NULL DEFAULT false;

-- Links a transaction back to the recurring-bill stream it belongs to (set alongside
-- is_recurring_bill during /api/sync_recurring), so per-bill inclusion choices can be
-- applied when computing spend.
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS recurring_bill_id INTEGER REFERENCES recurring_bills(id);
-- Queried by user_id directly every time the Bills tab loads.
CREATE INDEX IF NOT EXISTS idx_recurring_bills_user ON recurring_bills(user_id);
-- PATCH /api/bills/:id/include updates every transaction linked to a bill by this column -
-- unlike every other foreign key on this table, it had no index of its own to serve that.
CREATE INDEX IF NOT EXISTS idx_transactions_recurring_bill ON transactions(recurring_bill_id);

-- Non-null only while there's a real, unacknowledged price increase to show on the Bills
-- tab - holds what last_amount was immediately before the increase that's now pending, so
-- the alert can say "was $X, now $Y" without a separate history table. Set by
-- /api/sync_recurring when it detects last_amount rose meaningfully; cleared back to null
-- by PATCH /api/bills/:id/acknowledge_increase once the user dismisses it. A second
-- increase before the first is acknowledged just overwrites this with the latest jump
-- (still just "was X, now Y", not a running history) - simpler, and matches what the user
-- actually asked for.
ALTER TABLE recurring_bills ADD COLUMN IF NOT EXISTS previous_amount NUMERIC(12, 2);

-- One budget per user. monthly_amount is divided by days-in-month client-side
-- (the client knows the device's local timezone/date; the server intentionally doesn't).
CREATE TABLE IF NOT EXISTS budgets (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  monthly_amount NUMERIC(12, 2) NOT NULL,
  week_start_day SMALLINT NOT NULL DEFAULT 0, -- 0 = Sunday, 1 = Monday
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One goal per user, same one-row shape as budgets. Progress isn't stored here - it's
-- computed client-side from daily spend history since started_at (cumulative
-- budget-minus-spent), the same way streaks are computed from history rather than
-- persisted. started_at resets to now() on a fresh POST (starting over); PATCH (editing
-- name/target/date in place) deliberately leaves it untouched so progress isn't lost.
CREATE TABLE IF NOT EXISTS savings_goals (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target_amount NUMERIC(12, 2) NOT NULL,
  target_date DATE, -- nullable: no deadline means progress is shown against a projected pace instead
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Manually-entered expenses (free tier, or any user logging something not from a linked bank).
-- Unlike Plaid transactions these can be freely edited/deleted since they're not tied to a bank record.
--
-- local_date is the calendar date this counts against for budget purposes, always supplied by the
-- client (it knows the device's local timezone; the server deliberately doesn't guess). occurred_at
-- is a real timestamp kept for display/ordering, but is NOT used for "which day does this belong to" -
-- comparing a UTC instant's date to a client's local date silently misattributes expenses to the
-- wrong day for roughly half of every 24 hours in most US timezones.
CREATE TABLE IF NOT EXISTS manual_expenses (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount NUMERIC(12, 2) NOT NULL,
  note TEXT,
  local_date DATE NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE manual_expenses ADD COLUMN IF NOT EXISTS local_date DATE;

CREATE INDEX IF NOT EXISTS idx_manual_expenses_user_local_date ON manual_expenses(user_id, local_date);

-- Every webhook Plaid ever sends us, regardless of type - an audit trail more than an
-- operational table today, since nothing acts on specific webhook codes yet beyond logging
-- them. item_id is Plaid's own identifier, not our internal plaid_items.id - deliberately
-- not a foreign key, since a webhook can arrive for an item we've already deleted our side.
CREATE TABLE IF NOT EXISTS webhook_log (
  id SERIAL PRIMARY KEY,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  webhook_type TEXT,
  webhook_code TEXT,
  item_id TEXT,
  payload JSONB
);

-- Result of acting on a transaction-update webhook (see /plaid-webhook): 'OK', an error
-- message, or 'NO_MATCHING_ITEM' if the webhook's item_id didn't match anything in
-- plaid_items. Not filled in for webhook types/codes that don't trigger a sync at all.
ALTER TABLE webhook_log ADD COLUMN IF NOT EXISTS sync_error TEXT;
-- Not a foreign key (see this table's own comment above - a webhook can arrive for an item
-- already deleted our side), but still queried by item_id on account/bank deletion cleanup,
-- and this table has no retention policy - it only grows, unlike the others indexed here.
CREATE INDEX IF NOT EXISTS idx_webhook_log_item ON webhook_log(item_id);
