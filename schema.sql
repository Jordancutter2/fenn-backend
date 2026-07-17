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

-- Links a transaction back to the recurring-bill stream it belongs to (set alongside
-- is_recurring_bill during /api/sync_recurring), so per-bill inclusion choices can be
-- applied when computing spend.
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS recurring_bill_id INTEGER REFERENCES recurring_bills(id);

-- One budget per user. monthly_amount is divided by days-in-month client-side
-- (the client knows the device's local timezone/date; the server intentionally doesn't).
CREATE TABLE IF NOT EXISTS budgets (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  monthly_amount NUMERIC(12, 2) NOT NULL,
  week_start_day SMALLINT NOT NULL DEFAULT 0, -- 0 = Sunday, 1 = Monday
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
