# Fenn Information Security Policy

**Last reviewed:** 2026-07-21
**Owner:** Jordan Cutter (founder/sole operator)

## 1. Purpose and scope

This policy describes how Fenn identifies, mitigates, and monitors information
security risk to user data, with particular attention to financial data
accessed through Plaid. It covers the backend service (Node/Express,
hosted on Railway), the primary datastore (PostgreSQL, hosted on Neon), and
the iOS client application.

Fenn is currently operated by a single founder. Procedures below are scoped
to that reality rather than to a multi-team organization, and will be
revised as the team grows.

## 2. Data handled

- **Plaid access tokens** — credentials that grant read access to a user's
  linked bank account data. Most sensitive data in the system.
- **Transaction and account data** — pulled from Plaid, used to compute
  budgeting/spending figures for the user who owns it.
- **Account credentials** — email + password (or Apple Sign-In identity),
  used for authentication.
- **Session tokens** — short-lived credentials proving an authenticated app
  session.

## 3. Controls currently in place

### Encryption
- Plaid access tokens are encrypted at rest using AES-256-GCM before being
  stored in the database. The encryption key is held only as a server-side
  environment variable on Railway and is never committed to source control
  or stored in the database itself.
- All connections to the database use TLS (`sslmode=require` or stricter).
- All client-server traffic is HTTPS-only (enforced at Railway's edge).

### Authentication and access
- Passwords are hashed with bcrypt; plaintext passwords are never stored or
  logged.
- Sessions use a sliding-window expiration (90 days from last use); a
  session unused for that long is invalidated and requires re-authentication.
- Login and registration endpoints are rate-limited per IP address to
  mitigate brute-force credential attacks.
- Apple Sign-In is supported as an alternative to password-based auth.

### Application-level safeguards
- Database queries are parameterized throughout (no string-concatenated
  SQL), mitigating SQL injection.
- Crash/error reporting (Sentry) is configured to minimize collected user
  data: default PII collection (IP address) is disabled, and optional
  features that would capture UI content (Session Replay) are not enabled.

### Data minimization and retention
- Historical transaction backfill on signup is capped (90 days), rather
  than importing a user's full available history.
- Users can permanently delete their account and associated data from
  within the app at any time.

## 4. Vendors and subprocessors

| Vendor | Purpose | Data exposure |
|---|---|---|
| Plaid | Bank account linking and transaction data | Full financial data, per user consent |
| Railway | Backend application hosting | Encrypted data in transit/at rest; infra access controlled via Railway account |
| Neon | Managed PostgreSQL hosting | Encrypted data at rest (tokens); TLS in transit |
| Sentry | Crash/error reporting | Error stack traces and minimal device context; PII collection disabled |
| Apple | Sign in with Apple, app distribution | Apple ID identity token during sign-in only |

Vendor access is limited to what each service needs to function; no vendor
is given direct database or server access beyond its own managed platform.

## 5. Access control policy

### Who has access
- Production infrastructure (Railway, Neon, GitHub, and the Plaid Dashboard)
  is accessed solely by the founder; no other personnel currently have
  production access of any kind.
- Multi-factor authentication is enabled on all four of those accounts
  (Railway, Neon, GitHub, and the Plaid Dashboard), protecting the systems
  that hold production credentials and consumer financial data even though
  the underlying operation is a single person.
- Access follows the principle of least privilege: the backend application
  is the only entity holding a live database connection and Plaid
  credentials. These are never exposed to, or held by, the frontend client
  or any third party.
- Sensitive credentials — the database connection string, the Plaid client
  secret, and the token-encryption key — are stored exclusively as
  environment variables on Railway. They are not committed to source
  control and are not written to application logs.

### Non-human (service-to-service) authentication
- The backend's connection to its PostgreSQL database (hosted on Neon) is
  authenticated and encrypted using TLS (`sslmode=require` or stricter); the
  database will not accept an unencrypted connection.
- All traffic between the client app and the backend, and between the
  backend and Plaid's API, is TLS-encrypted (HTTPS only). Railway terminates
  TLS at its edge, and no unencrypted path to the application exists.
- The backend authenticates to Plaid's API using a client ID/secret pair
  transmitted only over this TLS-secured channel, never in plaintext.

### Review
This section follows the same review cadence as the rest of this policy
(Section 8) and will be revisited as soon as the team grows beyond a single
person, at which point role-based access control will be introduced for any
additional personnel.

## 6. Data retention and deletion policy

*As with the Terms of Service and Privacy Policy, this section is a reasonable
working policy, not a substitute for review by an actual lawyer regarding
compliance with a specific jurisdiction's data privacy laws (e.g., CCPA).*

### Retention
- Account, budget, and transaction data is retained for as long as a user's
  account remains active, since historical data is a core part of the
  product itself (spending history, streak calculation, recurring bill
  detection). There is no separate fixed-duration retention timer beyond
  that; retention is tied to account lifetime, not a calendar limit.
- Data collection is minimized at intake rather than only at deletion: on
  signup, historical transaction backfill from Plaid is capped at 90 days
  (`DATA_IMPORT_LOOKBACK_DAYS`), rather than importing a user's full
  available transaction history.

### Deletion
- Users can delete their account at any time from within the app
  (Settings), with no grace period and no manual/support intervention
  required.
- Deletion is immediate and complete: the backend first calls Plaid's
  `itemRemove` for each connected bank (revoking Fenn's access to that
  data at the source, not just locally), then deletes the user's database
  row. Every other table (transactions, sessions, budgets, manual
  expenses, recurring bills) references the user row with `ON DELETE
  CASCADE`, so deletion cascades automatically rather than relying on
  separate cleanup code that could drift out of sync over time.
- No soft-delete or retention-after-deletion period exists; there is
  nothing left to restore once an account is deleted.

### Review
This policy is reviewed on the same cadence as the rest of this document
(Section 8), and immediately if data privacy law applicable to Fenn's users
changes, or if the data collected changes.

## 7. Incident response

In the event of a suspected security incident (e.g., unauthorized access,
leaked credentials, suspicious database activity):

1. **Contain** — rotate the affected credential immediately (encryption key,
   database password, or API keys as applicable) and invalidate all active
   sessions if account compromise is suspected.
2. **Assess** — determine what data, and how many users, were potentially
   affected using database and Railway access logs.
3. **Notify** — affected users are notified directly. If Plaid-sourced data
   was affected, Plaid is notified per Plaid's own developer terms.
4. **Remediate** — fix the root cause before restoring normal operation.
5. **Review** — document what happened and update this policy or the
   underlying controls to prevent recurrence.

## 8. Review cadence

This policy is reviewed at least annually, and immediately after any
material change to the system's architecture, authentication model, or
vendor list.

## 9. Known limitations and planned improvements

In the interest of this policy being accurate rather than aspirational, two
known gaps are called out explicitly here rather than left implicit:

- **No consumer-facing multi-factor authentication yet.** Login is
  single-factor (password, or Sign in with Apple). A device-level Face
  ID/Touch ID lock is enabled by default on supported hardware, but that
  protects against someone accessing an already-logged-in device, not
  against remote credential-based account takeover. Account-level MFA
  (e.g., email or TOTP-based) is planned as the user base grows beyond the
  initial closed beta.
- **No formal vulnerability management program yet.** There is no scheduled
  vulnerability scanning, defined patch SLA, or active EOL-software
  tracking. Production infrastructure runs on managed platforms (Railway,
  Neon), which handle OS-level patching themselves as part of their own
  security programs. Enabling GitHub's built-in Dependabot dependency
  alerts on both repositories is a planned near-term step.

Both gaps are proportionate to Fenn's current stage (pre-launch, single
founder, no employees) rather than oversights, and will be revisited as
the product and team grow - see Section 8 for review cadence.

## 10. Contact

Security concerns or suspected vulnerabilities can be reported to
jordan.cutter@yahoo.com.
