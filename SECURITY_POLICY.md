# Fenn Information Security Policy

**Last reviewed:** 2026-08-02
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
- Changing a password invalidates every other active session for that
  account immediately (the session used to make the change itself is left
  alone, so the change doesn't log out the device it was made from) - this
  contains a stolen session token the moment the legitimate owner changes
  their password, rather than leaving it valid indefinitely.
- Login, registration, and MFA code verification endpoints are rate-limited
  per IP address to mitigate brute-force credential/code-guessing attacks.
- Apple Sign-In is supported as an alternative to password-based auth.
- Optional consumer-facing multi-factor authentication (TOTP, compatible
  with standard authenticator apps) is available; when enabled, a session
  from a correct password or Apple Sign-In is unusable for anything else
  until a second factor is also verified. One-time backup codes (hashed,
  single-use) are issued at setup for recovery if the authenticator device
  is lost. The TOTP secret is encrypted at rest the same way as Plaid
  access tokens.

### Application-level safeguards
- Database queries are parameterized throughout (no string-concatenated
  SQL), mitigating SQL injection.
- Every API endpoint that reads or modifies a specific record (an expense, a
  bill, a linked bank, a transaction) scopes its query to the authenticated
  user's own id, not just the record's id - an authenticated user cannot
  access or modify another user's data by guessing or iterating IDs.
- Inbound Plaid webhooks are cryptographically verified (the JWT Plaid signs
  into the `Plaid-Verification` header, per Plaid's own documented process)
  before any of their contents are trusted or acted on - without this, a
  webhook's `item_id` isn't secret, so anything reachable at the webhook URL
  could otherwise spoof Plaid and trigger a sync or forge connection-status
  flags for a targeted item.
- Standard HTTP security headers (baseline CSP, X-Content-Type-Options,
  HSTS, and others) are set on every response via `helmet`.
- Crash/error reporting (Sentry, on the iOS client only - not integrated into
  this backend) is configured to minimize collected user data: default PII
  collection (IP address) is disabled, and optional features that would
  capture UI content (Session Replay) are not enabled.

### Vulnerability management and patch SLA
- GitHub Dependabot alerts, security updates, and malware alerts are enabled
  on both repositories (frontend and backend, both npm-based), providing
  ongoing automated monitoring for known-vulnerable and known-malicious
  dependencies, with automatic patch PRs opened for the former.
- Defined patch SLA, measured from when a vulnerability is flagged (by
  Dependabot or any other source):
  - **Critical** (actively exploited, or directly affecting production data
    security): patched within 7 days.
  - **High**: patched within 30 days.
  - **Moderate or low**: patched within 90 days, or at the next routine
    dependency update if sooner.
- Production infrastructure (Railway, Neon) is managed-platform hosting;
  OS-level and infrastructure patching is handled by those providers as part
  of their own security programs, not by Fenn directly.

### End-of-life (EOL) software monitoring
- Application dependencies are continuously monitored via GitHub Dependabot,
  which flags packages with known vulnerabilities regardless of EOL status.
- Runtime versions (Node.js, PostgreSQL) are managed by Railway and Neon
  respectively as part of their own infrastructure lifecycle - neither is
  self-hosted by Fenn.
- The app's own pinned runtime and major dependency versions (e.g., the
  Node.js version used locally and in CI, the Expo/React Native SDK version)
  are reviewed against public EOL schedules at least as often as this
  policy's own review cadence (Section 8), and upgraded proactively rather
  than waiting for a forced deprecation.

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

### Role-based access control (RBAC)
- Every platform holding production access or credentials (GitHub, Railway,
  Neon, and the Plaid Dashboard) enforces its own built-in role-based
  permission system. The founder holds the Owner/Admin role on each -
  access is governed by an explicit assigned role on every system, not by
  an absence of any access model. RBAC does not require multiple people to
  exist; it requires that access be role-governed rather than unrestricted,
  which is true here.

### Zero trust access architecture
- No request to Fenn's backend is trusted based on network origin or
  location. Every API call requires a valid authenticated session token
  regardless of where it originates - there is no VPN, internal network, or
  other perimeter-based trust boundary anywhere in the architecture.
  Authentication is enforced per-request, consistent with zero trust
  principles, rather than relying on being "inside" a trusted network.

### Centralized identity and access management
- The founder accesses production systems (Railway, Neon, and the Plaid
  Dashboard) through a single identity provider rather than separate,
  independent credentials per platform, centralizing authentication to
  that one identity rather than fragmenting it across systems.

### Periodic access reviews and audits
Every quarter, the founder reviews access to every system holding production
credentials or consumer data (Railway, Neon, GitHub, the Plaid Dashboard):
- Confirm no additional collaborators, team members, or API keys have been
  added beyond what this policy documents.
- Confirm multi-factor authentication is still enabled on all four accounts.
- Review and revoke any unused API keys, access tokens, OAuth grants, or
  webhooks that are no longer needed.
- Confirm the vendor list in Section 4 still matches what's actually
  integrated - no forgotten or abandoned third-party access.

**Most recent review: 2026-07-27.** Findings: no collaborators beyond the
founder on any of the four systems; MFA confirmed still enabled on all
four; no unused API keys, tokens, or webhooks identified for revocation.
Next review due by 2026-10-27.

### Review
This section follows the same review cadence as the rest of this policy
(Section 8) and will be revisited as the team grows beyond a single
person, at which point these controls will be extended to additional
personnel rather than introduced from scratch.

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

In the interest of this policy being accurate rather than aspirational, gaps
are called out explicitly here rather than left implicit:

- **No automated employee de-provisioning.** No tooling exists to
  automatically revoke access when personnel leave, because there are no
  personnel beyond the founder. Unlike RBAC, zero trust, and centralized
  identity (see Section 5, which are genuinely in place today even at this
  scale), this control specifically claims automated tooling exists to
  perform an action - and none has been built, since it has never been
  needed. This will be built once Fenn actually has personnel for it to
  apply to, not before.

This gap is proportionate to Fenn's current stage (pre-launch,
single founder, no employees) rather than an oversight, and will be
revisited as the product and team grow.

## 10. Contact

Security concerns or suspected vulnerabilities can be reported to
jordan.cutter@yahoo.com.
