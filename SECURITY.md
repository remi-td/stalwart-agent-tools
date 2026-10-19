# Security review (local artifact)

## Authority and separation

- Plugin discovery alone is not authorization. Native `stalwart_*` tools are opt-in for explicitly configured non-family profiles; wrapper checks active `ctx.profile_name` against the profile binding on **every call**. Do not install/enable this plugin in Sharik. Workbench must import the versioned adapter into its separate `personal_*` policy surface, with Sharik-owned resource/recipient binding. Hermes plugins run with host Python privileges, not inside a security sandbox; an operator must review and pin the code.
- Mail owner auth only; no Stalwart admin API, personal inbox, arbitrary SMTP host, arbitrary JMAP method or forwarding-rule mutation. The configured recipient allowlist is checked before SMTP and duplicated server-side at RCPT stage. Folder reads are constrained to configured names, including Inbox/Junk where configured.
- Calendar generic writes require a writable logical binding and are denied for reference-only resources before backend mutation. A distinct feed-reflection path can write only the configured reference mirror; ownership metadata prevents overwriting/deleting unowned or manually modified events.
- The privacy-guard plugin and delegation path are untouched. The Stalwart adapter does not provide tools to a delegated lab child; profile toolset configuration must verify that independently.

## Input and side effects

- Model schemas have bounded strings/integer limits and closed top-level object fields. Server-side validation controls email addresses, event UIDs/UTC times, recipient allowlist, writable logical resources and idempotency keys. Requests never accept a host, account ID, filesystem path, calendar ID, credential or feed URL.
- Mail drafts, submissions, calendar PUT and DELETE use SQLite idempotency records with content fingerprints (not plaintext). The record is acquired before a validated write. `pending` on uncertain outcomes blocks retries; operator reconciliation is required. SMTP acceptance is followed by a Stalwart JMAP Sent copy and exact Message-ID/recipient/folder read-back. This is **not** proof of remote delivery. Draft/read and CalDAV operations also read back exact targets.
- JMAP and CalDAV use configured HTTPS endpoints with standard TLS verification; SMTP uses SMTPS with hostname validation. An operator may supply only an absolute private-CA PEM bundle path in profile configuration; verification is never disabled. The legacy loopback helpers' unverified TLS settings are not adopted. Both correct owner certificate trust and an Auxiliary target smoke are prerequisites.
- The external ICS fetcher validates HTTPS, allowlisted DNS hostname, TCP/443, public resolved addresses for every redirect, pinned TCP IP, TLS SNI and certificate hostname, response size/MIME, strict calendar grammar, ownership manifest, conditional CalDAV writes and read-back. It does not forward an auth header to feed hosts. The feed URL is supplied only by a configured profile secret reference and is not stored in SQLite, tool output, config or audit. Errors are generic. VTIMEZONE/IANA-timezone weekly recurrence and one-off exceptions are bounded to a 31-day expansion; unsupported grammar fails closed.

## Residual risks and gates

1. **Unverified live interoperability.** JMAP/CalDAV/SMTP are exercised with synthetic transport fixtures; no real disposable Stalwart account, cert chain or server queue was used. This is not live-ready until controlled Auxiliary tests pass.
2. **Source feed semantics.** The supported subset is VTIMEZONE/IANA zones, weekly recurrence and one-off exceptions. Other grammar fails closed; retaining the approved compatibility bridge is safer than silently losing family events.
3. **Account-wide backend credential.** Owner JMAP/CalDAV credentials technically have authority beyond this Python policy if stolen or if code is compromised. Run in a tightly scoped profile and keep tools/secret environments off Sharik and lab-deep; the adapter does not change Stalwart's underlying account rights.
4. **Crash ambiguity.** SMTP might accept while read-back or durable finish fails. Same-key retry remains blocked; manual reconciliation is required. Do not solve this by auto-resending with a new key.
5. **Untrusted calendar content.** Reflected and listed events may contain private text. The plugin does not audit raw content; the calling Workbench and parent agent must still apply privacy guardrails when delegating/extracting it.

No live profile, mailbox, calendar, Vault, private feed or family record was used as a fixture or modified by this repository work. The remaining gates are target profile discovery/isolation, disposable owner smoke, TLS, actual feed-grammar compatibility, and operator approval.
