# stalwart-agent-tools

`stalwart-agent-tools` is a native Hermes plugin plus a versioned Python adapter for **explicitly bound, non-family profiles**. It provides narrow JMAP mail reads/drafts, verified `SMTP_SSL` submission, CalDAV event writes, standards-compliant invitation construction, and a constrained external-ICS registration boundary. It does not enable itself, alter Sharik/Auxiliary configuration, read any live data, or expose credentials to a model.

## Deployment configuration

The active profile must enable the plugin and give it one profile-local binding. Values below are names/examples only; never commit real account IDs, host names, or secret values.

```yaml
plugins:
  entries:
    stalwart-agent-tools:
      settings:
        binding:
          enabled: true
          # Optional; when present must equal this Hermes profile name.
          profile: operations
          mail:
            account_id: opaque-server-account-id
            account_name: service-account-name
            organizer: agent@example.invalid
            allowed_recipients: [approved@example.invalid]
            folders: [Inbox, Junk Mail, Sent]
          calendars:
            planning:
              calendar_id: opaque-calendar-id
              slug: planning
              read: true
              write: true
            reference:
              calendar_id: opaque-reference-id
              slug: family-reference
              read: true
              write: false
          bridge_hosts: [calendar.example.invalid]
          bridge:
            source_credential_env: APPROVED_ICS_BEARER_URL
            reference_resource: reference
          transport:
            jmap_url: https://mail.example.invalid/.well-known/jmap
            caldav_base_url: https://mail.example.invalid
            smtp_host: smtp.example.invalid
            smtp_port: 465
            credential_env: STALWART_OWNER_PASSWORD
            smtp_credential_env: STALWART_SMTP_PASSWORD
```

`credential_env` and `smtp_credential_env` are **environment-variable references**, not credential values. The HTTP transport uses Basic owner authentication over verified TLS; provision the owner password and SMTP password in the profile's secret environment before enabling the plugin. `source_credential_env` likewise points to an approved HTTPS ICS bearer URL in secret storage; it is never a model input. The plugin's `check_fn` stays unavailable until its binding is valid and the owner/SMTP references resolve. The configured hostname, including local SMTPS, must present a hostname-valid trusted certificate; this package does not disable verification for a self-signed loopback listener. Do not configure this plugin for Sharik: Personal Workbench is the Sharik-facing policy layer and must expose only `personal_*` tools.

## Guarantees and limits

- Native handlers always return JSON envelopes and resolve the active profile binding at call time.
- JMAP authenticates as the mailbox owner over verified TLS, discovers the session `apiUrl` and allows only same-origin API calls. Folder lookups are by configured name; list/search results are bounded. Drafts are retrieved by exact JMAP ID after creation.
- SMTP uses `SMTP_SSL` with certificate verification. `submission: accepted` means the local SMTP server accepted submission; it never claims remote delivery.
- Stalwart SMTP does not necessarily save a Sent copy. After SMTP accepts a message, the adapter creates a Sent Items record with JMAP, then queries/reads the exact Message-ID, recipient and Sent membership. Uncertain outcomes are held for operator reconciliation and never resubmitted under the same key.
- A durable SQLite idempotency record is written before a validated write. Reusing a key for a different payload fails; a retry after an uncertain/send-readback outcome returns opaque reconciliation-required status and never submits a duplicate.
- CalDAV paths use Stalwart’s documented `/dav/cal/<account>/<calendar-slug>/<uid>.ics` layout, use ETags for PUT/DELETE, and read back exact writes/deletes. Calendar listing uses bounded `calendar-query` REPORT.
- Read-only calendar resources are rejected before generic write transport invocation. Only the configured ICS reflector may write its reference mirror, with an ownership manifest and conditional ETags.
- Invitation output uses RFC 5545 CRLF/UTF-8-safe 75-octet folding, organizer/attendee, sequence, and REQUEST/CANCEL methods; MIME is `multipart/alternative` with `text/calendar` method parameter.
- External ICS registration takes a **configured**, not model-supplied, secret environment reference and returns an opaque bridge ID. The bridge refresh tool pins public DNS IPs at TCP connect with SNI/hostname validation and checks every redirect. It refuses unowned event overwrites/deletes and reads back all changes; URL and payload are absent from state/results. No native Stalwart subscription is claimed.
- **Known feed-compatibility limit:** the strict UTF-8 parser accepts simple UTC/basic-date VEVENT feeds only. VTIMEZONE blocks, recurrence exceptions sharing a UID, and timezone-local DTSTART are rejected, not silently misrepresented. Validate an approved synthetic equivalent of the actual feed grammar before Auxiliary deployment.
- Errors are opaque: no endpoint, raw HTTP status/body, URL, credential, mail content, or stack trace is returned.

## Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
uv lock --check
uv run --locked python -m unittest discover -s tests -v
hermes plugins doctor . --ci
```

Tests use synthetic account identifiers, fake JMAP/SMTP/CalDAV transport records, plugin registration/dispatch, profile isolation, idempotency replay/ambiguity, ownership denial, UTF-8 ICS folding, and SSRF policy checks. They do not connect to Stalwart or use secrets.

## Controlled install / rollback

1. Build the versioned adapter wheel and install the reviewed **native plugin directory** (manifest + root `__init__.py` + `src/`) into an explicitly selected non-family test profile using the pinned git commit; the wheel alone is not a native plugin. See [DEPLOYMENT.md](DEPLOYMENT.md) for exact commands and configuration.
2. Run `hermes plugins doctor . --ci`, start a fresh session, and confirm only the intended profile exposes the tools.
3. With an operator-approved disposable account, perform one draft/readback, one send/Sent-readback, and one planning-calendar create/readback/delete. Never test against Sharik/Auxiliary live data without separate approval.
4. To roll back, disable `stalwart-agent-tools` in the target profile, restart Hermes, revoke its bound credential values, and remove its profile plugin-data directory only after retaining any required reconciliation record.

No live deployment is performed by this repository.
