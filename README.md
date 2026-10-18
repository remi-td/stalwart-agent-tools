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
          transport:
            jmap_url: https://mail.example.invalid/jmap/
            caldav_base_url: https://mail.example.invalid
            smtp_host: smtp.example.invalid
            smtp_port: 465
            credential_env: STALWART_JMAP_BEARER
            smtp_credential_env: STALWART_SMTP_PASSWORD
```

`credential_env` and `smtp_credential_env` are **environment-variable references**, not credential values. Provision those values with the profile’s secret/environment mechanism before enabling the plugin. The plugin’s `check_fn` stays unavailable until its binding is valid and those references resolve. Do not configure this plugin for Sharik: Personal Workbench is the Sharik-facing policy layer and must expose only `personal_*` tools.

## Guarantees and limits

- Native handlers always return JSON envelopes and resolve the active profile binding at call time.
- JMAP uses a verified-TLS session GET and only calls the session-derived, same-origin `apiUrl`.
- SMTP uses `SMTP_SSL` with certificate verification. `submission: accepted` means the local SMTP server accepted submission; it never claims remote delivery.
- Send success requires a JMAP Sent query containing the exact generated `Message-ID` and recipient. The adapter does **not** create a synthetic Sent copy.
- A durable SQLite idempotency record is written before SMTP. A retry after an uncertain/send-readback outcome returns opaque reconciliation-required status and never submits a duplicate.
- CalDAV paths use Stalwart’s documented `/dav/cal/<account>/<calendar-slug>/<uid>.ics` layout, use ETags for PUT/DELETE, and read back writes/deletes.
- Read-only calendar resources are rejected before transport invocation.
- Invitation output uses RFC 5545 CRLF/UTF-8-safe 75-octet folding, organizer/attendee, sequence, and REQUEST/CANCEL methods.
- External ICS registration takes a secret environment reference, returns only an opaque bridge ID, and stores only the reference/ID in profile state. HTTPS, allowlisted host, standard port, and public DNS checks are enforced. A deployment must supply a separate reviewed bridge refresher which pins the validated DNS address for every TCP connection; this release does not claim a safe generic HTTP fetch-reflect implementation.
- Errors are opaque: no endpoint, raw HTTP status/body, URL, credential, mail content, or stack trace is returned.

## Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
uv lock
uv lock --check
uv run --locked python -m unittest discover -s tests -v
hermes plugins doctor . --ci
```

Tests use synthetic account identifiers, fake JMAP/SMTP/CalDAV transport records, plugin registration/dispatch, profile isolation, idempotency replay/ambiguity, ownership denial, UTF-8 ICS folding, and SSRF policy checks. They do not connect to Stalwart or use secrets.

## Controlled install / rollback

1. Build/install the reviewed package in a non-family test profile; set only synthetic test binding and secret references.
2. Run `hermes plugins doctor . --ci`, start a fresh session, and confirm only the intended profile exposes the tools.
3. With an operator-approved disposable account, perform one draft/readback, one send/Sent-readback, and one planning-calendar create/readback/delete. Never test against Sharik/Auxiliary live data without separate approval.
4. To roll back, disable `stalwart-agent-tools` in the target profile, restart Hermes, revoke its bound credential values, and remove its profile plugin-data directory only after retaining any required reconciliation record.

No live deployment is performed by this repository.
