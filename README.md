# stalwart-agent-tools

Standalone native Hermes plugin and versioned Python adapter (`0.1.0`) for explicitly configured profiles. It does **not** enable itself, read credentials, access live data, or grant tools to Sharik. `personal-workbench` must import the adapter and own Sharik policy.

## Security boundary

- Profile config supplies opaque account/calendar IDs and recipient allowlists; no hardcoded IDs.
- Backend transport must use verified TLS or an explicit pinned local certificate. No unverified TLS.
- Send and invitations require JMAP Sent Items read-back; success denotes accepted local submission, not remote delivery.
- Calendar writes require configured writable logical resource, idempotency key, and exact CalDAV read-back.
- The ICS bridge permits only allowlisted HTTPS hosts; DNS is checked initially and on every redirect to block private, loopback, link-local and rebinding targets. URLs go only to profile secret storage and never return in results.
- No admin, forwarding, arbitrary JMAP/SMTP, broad mutation, or helper-script API is exposed.

## Lock strategy

`uv.lock` is committed. Current adapter is stdlib-only. Add dependencies only with `uv lock --upgrade-package <name>` and commit lock changes; CI uses `uv sync --locked` when dependencies exist.

## Verification

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
hermes plugins doctor . --ci
```

## Operator-only deployment and rollback

Install a reviewed wheel in an explicitly selected non-family profile; configure opaque bindings and secret references out of band; then enable it and execute controlled synthetic then live read/write/read-back validation. Roll back by disabling/removing the plugin and revoking its profile binding. This repository does neither.
