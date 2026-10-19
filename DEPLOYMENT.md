# Controlled staging for Auxiliary

This is an **artifact**, not permission to deploy. Never enable the direct `stalwart_*` tools in Sharik. Personal Workbench must import `stalwart_agent_tools` as a library and expose only policy-bound `personal_mail_*` / `personal_calendar_*` operations. No Sharik, Auxiliary, mailbox, Vault or calendar state was changed in development.

## Review and prerequisites

1. Review the immutable repository commit and build provenance before copying to the target. `plugin.yaml` and repository-root `__init__.py` are the native Hermes **directory** plugin. The wheel contains the versioned Python adapter for Workbench; installing the wheel alone does not install/enable the native wrapper.
2. In a non-family staging profile, confirm the installed Hermes version supports native `ctx.get_config`, `ctx.profile_name`, `ctx.state.data_dir` and plugin doctor. Do not provision server-admin authority; use an account owner credential with only the bound mailbox and calendars. Restrict outbound recipients at both the plugin allowlist and the Stalwart RCPT-stage rule.
3. Configure profile-local `plugins.entries.stalwart-agent-tools.settings.binding` from README. Set `profile` to the exact served profile name, calendar logical names/opaque IDs, allowed folder names and exact approved recipients. For `bridge`, set a reference-only resource and source secret **environment variable name**, not a URL in YAML. Do not enable the native plugin in Sharik.
4. Provision owner password, SMTP password and HTTPS feed URL through profile-scoped secret delivery. Stalwart JMAP/CalDAV uses Basic owner auth under HTTPS. Ensure JMAP session endpoint returns an account map including the bound account and a same-origin `apiUrl`. Hostname-verified certificates must validate for HTTP and SMTPS. For a private CA, configure the absolute profile-readable `tls_ca_bundle_file`; never bypass verification or use a loopback IP with a DNS-only certificate.
5. Permit only host-local Stalwart HTTP/SMTP network paths and outbound TCP/443 to explicitly approved public feed hosts. The bridge pins public DNS addresses on connection and rejects other redirect hosts. No credential or URL belongs in plugin output, log, config or artifact.

## Build, install, verify

```sh
cd /path/to/stalwart-agent-tools
uv lock --check
PYTHONPATH=src python3 -m unittest discover -s tests -v
hermes plugins doctor . --ci
uv build
# install the reviewed directory plugin through the target Hermes plugin installer;
# explicitly select the staging profile, and keep it disabled until bindings are checked
hermes -p <staging-profile> plugins install file:///path/to/reviewed/repo --ref <full-40-char-commit-sha> --no-enable
hermes -p <staging-profile> plugins doctor stalwart-agent-tools --ci
# after explicit operator approval:
hermes -p <staging-profile> plugins enable stalwart-agent-tools
```

Start a **fresh** staging session. Verify registered tool names against `plugin.yaml`; confirm another profile and Sharik cannot see `stalwart_*` tools. Use a disposable owner account: list only configured Inbox/Junk; create a draft and independently inspect its JMAP ID/body; create and delete one planning event and inspect exact CalDAV target; send **one operator-approved message** to an allowlisted test recipient and verify the Sent JMAP ID, actual recipient, Message-ID and server queue/remote delivery separately. Retry the same key and verify no second SMTP submission; reuse it with different content and verify denial. Confirm reference-calendar generic write denial before transport. For the feed bridge, first validate an **approved synthetic equivalent** of the actual ICS grammar (see parser limit below), register configured source reference, refresh, inspect only the mirror collection, rerun for idempotency and inspect metadata-only state. No live smoke was run in this development environment.

## Failure and rollback

- Do not retry a pending/ambiguous send with a new key: inspect Stalwart queue and Sent copy and reconcile with the profile-local `plugin-data/stalwart-agent-tools/idempotency.sqlite` first. `accepted` is local submission, not confirmed remote delivery.
- On any unsafe discovery, disable the plugin in the staging profile, restart the gateway, and confirm a fresh session exposes no `stalwart_*` tools. Preserve the SQLite idempotency/bridge manifests until reconciliation; revoke the owner credentials and feed URL if exposed. Restore the prior plugin commit/config backup only after verifying the target profile binding.
- The bridge supports a restricted VTIMEZONE/IANA-timezone and weekly-recurrence grammar, including one-off recurrence exceptions. Run the synthetic DST/recurrence test before enabling an actual feed. Any unsupported grammar must remain an opaque blocking error; do not fall back to raw source files or helper output.

## Status

Local synthetic protocol/unit tests and plugin doctor are gates, **not** live interoperability evidence. Auxiliary readiness requires target configuration inspection, fresh-session discovery/isolation, disposable read/write/read-back smoke, TLS verification, feed-grammar acceptance and operator approval. No automatic enabling, migration or removal of working helpers is in this package.
