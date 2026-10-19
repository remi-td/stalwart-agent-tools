# Adapter contract v0.2.0

`stalwart_agent_tools` is the Python library used by a policy-composition plugin. The separate Hermes directory plugin at repository root registers `stalwart_*` tools **only for explicitly bound administrative profiles**; do not register it in Sharik. Personal Workbench should import the package and expose only its own `personal_*` schemas.

```python
from pathlib import Path
from stalwart_agent_tools import (
    resolve_policy, StalwartTransport, IdempotencyStore, StalwartAdapter,
)

# `binding` comes from the active profile's validated plugin settings;
# neither credentials nor URLs come from model tool arguments.
policy = resolve_policy(active_profile_name, binding)
adapter = StalwartAdapter(
    policy, StalwartTransport(policy),
    IdempotencyStore(profile_plugin_data_dir / "idempotency.sqlite"),
)
messages = adapter.list_mail("Inbox", 20)
# adapter.send(recipient, subject, text, stable_idempotency_key)
# adapter.calendar_upsert("planning", utc_event_fields, stable_idempotency_key)
```

Public methods: `list_mail`, `search_mail`, `draft`, `send`, `send_invitation`, `calendar_list`, `calendar_upsert`, `calendar_delete`, `register_bridge`, `refresh_bridge`. Mail `send` and invitation return local-submission status and exact Sent-copy evidence or an opaque failure; remote delivery is never inferred. Planning writes require a writable logical calendar; the bridge accepts only a configured reference-only mirror. `refresh_bridge` requires the URL resolved from the profile secret reference (never model input) and a profile-local state directory.

Requests currently use a single recipient, UTC iCalendar time strings (`YYYYMMDDTHHMMSSZ`), a stable UID composed of letters/digits/dot/underscore/hyphen, and a unique idempotency key of 8–128 characters. Reusing a key with different content is rejected. The library deliberately does not expose arbitrary JMAP/CalDAV methods or a raw HTTP fetcher to model tools.

The native plugin resolves `ctx.profile_name`, `ctx.get_config('binding')`, and `ctx.state.data_dir` at tool execution time. It returns JSON strings with `ok`/`result` or opaque `error.code`; no exception message, transport endpoint or source URL is returned. The plugin registration and schema are validated by `hermes plugins doctor . --ci` and `hermes plugins validate .`.

**Compatibility boundary:** existing owner-scoped helper scripts remain untouched and operational. They are not invoked through model-visible terminal commands. This adapter's new transport still needs disposable-account Stalwart interoperability and feed-grammar validation before it can replace helpers in production. See `DEPLOYMENT.md` and `SECURITY.md`.
