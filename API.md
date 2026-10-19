# Adapter contract v0.3.0

`stalwart_agent_tools` is a policy-bound library. Native registration is for explicitly bound non-family profiles only; do not install it in Sharik. A conversational integration exposes only `personal_calendar_query` for calendar reads.

## `personal_calendar_query`

```json
{
  "resource": "reference | planning | combined",
  "start": "2026-10-20T00:00:00Z",
  "end": "2026-10-21T00:00:00Z",
  "fields": ["summary", "start", "end"],
  "limit": 20
}
```

`start` and `end` are required RFC 3339 timestamps with offsets. The interval is half-open `[start, end)`, must be positive, and is at most 31 days. `fields` defaults to `summary`, `start`, `end`; the only supported fields are `summary`, `start`, `end`, and `status`. The limit defaults to 20 and is at most 50. Results are UTC structured records and the complete serialized response is capped at 8 KiB. Raw ICS, UIDs, locations, descriptions, attendees, account IDs, URLs, ETags, and source data never appear.

`reference` queries the read-only mirror. `planning` queries the writable planning calendar. `combined` executes the same bounded query on both and adds only a logical `resource` label. Writes are separate planning-only operations; reference writes fail closed.

The transport sends a matching CalDAV `time-range` filter and also discards any returned event outside the requested range. Invalid, malformed, unsupported, oversized, or transport-failed reads return the plugin's opaque error envelope. They never authorize file/cache reads, shell commands, bridge-state inspection, source retrieval, or delegated workers as fallbacks.

## External ICS compatibility

The bridge accepts a deliberately restricted grammar: UTC or IANA `TZID` timestamps declared by `VTIMEZONE`, weekly recurrence (`FREQ=WEEKLY`, `INTERVAL`, `COUNT`, `UNTIL`), and one-off recurrence overrides. It bounds expansion to a caller-supplied 31-day range and emits only hashed occurrence IDs internally. Unsupported recurrence or timezone semantics fail closed with an opaque error; raw source content and URLs are absent from state and tool output.

## Mail transport and trust

Endpoints, account IDs, calendar slugs, secrets, and CA paths are profile configuration, never tool parameters. TLS always uses `CERT_REQUIRED` plus hostname validation. `transport.tls_ca_bundle_file` may point to an absolute readable private-CA PEM bundle; the endpoint must use the hostname in its certificate SAN. There is no insecure-loopback or verification-disable option.

JMAP special folders resolve by the standard `drafts` and `sent` roles, not display names. Operators may instead bind opaque JMAP IDs with `mail.special_mailbox_ids`; localized names are never used as a fallback. Sent role resolution happens before SMTP submission, preventing a known bad mailbox binding from stranding a submitted message behind a pending idempotency key.
