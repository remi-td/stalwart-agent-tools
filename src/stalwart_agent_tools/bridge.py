"""Protected, idempotent external ICS-to-CalDAV reflection.

``refresh`` deliberately accepts an already-authorized source URL and a narrow
CalDAV target.  It neither logs nor persists that URL: SQLite holds only a
SHA-256 identifier, HTTP validators, and bridge-owned event fingerprints.
"""
from __future__ import annotations

import hashlib
import http.client
import inspect
import socket
import sqlite3
import ssl
import threading
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urljoin, urlparse

try:  # Keep the public errors consistent when used beside the native adapter.
    from .core import ConflictError, PolicyError, TransportError
except ImportError:  # pragma: no cover - allows direct source loading
    class BridgeError(Exception): pass
    class PolicyError(BridgeError): pass
    class TransportError(BridgeError): pass
    class ConflictError(BridgeError): pass

_MAX_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_UID = __import__("re").compile(r"^[A-Za-z0-9._-]{1,200}$")
_DATE = __import__("re").compile(r"^(?:\d{8}|\d{8}T\d{6}Z)$")
_SAFE = frozenset({"UID", "DTSTAMP", "DTSTART", "DTEND", "DURATION", "SUMMARY", "DESCRIPTION", "LOCATION", "STATUS", "SEQUENCE", "RRULE", "RDATE", "EXDATE", "TRANSP", "CLASS", "CATEGORIES", "CREATED", "LAST-MODIFIED"})


class CalendarTarget(Protocol):
    def get(self, uid: str) -> dict[str, Any] | None: ...
    def put(self, uid: str, icalendar: str, etag: str | None = None) -> str | None: ...
    def delete(self, uid: str, etag: str) -> None: ...


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


def _error(message: str, kind: type[Exception] = PolicyError) -> None:
    # Never interpolate source URLs, headers, bodies, hostnames, or UIDs.
    raise kind(message)


def _public(host: str, resolver: Callable[[str], list[str]]) -> tuple[str, ...]:
    try:
        values = tuple(resolver(host))
        if not values:
            raise ValueError
        parsed = tuple(ip_address(value) for value in values)
    except Exception:
        _error("source resolution unavailable")
    if any(not value.is_global or value.is_multicast or value.is_unspecified for value in parsed):
        _error("unsafe source address")
    return tuple(str(value) for value in parsed)


def validate_source_url(source_url: Any, allowed_hosts: frozenset[str] | set[str], resolver: Callable[[str], list[str]]) -> tuple[str, tuple[str, ...]]:
    """Validate one redirect hop and return its normalized host plus public IPs."""
    if not isinstance(source_url, str) or not source_url or len(source_url) > 2048 or any(ord(ch)<32 or ord(ch)==127 for ch in source_url):
        _error("invalid source")
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        _error("source must be approved HTTPS")
    try:
        port = parsed.port
    except ValueError:
        _error("source must be approved HTTPS")
    if port not in (None, 443):
        _error("source must be approved HTTPS")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ip_address(host)
    except ValueError:
        pass
    else:
        _error("source must use an approved DNS hostname")
    normalized = frozenset(str(x).rstrip(".").lower() for x in allowed_hosts)
    if host not in normalized:
        _error("source host not approved")
    return host, _public(host, resolver)


class PinnedHTTPSClient:
    """Minimal HTTPS client which connects to a resolver-approved literal IP.

    TLS still uses the original DNS hostname for SNI and certificate validation.
    This closes the DNS re-resolution window present in hostname-based clients.
    """
    def request(self, url: str, ips: tuple[str, ...], headers: dict[str, str], max_bytes: int) -> Response:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            _error("source unavailable", TransportError)
        request_target = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        last: Exception | None = None
        for address in ips:
            raw = tls = None
            try:
                raw = socket.create_connection((address, 443), timeout=15)
                tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
                payload = (f"GET {request_target} HTTP/1.1\r\nHost: {host}\r\n"
                           "Accept: text/calendar\r\nConnection: close\r\n" +
                           "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n").encode("ascii")
                tls.sendall(payload)
                response = http.client.HTTPResponse(tls)
                response.begin()
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    _error("source response too large", TransportError)
                return Response(response.status, {k.lower(): v for k, v in response.getheaders()}, body)
            except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                last = exc
            finally:
                if tls is not None:
                    tls.close()
                elif raw is not None:
                    raw.close()
        _error("source unavailable", TransportError)


def _fetch(source_url: str, allowed_hosts: frozenset[str] | set[str], resolver: Callable[[str], list[str]], client: Any, etag: str | None, max_bytes: int) -> Response:
    url = source_url
    conditional = {"If-None-Match": etag} if etag else {}
    for hop in range(_MAX_REDIRECTS + 1):
        _, ips = validate_source_url(url, allowed_hosts, resolver)
        response = client.request(url, ips, conditional, max_bytes)
        if response.status not in (301, 302, 303, 307, 308):
            return response
        if hop == _MAX_REDIRECTS or not response.headers.get("location"):
            _error("source redirect rejected", TransportError)
        # A redirect gets no cookies, authorization, or conditional validator.
        url = urljoin(url, response.headers["location"])
        conditional = {}
    _error("source redirect rejected", TransportError)


def _unfold(raw: str) -> list[str]:
    if "\x00" in raw or "<!DOCTYPE" in raw.upper() or "<!ENTITY" in raw.upper():
        _error("invalid calendar")
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    output: list[str] = []
    for line in lines:
        if not line:
            continue
        if any(ord(ch) < 32 and ch not in "\t" for ch in line):
            _error("invalid calendar")
        if line.startswith((" ", "\t")):
            if not output:
                _error("invalid calendar")
            output[-1] += line[1:]
        else:
            output.append(line)
    return output


def _property(line: str) -> tuple[str, str]:
    if ":" not in line:
        _error("invalid calendar")
    left, value = line.split(":", 1)
    name = left.split(";", 1)[0].upper()
    if not name or not __import__("re").fullmatch(r"[A-Z0-9-]+", name):
        _error("invalid calendar")
    return name, value


def parse_calendar(payload: bytes) -> dict[str, str]:
    """Return canonical, safe single-VEVENT calendars indexed by UID."""
    if len(payload) > _MAX_BYTES:
        _error("source response too large", TransportError)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _error("invalid calendar")
    lines = _unfold(text)
    if not lines or lines[0].upper() != "BEGIN:VCALENDAR" or lines[-1].upper() != "END:VCALENDAR":
        _error("invalid calendar")
    events: dict[str, str] = {}
    current: list[str] | None = None
    version = False
    for line in lines[1:-1]:
        upper = line.upper()
        if upper == "BEGIN:VEVENT":
            if current is not None:
                _error("invalid calendar")
            current = []
            continue
        if upper == "END:VEVENT":
            if current is None:
                _error("invalid calendar")
            props: dict[str, str] = {}
            for raw_property in current:
                name, value = _property(raw_property)
                if name in props:
                    _error("invalid calendar")
                props[name] = value
            uid = props.get("UID", "")
            if not _UID.fullmatch(uid) or uid in events or "DTSTAMP" not in props or "DTSTART" not in props or ("DTEND" not in props and "DURATION" not in props):
                _error("invalid calendar")
            if not _DATE.fullmatch(props["DTSTAMP"]) or not _DATE.fullmatch(props["DTSTART"]) or ("DTEND" in props and not _DATE.fullmatch(props["DTEND"])):
                _error("invalid calendar")
            if "DURATION" in props and not __import__("re").fullmatch(r"P(?:\d+W|(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?)", props["DURATION"]):
                _error("invalid calendar")
            if "DTEND" in props and props["DTEND"] <= props["DTSTART"]:
                _error("invalid calendar")
            safe = [x for x in current if _property(x)[0] in _SAFE]
            # Canonicalize line endings and discard calendar-level/unknown components.
            events[uid] = "\r\n".join(["BEGIN:VCALENDAR", "VERSION:2.0", "BEGIN:VEVENT", *safe, "END:VEVENT", "END:VCALENDAR", ""])
            current = None
            continue
        if current is None:
            name, value = _property(line)
            if name == "VERSION" and value == "2.0":
                version = True
            elif name not in {"PRODID", "CALSCALE", "METHOD", "X-WR-CALNAME", "X-WR-TIMEZONE"}:
                _error("invalid calendar")
        else:
            name, _ = _property(line)
            if name not in _SAFE:
                # Explicitly reject nested components, not merely ignore them.
                if name in {"BEGIN", "END"}:
                    _error("invalid calendar")
                continue
            if name in {"UID", "DTSTAMP", "DTSTART", "DTEND", "DURATION"} and any(_property(x)[0] == name for x in current):
                _error("invalid calendar")
            current.append(line)
    # An empty but syntactically valid VCALENDAR deliberately represents a
    # source-side removal set; it is needed for safe deletion of owned events.
    if current is not None or not version:
        _error("invalid calendar")
    return events


class OwnershipManifest:
    """Durable manifest containing no source URL or calendar payload."""
    def __init__(self, state: str | Path | Any):
        root = getattr(state, "data_dir", state)
        path = Path(root) if not isinstance(root, Path) else root
        if path.suffix:
            db_path = path
        else:
            path.mkdir(parents=True, exist_ok=True)
            db_path = path / "ics-bridge.sqlite"
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.lock = threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS source (id TEXT PRIMARY KEY, etag TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS owned (source_id TEXT NOT NULL, uid TEXT NOT NULL, etag TEXT, digest TEXT NOT NULL, PRIMARY KEY(source_id,uid))")
    def __del__(self):
        db=getattr(self,"db",None)
        if db is not None:db.close()
    def validator(self, source_id: str) -> str | None:
        row = self.db.execute("SELECT etag FROM source WHERE id=?", (source_id,)).fetchone()
        return row[0] if row else None
    def set_validator(self, source_id: str, etag: str | None) -> None:
        self.db.execute("INSERT INTO source(id,etag) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET etag=excluded.etag", (source_id, etag))
    def owned(self, source_id: str) -> dict[str, tuple[str | None, str]]:
        return {uid: (etag, digest) for uid, etag, digest in self.db.execute("SELECT uid,etag,digest FROM owned WHERE source_id=?", (source_id,))}
    def put(self, source_id: str, uid: str, etag: str | None, digest: str) -> None:
        self.db.execute("INSERT INTO owned(source_id,uid,etag,digest) VALUES(?,?,?,?) ON CONFLICT(source_id,uid) DO UPDATE SET etag=excluded.etag,digest=excluded.digest", (source_id, uid, etag, digest))
    def remove(self, source_id: str, uid: str) -> None:
        self.db.execute("DELETE FROM owned WHERE source_id=? AND uid=?", (source_id, uid))


def _digest(ical: str) -> str:
    return hashlib.sha256(ical.encode("utf-8")).hexdigest()


def refresh(source_url: str, allowed_hosts: frozenset[str] | set[str], target: CalendarTarget, state: str | Path | Any, *, resolver: Callable[[str], list[str]] = lambda host: [x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)], http: Any | None = None, max_bytes: int = _MAX_BYTES) -> dict[str, int | bool]:
    """Fetch an allowlisted ICS feed and mirror only bridge-owned VEVENTs.

    ``target`` must implement conditional ``put``/``delete`` using the supplied
    ETag and provide ``get(uid)`` -> ``{'etag': ..., 'icalendar': ...}`` or None.
    A changed source event is read back before its manifest entry is committed.
    """
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= _MAX_BYTES:
        _error("invalid response limit")
    source_id = hashlib.sha256(source_url.encode("utf-8")).hexdigest()
    manifest = OwnershipManifest(state)
    response = _fetch(source_url, allowed_hosts, resolver, http or PinnedHTTPSClient(), manifest.validator(source_id), max_bytes)
    if response.status == 304:
        return {"not_modified": True, "created": 0, "updated": 0, "deleted": 0, "skipped": 0}
    if response.status != 200 or not response.headers.get("content-type", "").lower().split(";", 1)[0].strip() == "text/calendar":
        _error("invalid calendar response", TransportError)
    incoming = parse_calendar(response.body)
    owned = manifest.owned(source_id)
    created = updated = deleted = skipped = 0
    for uid, ical in incoming.items():
        digest = _digest(ical)
        old = owned.get(uid)
        remote = target.get(uid)
        if old is None and remote is not None:
            skipped += 1  # A non-bridge event always wins over the remote feed.
            continue
        if old is not None and remote is not None and _digest(remote.get("icalendar", "")) != old[1]:
            skipped += 1  # Never overwrite an event edited since the last reflection.
            continue
        if old is not None and old[1] == digest and remote is not None:
            continue
        try:
            etag = target.put(uid, ical, remote.get("etag") if remote else None)
        except ConflictError:
            raise
        read_back = target.get(uid)
        if not read_back or _digest(read_back.get("icalendar", "")) != digest:
            _error("calendar read-back failed", TransportError)
        manifest.put(source_id, uid, read_back.get("etag", etag), digest)
        if old is None:
            created += 1
        else:
            updated += 1
    for uid, (_, digest) in owned.items():
        if uid in incoming:
            continue
        remote = target.get(uid)
        if remote is None:
            manifest.remove(source_id, uid)
            continue
        # Do not erase an item manually changed since the bridge last owned it.
        if _digest(remote.get("icalendar", "")) != digest:
            skipped += 1
            continue
        target.delete(uid, remote.get("etag"))
        if target.get(uid) is not None:
            _error("calendar delete verification failed", TransportError)
        manifest.remove(source_id, uid)
        deleted += 1
    etag=response.headers.get("etag")
    if etag is not None and (len(etag)>128 or any(ord(ch)<32 or ord(ch)>126 for ch in etag) or "://" in etag):
        etag=None
    manifest.set_validator(source_id, etag)
    return {"not_modified": False, "created": created, "updated": updated, "deleted": deleted, "skipped": skipped}
