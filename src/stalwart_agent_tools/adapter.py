from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlparse

class PolicyError(ValueError): pass
class BackendError(RuntimeError): pass

@dataclass(frozen=True)
class ProfilePolicy:
    profile: str
    account_id: str
    allowed_recipients: frozenset[str]
    calendars: dict[str, dict]
    bridge_hosts: frozenset[str]
    pinned_local_cert: str | None = None
    folders: frozenset[str] = frozenset({"Inbox", "Junk Mail", "Sent"})
    def __post_init__(self):
        if not self.profile or not self.account_id: raise PolicyError("configured profile/account required")

def safe_url(url, hosts, resolve):
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password: raise PolicyError("source must be approved HTTPS")
    host = p.hostname.rstrip(".").lower()
    if host not in hosts: raise PolicyError("source host not approved")
    try: ips = resolve(host)
    except Exception as e: raise PolicyError("DNS unavailable") from e
    if not ips or any(ip_address(x).is_private or ip_address(x).is_loopback or ip_address(x).is_link_local or ip_address(x).is_reserved for x in ips): raise PolicyError("unsafe resolved address")
    return host

def _esc(s): return str(s).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r", "").replace("\n", "\\n")
def _fold(line):
    raw=line.encode(); chunks=[]
    while len(raw)>75: chunks.append(raw[:75].decode("utf-8", "ignore")); raw=b" "+raw[75:]
    chunks.append(raw.decode()); return "\r\n".join(chunks)
def invitation_ics(event, recipient):
    if any(not event.get(x) for x in ("uid", "summary", "start", "end")): raise PolicyError("event fields missing")
    lines=("BEGIN:VCALENDAR", "VERSION:2.0", "METHOD:REQUEST", "BEGIN:VEVENT", f"UID:{_esc(event['uid'])}", f"DTSTAMP:{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}", f"DTSTART:{event['start']}", f"DTEND:{event['end']}", f"SUMMARY:{_esc(event['summary'])}", f"ATTENDEE;ROLE=REQ-PARTICIPANT:mailto:{recipient}", "END:VEVENT", "END:VCALENDAR")
    return "\r\n".join(_fold(x) for x in lines)+"\r\n"

class StalwartAdapter:
    """Injected backend performs JMAP/CalDAV/SMTP; no secrets or shell helpers."""
    def __init__(self, policy, backend, *, resolve): self.policy,self.backend,self.resolve=policy,backend,resolve
    def _recipient(self, r):
        r=r.strip().lower()
        if r not in self.policy.allowed_recipients: raise PolicyError("recipient not allowlisted")
        return r
    def list_mail(self, folder="Inbox", limit=20):
        if folder not in self.policy.folders: raise PolicyError("folder not approved")
        return self.backend.jmap_list(self.policy.account_id, folder, min(int(limit),100))
    def search_mail(self, query, folder="Inbox", limit=20):
        if not isinstance(query,str) or len(query)>256 or folder not in self.policy.folders: raise PolicyError("invalid search")
        return self.backend.jmap_search(self.policy.account_id,folder,query,min(int(limit),100))
    def draft(self, recipient, subject, text, idempotency_key): return self.backend.jmap_draft(self.policy.account_id,self._recipient(recipient),subject,text,idempotency_key)
    def _submit(self, result):
        sent=self.backend.jmap_get_sent(self.policy.account_id,result["message_id"])
        if not sent or sent.get("id") != result["message_id"]: raise BackendError("Sent Items read-back absent")
        return {"submission":"accepted", "sent_id":sent["id"], "remote_delivery":"unconfirmed"}
    def send(self, recipient, subject, text, idempotency_key):
        result=self.backend.smtp_submit(self.policy.account_id,self._recipient(recipient),subject,text,idempotency_key,tls_verify=True,pinned_cert=self.policy.pinned_local_cert)
        return self._submit(result)
    def send_invitation(self, recipient, event, idempotency_key):
        r=self._recipient(recipient); result=self.backend.smtp_submit_calendar(self.policy.account_id,r,event["summary"],invitation_ics(event,r),idempotency_key,tls_verify=True,pinned_cert=self.policy.pinned_local_cert)
        return self._submit(result)
    def _cal(self, resource, write=False):
        c=self.policy.calendars.get(resource)
        if not c or (write and not c.get("write")): raise PolicyError("calendar resource not writable" if write else "unknown calendar resource")
        return c
    def list_calendar(self, resource): return self.backend.caldav_list(self.policy.account_id,self._cal(resource)["calendar_id"])
    def upsert_calendar(self, resource,event,idempotency_key):
        c=self._cal(resource,True); out=self.backend.caldav_upsert(self.policy.account_id,c["calendar_id"],event,idempotency_key)
        if self.backend.caldav_get(self.policy.account_id,c["calendar_id"],out["uid"]) != out: raise BackendError("CalDAV read-back mismatch")
        return out
    def delete_calendar(self, resource,uid,idempotency_key):
        c=self._cal(resource,True); self.backend.caldav_delete(self.policy.account_id,c["calendar_id"],uid,idempotency_key)
        if self.backend.caldav_get(self.policy.account_id,c["calendar_id"],uid) is not None: raise BackendError("delete read-back failed")
        return {"deleted":True,"uid":uid}
    def register_bridge(self, source):
        safe_url(source,self.policy.bridge_hosts,self.resolve)
        self.backend.store_secret(self.policy.profile,"ics_source",source)
        return {"bridge_registered":True,"source":"configured"}
    def fetch_bridge(self, source, fetch):
        for _ in range(4):
            safe_url(source,self.policy.bridge_hosts,self.resolve); response=fetch(source,verify_tls=True,allow_redirects=False)
            if response.get("redirect"): source=response["redirect"]; continue
            if response.get("status") != 200 or len(response.get("body",b""))>1_000_000: raise BackendError("bridge fetch rejected")
            return {"refreshed":True,"bytes":len(response["body"])}
        raise PolicyError("too many redirects")
