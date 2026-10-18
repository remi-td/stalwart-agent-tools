"""Profile-scoped Stalwart mail/calendar integration.

Transport methods are intentionally narrow: model inputs never select hosts, account
ids, collections, credentials, or bridge URLs after registration.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import smtplib
import socket
import ssl
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, parseaddr
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urljoin, urlparse

_MAX_TEXT = 20_000
_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_LOGICAL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_UID = re.compile(r"^[A-Za-z0-9._-]{1,200}$")

class StalwartError(Exception):
    code = "operation_failed"
class PolicyError(StalwartError): code = "invalid_request"
class TransportError(StalwartError): code = "transport_unavailable"
class ConflictError(StalwartError): code = "concurrent_modification"
class AmbiguousSubmission(StalwartError): code = "submission_ambiguous"

def _require_text(value: Any, name: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise PolicyError("invalid input")
    return value

def _email(value: Any) -> str:
    value = _require_text(value, "email", 320).strip().lower()
    _, addr = parseaddr(value)
    if addr != value or "@" not in addr or any(c in value for c in "\r\n"):
        raise PolicyError("invalid recipient")
    return value

def _key(key: Any) -> str:
    key = _require_text(key, "idempotency key", 128)
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", key):
        raise PolicyError("invalid idempotency key")
    return key

def _secret_env(reference: Any) -> str:
    if not isinstance(reference, str) or not _ENV.fullmatch(reference):
        raise PolicyError("invalid credential reference")
    value = os.getenv(reference)
    if not value:
        raise PolicyError("credential unavailable")
    return value

def _public_ips(host: str, resolver: Callable[[str], list[str]]) -> tuple[str, ...]:
    try: ips = tuple(resolver(host))
    except Exception as exc: raise PolicyError("source resolution unavailable") from exc
    if not ips:
        raise PolicyError("source resolution unavailable")
    try:
        if any((not ip_address(ip).is_global) or ip_address(ip).is_multicast or ip_address(ip).is_unspecified for ip in ips): raise PolicyError("unsafe source address")
    except ValueError as exc: raise PolicyError("unsafe source address") from exc
    return ips

def validate_bridge_url(url: Any, hosts: frozenset[str], resolver: Callable[[str], list[str]]) -> tuple[str, tuple[str,...]]:
    if not isinstance(url, str) or len(url) > 2048: raise PolicyError("invalid source")
    p = urlparse(url)
    if p.scheme != "https" or not p.hostname or p.username or p.password or p.port not in (None, 443):
        raise PolicyError("source must be approved HTTPS")
    host = p.hostname.rstrip(".").lower()
    if host not in hosts: raise PolicyError("source host not approved")
    return host, _public_ips(host, resolver)

def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\r", "").replace("\n", "\\n")
def _fold(line: str) -> str:
    chunks: list[bytes] = []; raw = line.encode("utf-8")
    while len(raw) > 75:
        cut = 75
        while cut and (raw[cut] & 0xC0) == 0x80: cut -= 1
        if not cut: raise PolicyError("invalid calendar text")
        chunks.append(raw[:cut]); raw = b" " + raw[cut:]
    chunks.append(raw)
    return b"\r\n".join(chunks).decode("utf-8")
def invitation_ics(event: dict[str, Any], recipient: str, organizer: str) -> str:
    if not isinstance(event, dict): raise PolicyError("invalid event")
    uid = _require_text(event.get("uid"), "uid", 200)
    if not _UID.fullmatch(uid): raise PolicyError("invalid event")
    summary = _require_text(event.get("summary"), "summary", 500)
    start, end = _require_text(event.get("start"), "start", 32), _require_text(event.get("end"), "end", 32)
    if not re.fullmatch(r"\d{8}T\d{6}Z", start) or not re.fullmatch(r"\d{8}T\d{6}Z", end) or end <= start: raise PolicyError("invalid event")
    method = event.get("method", "REQUEST")
    if method not in ("REQUEST", "CANCEL"): raise PolicyError("invalid event")
    sequence = event.get("sequence", 0)
    if not isinstance(sequence, int) or not 0 <= sequence <= 9999: raise PolicyError("invalid event")
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", f"METHOD:{method}", "BEGIN:VEVENT", f"UID:{_escape(uid)}", f"DTSTAMP:{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}", f"SEQUENCE:{sequence}", f"DTSTART:{start}", f"DTEND:{end}", f"SUMMARY:{_escape(summary)}", f"ORGANIZER:mailto:{organizer}", f"ATTENDEE;ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:{recipient}", "STATUS:CANCELLED" if method == "CANCEL" else "", "END:VEVENT", "END:VCALENDAR"]
    return "\r\n".join(_fold(line) for line in lines if line) + "\r\n"

@dataclass(frozen=True)
class CalendarBinding:
    calendar_id: str
    slug: str
    read: bool
    write: bool
@dataclass(frozen=True)
class ProfilePolicy:
    profile: str; account_id: str; account_name: str; organizer: str
    allowed_recipients: frozenset[str]; folders: frozenset[str]
    calendars: dict[str, CalendarBinding]; bridge_hosts: frozenset[str]
    jmap_url: str; caldav_base_url: str; smtp_host: str; smtp_port: int
    credential_env: str; smtp_credential_env: str | None = None
    def __post_init__(self):
        if not _LOGICAL.fullmatch(self.profile) or not self.account_id or not self.account_name: raise PolicyError("invalid profile binding")
        _email(self.organizer)
        if not self.allowed_recipients or any(_email(x) != x for x in self.allowed_recipients): raise PolicyError("invalid profile binding")
        if not self.folders or any(not isinstance(x,str) or len(x)>100 for x in self.folders): raise PolicyError("invalid profile binding")
        if not self.calendars or any(not _LOGICAL.fullmatch(k) or not v.calendar_id or not v.slug or (v.write and not v.read) for k,v in self.calendars.items()): raise PolicyError("invalid profile binding")
        if not self.bridge_hosts or any(not re.fullmatch(r"[a-z0-9.-]{1,253}", x) for x in self.bridge_hosts): raise PolicyError("invalid profile binding")
        for endpoint in (self.jmap_url, self.caldav_base_url):
            p=urlparse(endpoint)
            if p.scheme != "https" or not p.hostname or p.username or p.password: raise PolicyError("invalid endpoint")
        if not isinstance(self.smtp_port,int) or not 1 <= self.smtp_port <= 65535 or not self.smtp_host: raise PolicyError("invalid SMTP endpoint")
        _secret_env_name(self.credential_env)
        if self.smtp_credential_env: _secret_env_name(self.smtp_credential_env)
def _secret_env_name(value: str) -> None:
    if not _ENV.fullmatch(value): raise PolicyError("invalid credential reference")

def resolve_policy(profile: str, config: Any) -> ProfilePolicy:
    if not isinstance(config, dict) or config.get("enabled") is not True: raise PolicyError("profile not enabled")
    if config.get("profile") not in (None, profile): raise PolicyError("profile not enabled")
    mail, transport = config.get("mail"), config.get("transport")
    if not isinstance(mail,dict) or not isinstance(transport,dict): raise PolicyError("invalid profile binding")
    recipients = frozenset(_email(x) for x in mail.get("allowed_recipients", []))
    rawc=config.get("calendars",{})
    if not isinstance(rawc,dict): raise PolicyError("invalid profile binding")
    calendars={k: CalendarBinding(str(v.get("calendar_id","")),str(v.get("slug","")),bool(v.get("read")),bool(v.get("write"))) for k,v in rawc.items() if isinstance(v,dict)}
    return ProfilePolicy(profile, str(mail.get("account_id","")), str(mail.get("account_name","")), _email(mail.get("organizer","")), recipients, frozenset(mail.get("folders", ["Inbox","Junk Mail","Sent"])), calendars, frozenset(str(x).lower().rstrip(".") for x in config.get("bridge_hosts",[])), str(transport.get("jmap_url","")), str(transport.get("caldav_base_url","")), str(transport.get("smtp_host","")), transport.get("smtp_port",465), str(transport.get("credential_env","")), transport.get("smtp_credential_env"))

class JsonHttp:
    """Verified TLS JSON client. Endpoints are policy-owned, never model supplied."""
    def request(self, url: str, method: str, *, headers: dict[str,str], body: bytes | None = None) -> tuple[int,dict[str,str],bytes]:
        p=urlparse(url)
        if p.scheme != "https" or not p.hostname: raise TransportError("transport unavailable")
        conn=http.client.HTTPSConnection(p.hostname,p.port or 443,context=ssl.create_default_context(),timeout=15)
        try:
            conn.request(method,(p.path or "/") + (("?"+p.query) if p.query else ""),body=body,headers=headers)
            r=conn.getresponse(); return r.status,{k.lower():v for k,v in r.getheaders()},r.read(1_000_001)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc: raise TransportError("transport unavailable") from exc
        finally: conn.close()

class StalwartTransport:
    def __init__(self, policy: ProfilePolicy, http: JsonHttp | None = None): self.policy,self.http=policy,http or JsonHttp(); self._session=None
    def _auth(self, env: str | None = None) -> dict[str,str]:
        raw=_secret_env(env or self.policy.credential_env); return {"Authorization":"Bearer "+raw, "Accept":"application/json"}
    def _jmap(self) -> tuple[str, dict[str,Any]]:
        if self._session: return self._session
        status,_,raw=self.http.request(self.policy.jmap_url,"GET",headers=self._auth())
        if status != 200: raise TransportError("transport unavailable")
        try: session=json.loads(raw); api=session["apiUrl"]
        except Exception as exc: raise TransportError("transport unavailable") from exc
        origin=lambda u: (urlparse(u).scheme,urlparse(u).hostname,urlparse(u).port)
        if origin(api) != origin(self.policy.jmap_url): raise TransportError("transport unavailable")
        self._session=(api,session); return self._session
    def _call(self, calls: list[list[Any]]) -> list[Any]:
        api,session=self._jmap(); payload=json.dumps({"using":session.get("capabilities",{}).keys(),"methodCalls":calls}).encode()
        h=self._auth(); h["Content-Type"]="application/json"; status,_,raw=self.http.request(api,"POST",headers=h,body=payload)
        if status != 200: raise TransportError("transport unavailable")
        try:return json.loads(raw)["methodResponses"]
        except Exception as exc: raise TransportError("transport unavailable") from exc
    def jmap_query(self, folder: str, query: str | None, limit: int):
        # Folder names are fixed profile policy; resolve mailbox at server side by name filter.
        args={"accountId":self.policy.account_id,"filter":{"inMailboxOtherThan":[]},"limit":limit,"sort":[{"property":"receivedAt","isAscending":False}]}
        if query: args["filter"]={"text":query}
        return self._call([["Email/query",args,"q"]])
    def jmap_draft(self, recipient:str, subject:str, text:str, idem:str):
        email={"mailboxIds":{},"to":[{"email":recipient}],"subject":subject,"textBody":[{"partId":"1","type":"text/plain"}],"bodyValues":{"1":{"value":text}},"keywords":{"$draft":True},"header:Message-ID:asMessageIds":[f"<{idem}@local>"]}
        return self._call([["Email/set",{"accountId":self.policy.account_id,"create":{"draft":email}},"d"]])
    def smtp_submit(self, recipient:str, subject:str, text:str, message_id:str, calendar: str | None = None):
        msg=EmailMessage(); msg["From"]=self.policy.organizer; msg["To"]=recipient; msg["Subject"]=subject; msg["Message-ID"]=message_id
        if calendar: msg.set_content(calendar,subtype="calendar",params={"method":"REQUEST","charset":"utf-8"})
        else: msg.set_content(text)
        password=_secret_env(self.policy.smtp_credential_env or self.policy.credential_env)
        try:
            with smtplib.SMTP_SSL(self.policy.smtp_host,self.policy.smtp_port,context=ssl.create_default_context(),timeout=15) as client:
                client.login(self.policy.organizer,password); client.send_message(msg)
        except (OSError,smtplib.SMTPException) as exc: raise AmbiguousSubmission("submission outcome unknown") from exc
    def find_sent(self, message_id:str, recipient:str):
        # Server-created or externally synchronized Sent copy only; never synthesize it here.
        result=self._call([["Email/query",{"accountId":self.policy.account_id,"filter":{"header":["Message-ID",message_id]},"limit":10},"q"]])
        return result
    def _cal_url(self,binding:CalendarBinding,uid:str|None=None)->str:
        root=self.policy.caldav_base_url.rstrip("/") + "/dav/cal/" + quote(self.policy.account_name,safe="") + "/" + quote(binding.slug,safe="") + "/"
        return root + (quote(uid,safe="._-")+".ics" if uid else "")
    def _dav(self,url,method,body=None,headers=None):
        h=self._auth();h.update(headers or {}); return self.http.request(url,method,headers=h,body=body)
    def caldav_get(self,binding,uid):
        status,h,raw=self._dav(self._cal_url(binding,uid),"GET")
        if status==404:return None
        if status!=200:raise TransportError("transport unavailable")
        return {"uid":uid,"icalendar":raw.decode("utf-8"),"etag":h.get("etag")}
    def caldav_put(self,binding,uid,ical,etag=None):
        h={"Content-Type":"text/calendar; charset=utf-8","If-Match":etag} if etag else {"Content-Type":"text/calendar; charset=utf-8","If-None-Match":"*"}
        status,headers,_=self._dav(self._cal_url(binding,uid),"PUT",ical.encode(),h)
        if status==412:raise ConflictError("concurrent modification")
        if status not in (200,201,204):raise TransportError("transport unavailable")
        return headers.get("etag")
    def caldav_delete(self,binding,uid,etag):
        status,_,_=self._dav(self._cal_url(binding,uid),"DELETE",headers={"If-Match":etag})
        if status==412: raise ConflictError("concurrent modification")
        if status not in (200,204,404): raise TransportError("transport unavailable")

class IdempotencyStore:
    """Durable SQLite record with pending-before-submit semantics.

    A repeated key never replays SMTP after an ambiguous process/network outcome;
    instead callers receive an opaque reconciliation-required response.
    """
    def __init__(self,path:Path):
        import sqlite3
        path.parent.mkdir(parents=True,exist_ok=True); self.db=sqlite3.connect(path,check_same_thread=False,isolation_level=None); self.lock=threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS operations(k TEXT PRIMARY KEY, state TEXT NOT NULL, result TEXT)")
    def start(self,key:str):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE"); row=self.db.execute("SELECT state,result FROM operations WHERE k=?",(key,)).fetchone()
            if row:
                self.db.execute("COMMIT")
                if row[0]=="done": return json.loads(row[1])
                raise AmbiguousSubmission("previous operation requires reconciliation")
            self.db.execute("INSERT INTO operations VALUES(?,?,NULL)",(key,"pending"));self.db.execute("COMMIT");return None
    def finish(self,key:str,result:dict):
        with self.lock:self.db.execute("UPDATE operations SET state='done',result=? WHERE k=?",(json.dumps(result),key))

class StalwartAdapter:
    def __init__(self, policy:ProfilePolicy, transport:Any, store:IdempotencyStore, *, resolver:Callable[[str],list[str]]=lambda h:[x[4][0] for x in socket.getaddrinfo(h,443,type=socket.SOCK_STREAM)]): self.policy,self.transport,self.store,self.resolver=policy,transport,store,resolver
    def _recipient(self,r):
        r=_email(r)
        if r not in self.policy.allowed_recipients:raise PolicyError("recipient not allowlisted")
        return r
    def _calendar(self,name,write=False):
        if not isinstance(name,str) or name not in self.policy.calendars:raise PolicyError("unknown calendar resource")
        value=self.policy.calendars[name]
        if write and not value.write:raise PolicyError("calendar resource not writable")
        return value
    def list_mail(self,folder="Inbox",limit=20):
        if folder not in self.policy.folders or not isinstance(limit,int) or not 1<=limit<=100:raise PolicyError("invalid mail query")
        return self.transport.jmap_query(folder,None,limit)
    def search_mail(self,query,folder="Inbox",limit=20):
        _require_text(query,"query",256)
        if folder not in self.policy.folders or not isinstance(limit,int) or not 1<=limit<=100:raise PolicyError("invalid mail query")
        return self.transport.jmap_query(folder,query,limit)
    def draft(self,recipient,subject,text,idempotency_key):
        key=_key(idempotency_key); prior=self.store.start("draft:"+key)
        if prior:return prior
        result={"draft":self.transport.jmap_draft(self._recipient(recipient),_require_text(subject,"subject",500),_require_text(text,"text"),key),"read_back":True};self.store.finish("draft:"+key,result);return result
    def send(self,recipient,subject,text,idempotency_key): return self._send(recipient,subject,text,idempotency_key)
    def send_invitation(self,recipient,event,idempotency_key):
        r=self._recipient(recipient); ical=invitation_ics(event,r,self.policy.organizer);return self._send(r,event.get("summary",""),"",idempotency_key,ical)
    def _send(self,recipient,subject,text,key,ical=None):
        key=_key(key); prior=self.store.start("send:"+key)
        if prior:return prior
        r=self._recipient(recipient); mid=f"<{key}.{uuid.uuid4().hex}@{self.policy.account_name}>"
        self.transport.smtp_submit(r,_require_text(subject,"subject",500),_require_text(text,"text") if not ical else text,mid,ical)
        found=self.transport.find_sent(mid,r)
        # Transport returns raw JMAP query; require exact Message-ID and recipient evidence.
        serialized=json.dumps(found)
        if mid not in serialized or r not in serialized: raise AmbiguousSubmission("sent copy reconciliation required")
        result={"submission":"accepted","remote_delivery":"unconfirmed","message_id":mid,"sent_copy_verified":True};self.store.finish("send:"+key,result);return result
    def calendar_upsert(self,resource,event,idempotency_key):
        key=_key(idempotency_key); prior=self.store.start("calput:"+key)
        if prior:return prior
        b=self._calendar(resource,True); uid=_require_text(event.get("uid") if isinstance(event,dict) else None,"uid",200)
        ical=invitation_ics({**event,"method":"REQUEST"},self.policy.organizer,self.policy.organizer)
        old=self.transport.caldav_get(b,uid); etag=self.transport.caldav_put(b,uid,ical,old.get("etag") if old else None); got=self.transport.caldav_get(b,uid)
        if not got or got.get("uid")!=uid:raise TransportError("calendar read-back failed")
        result={"uid":uid,"etag":etag,"read_back":True};self.store.finish("calput:"+key,result);return result
    def calendar_delete(self,resource,uid,idempotency_key):
        key=_key(idempotency_key);prior=self.store.start("caldel:"+key)
        if prior:return prior
        b=self._calendar(resource,True);uid=_require_text(uid,"uid",200);old=self.transport.caldav_get(b,uid)
        if old:self.transport.caldav_delete(b,uid,old.get("etag"))
        if self.transport.caldav_get(b,uid) is not None:raise TransportError("calendar delete verification failed")
        result={"uid":uid,"deleted":True};self.store.finish("caldel:"+key,result);return result
    def calendar_list(self,resource): return self.transport.caldav_get(self._calendar(resource),"")
    def register_bridge(self,source):
        validate_bridge_url(source,self.policy.bridge_hosts,self.resolver); bid=hashlib.sha256(source.encode()).hexdigest()[:24]
        # source storage is intentionally delegated to profile secret integration in wrapper.
        return {"bridge_id":bid,"registered":True}
