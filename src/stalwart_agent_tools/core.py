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
    if not re.fullmatch(r"\d{8}T\d{6}Z", start) or not re.fullmatch(r"\d{8}T\d{6}Z", end): raise PolicyError("invalid event")
    try:
        begin=datetime.strptime(start,"%Y%m%dT%H%M%SZ")
        finish=datetime.strptime(end,"%Y%m%dT%H%M%SZ")
    except ValueError as exc:raise PolicyError("invalid event") from exc
    if finish<=begin:raise PolicyError("invalid event")
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
    def __post_init__(self):
        if not isinstance(self.calendar_id,str) or not self.calendar_id or not isinstance(self.slug,str) or not _LOGICAL.fullmatch(self.slug):raise PolicyError("invalid calendar binding")
        if type(self.read) is not bool or type(self.write) is not bool or (self.write and not self.read):raise PolicyError("invalid calendar binding")
@dataclass(frozen=True)
class ProfilePolicy:
    profile: str; account_id: str; account_name: str; organizer: str
    allowed_recipients: frozenset[str]; folders: frozenset[str]
    calendars: dict[str, CalendarBinding]; bridge_hosts: frozenset[str]
    jmap_url: str; caldav_base_url: str; smtp_host: str; smtp_port: int
    credential_env: str; smtp_credential_env: str | None = None
    def __post_init__(self):
        if not _LOGICAL.fullmatch(self.profile) or not isinstance(self.account_id,str) or not self.account_id or not isinstance(self.account_name,str) or not self.account_name or ".." in self.account_name or not re.fullmatch(r"[A-Za-z0-9@._+-]{1,320}",self.account_name): raise PolicyError("invalid profile binding")
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
    calendars={}
    for k,v in rawc.items():
        if not isinstance(k,str) or not isinstance(v,dict):raise PolicyError("invalid calendar binding")
        cid,slug,read,write=(v.get(x) for x in ("calendar_id","slug","read","write"))
        if not isinstance(cid,str) or not isinstance(slug,str) or type(read) is not bool or type(write) is not bool:raise PolicyError("invalid calendar binding")
        calendars[k]=CalendarBinding(cid,slug,read,write)
    credential_env=transport.get("credential_env")
    if not isinstance(mail.get("account_id"),str) or not isinstance(mail.get("account_name"),str) or not isinstance(credential_env,str):raise PolicyError("invalid profile binding")
    return ProfilePolicy(profile, mail["account_id"], mail["account_name"], _email(mail.get("organizer","")), recipients, frozenset(mail.get("folders", ["Inbox","Junk Mail","Sent"])), calendars, frozenset(str(x).lower().rstrip(".") for x in config.get("bridge_hosts",[])), str(transport.get("jmap_url","")), str(transport.get("caldav_base_url","")), str(transport.get("smtp_host","")), transport.get("smtp_port",465), credential_env, transport.get("smtp_credential_env"))

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
        password = _secret_env(env or self.policy.credential_env)
        token = base64.b64encode(f"{self.policy.organizer}:{password}".encode()).decode("ascii")
        return {"Authorization": "Basic " + token, "Accept": "application/json"}
    def _jmap(self) -> tuple[str, dict[str,Any]]:
        if self._session: return self._session
        status,_,raw=self.http.request(self.policy.jmap_url,"GET",headers=self._auth())
        if status != 200: raise TransportError("transport unavailable")
        try: session=json.loads(raw); api=session["apiUrl"]
        except Exception as exc: raise TransportError("transport unavailable") from exc
        origin=lambda u: (urlparse(u).scheme,urlparse(u).hostname,urlparse(u).port or 443)
        if origin(api) != origin(self.policy.jmap_url) or origin(api)[0] != "https": raise TransportError("transport unavailable")
        accounts=session.get("accounts",{})
        if self.policy.account_id not in accounts: raise TransportError("account unavailable")
        self._session=(api,session); return self._session
    def _call(self, calls: list[list[Any]]) -> list[Any]:
        api,_=self._jmap()
        payload=json.dumps({"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":calls}).encode()
        h=self._auth(); h["Content-Type"]="application/json"; status,_,raw=self.http.request(api,"POST",headers=h,body=payload)
        if status != 200: raise TransportError("transport unavailable")
        try:
            response=json.loads(raw)["methodResponses"]
            if len(response)!=len(calls) or any(item[0]=="error" or item[0]!=call[0] for item,call in zip(response,calls)):
                raise TransportError("JMAP method failed")
            return [item[1] for item in response]
        except (KeyError, IndexError, TypeError, ValueError) as exc: raise TransportError("transport unavailable") from exc
    def _folder_id(self, folder: str) -> str:
        result=self._call([["Mailbox/get",{"accountId":self.policy.account_id,"ids":None},"m"]])[0]
        matches=[item["id"] for item in result.get("list",[]) if item.get("name"," ").casefold()==folder.casefold()]
        if len(matches)!=1: raise TransportError("configured folder unavailable")
        return matches[0]
    def jmap_query(self, folder: str, query: str | None, limit: int):
        fid=self._folder_id(folder)
        filt={"inMailbox":fid}
        if query: filt={"operator":"AND","conditions":[filt,{"text":query}]}
        args={"accountId":self.policy.account_id,"filter":filt,"limit":limit,"sort":[{"property":"receivedAt","isAscending":False}]}
        result=self._call([["Email/query",args,"q"]])[0]
        ids=result.get("ids",[])
        if not isinstance(ids,list) or len(ids)>limit: raise TransportError("transport unavailable")
        if not ids: return {"total":result.get("total",0),"messages":[]}
        got=self._call([["Email/get",{"accountId":self.policy.account_id,"ids":ids,"properties":["id","subject","from","receivedAt","preview","keywords"]},"g"]])[0]
        return {"total":result.get("total"),"messages":[{"id":e["id"],"subject":e.get("subject", ""),"from":e.get("from", []),"received_at":e.get("receivedAt"),"preview":(e.get("preview") or "")[:200],"unread":"$seen" not in e.get("keywords",{})} for e in got.get("list",[])]}
    def jmap_draft(self, recipient:str, subject:str, text:str, idem:str):
        fid=self._folder_id("Drafts")
        email={"mailboxIds":{fid:True},"from":[{"email":self.policy.organizer}],"to":[{"email":recipient}],"subject":subject,"textBody":[{"partId":"1","type":"text/plain"}],"bodyValues":{"1":{"value":text}},"keywords":{"$draft":True}}
        created=self._call([["Email/set",{"accountId":self.policy.account_id,"create":{"draft":email}},"d"]])[0].get("created",{}).get("draft")
        if not isinstance(created,dict) or not created.get("id"): raise TransportError("draft creation failed")
        eid=created["id"]
        got=self._call([["Email/get",{"accountId":self.policy.account_id,"ids":[eid],"properties":["id","subject","to","mailboxIds","keywords","textBody","bodyValues"],"fetchTextBodyValues":True},"g"]])[0].get("list",[])
        if len(got)!=1 or got[0].get("id")!=eid or got[0].get("subject")!=subject or got[0].get("to")!=[{"email":recipient}] or fid not in got[0].get("mailboxIds",{}) or "$draft" not in got[0].get("keywords",{}): raise TransportError("draft read-back failed")
        values=got[0].get("bodyValues",{})
        if text not in [part.get("value") for part in values.values()]: raise TransportError("draft read-back failed")
        return {"draft_id":eid,"read_back":True}
    def smtp_submit(self, recipient:str, subject:str, text:str, message_id:str, calendar: str | None = None):
        msg=EmailMessage(); msg["From"]=self.policy.organizer; msg["To"]=recipient; msg["Subject"]=subject; msg["Message-ID"]=message_id
        if calendar:
            msg.set_content("Calendar invitation attached.")
            method="CANCEL" if "METHOD:CANCEL\r\n" in calendar else "REQUEST"
            msg.add_alternative(calendar,subtype="calendar",charset="utf-8",params={"method":method,"component":"VEVENT"})
        else: msg.set_content(text)
        password=_secret_env(self.policy.smtp_credential_env or self.policy.credential_env)
        try:
            with smtplib.SMTP_SSL(self.policy.smtp_host,self.policy.smtp_port,context=ssl.create_default_context(),timeout=15) as client:
                client.login(self.policy.organizer,password)
                refused=client.send_message(msg,from_addr=self.policy.organizer,to_addrs=[recipient])
                if refused: raise AmbiguousSubmission("submission outcome unknown")
        except (OSError,smtplib.SMTPException) as exc: raise AmbiguousSubmission("submission outcome unknown") from exc
    def find_sent(self, message_id:str, recipient:str):
        fid=self._folder_id("Sent")
        query=self._call([["Email/query",{"accountId":self.policy.account_id,"filter":{"operator":"AND","conditions":[{"inMailbox":fid},{"header":["Message-ID",message_id]}]},"limit":10},"q"]])[0]
        ids=query.get("ids",[])
        if not ids: return []
        result=self._call([["Email/get",{"accountId":self.policy.account_id,"ids":ids,"properties":["id","messageId","to","mailboxIds"]},"g"]])[0]
        expected=message_id.strip("<>")
        return [{"id":e["id"]} for e in result.get("list",[]) if expected in (e.get("messageId") or []) and any(_email(x.get("email"))==recipient for x in e.get("to",[])) and fid in e.get("mailboxIds",{})]
    def append_sent(self, recipient:str, subject:str, text:str, message_id:str, calendar:str|None=None):
        fid=self._folder_id("Sent")
        entry={"mailboxIds":{fid:True},"keywords":{"$seen":True},"from":[{"email":self.policy.organizer}],"to":[{"email":recipient}],"subject":subject,"messageId":[message_id.strip("<>")],"sentAt":datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),"bodyValues":{"plain":{"value":text or "Calendar invitation attached."}},"textBody":[{"partId":"plain","type":"text/plain"}]}
        created=self._call([["Email/set",{"accountId":self.policy.account_id,"create":{"sent":entry}},"s"]])[0].get("created",{}).get("sent")
        if not isinstance(created,dict) or not created.get("id"): raise AmbiguousSubmission("sent copy creation unknown")
        return created["id"]
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

    def caldav_list(self,binding,limit=50):
        import xml.etree.ElementTree as ET
        request=b'''<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/><c:calendar-data/></d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="VEVENT"/></c:comp-filter></c:filter></c:calendar-query>'''
        status,_,raw=self._dav(self._cal_url(binding),"REPORT",request,{"Depth":"1","Content-Type":"application/xml"})
        if status!=207 or len(raw)>1_000_000 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():raise TransportError("calendar query failed")
        try:
            tree=ET.fromstring(raw)
            ns={"d":"DAV:","c":"urn:ietf:params:xml:ns:caldav"}
            records=[]
            for node in tree.findall("d:response",ns):
                data=node.find(".//c:calendar-data",ns)
                if data is not None and data.text:
                    records.append({"icalendar":data.text[:20000]})
                    if len(records)>=limit:break
            return records
        except ET.ParseError as exc:raise TransportError("calendar query failed") from exc

class CalDAVBridgeTarget:
    """Bridge-only facade. The reflected reference calendar is never writable by
    generic calendar tools; only this operator-configured mirror target writes it.
    """
    def __init__(self, transport:StalwartTransport, binding:CalendarBinding):
        self.transport=transport;self.binding=binding
    def get(self,uid):return self.transport.caldav_get(self.binding,uid)
    def put(self,uid,icalendar,etag=None):return self.transport.caldav_put(self.binding,uid,icalendar,etag)
    def delete(self,uid,etag):return self.transport.caldav_delete(self.binding,uid,etag)

class IdempotencyStore:
    """Durable SQLite record with pending-before-submit semantics.

    A repeated key never replays SMTP after an ambiguous process/network outcome;
    instead callers receive an opaque reconciliation-required response.
    """
    def __init__(self,path:Path):
        import sqlite3
        path.parent.mkdir(parents=True,exist_ok=True); self.db=sqlite3.connect(path,check_same_thread=False,isolation_level=None); self.lock=threading.Lock()
        self.db.execute("CREATE TABLE IF NOT EXISTS operations(k TEXT PRIMARY KEY, state TEXT NOT NULL, result TEXT, fingerprint TEXT)")
        columns={row[1] for row in self.db.execute("PRAGMA table_info(operations)")}
        if "fingerprint" not in columns:self.db.execute("ALTER TABLE operations ADD COLUMN fingerprint TEXT")
    def __del__(self):
        db=getattr(self,"db",None)
        if db is not None:db.close()
    def start(self,key:str,fingerprint:str):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE"); row=self.db.execute("SELECT state,result,fingerprint FROM operations WHERE k=?",(key,)).fetchone()
            if row:
                self.db.execute("COMMIT")
                if row[2]!=fingerprint:raise PolicyError("idempotency key reused with different request")
                if row[0]=="done": return json.loads(row[1])
                raise AmbiguousSubmission("previous operation requires reconciliation")
            self.db.execute("INSERT INTO operations(k,state,result,fingerprint) VALUES(?,'pending',NULL,?)",(key,fingerprint));self.db.execute("COMMIT");return None
    def finish(self,key:str,result:dict):
        with self.lock:self.db.execute("UPDATE operations SET state='done',result=? WHERE k=?",(json.dumps(result),key))

def _fingerprint(*values:Any) -> str:
    return hashlib.sha256(json.dumps(values,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

class StalwartAdapter:
    def __init__(self, policy:ProfilePolicy, transport:Any, store:IdempotencyStore, *, resolver:Callable[[str],list[str]]=lambda h:[x[4][0] for x in socket.getaddrinfo(h,443,type=socket.SOCK_STREAM)]): self.policy,self.transport,self.store,self.resolver=policy,transport,store,resolver
    def _recipient(self,r):
        r=_email(r)
        if r not in self.policy.allowed_recipients:raise PolicyError("recipient not allowlisted")
        return r
    def _calendar(self,name,write=False):
        if not isinstance(name,str) or name not in self.policy.calendars:raise PolicyError("unknown calendar resource")
        value=self.policy.calendars[name]
        if (write and not value.write) or (not write and not value.read):raise PolicyError("calendar resource unavailable")
        return value
    def list_mail(self,folder="Inbox",limit=20):
        if folder not in self.policy.folders or not isinstance(limit,int) or not 1<=limit<=100:raise PolicyError("invalid mail query")
        return self.transport.jmap_query(folder,None,limit)
    def search_mail(self,query,folder="Inbox",limit=20):
        _require_text(query,"query",256)
        if folder not in self.policy.folders or not isinstance(limit,int) or not 1<=limit<=100:raise PolicyError("invalid mail query")
        return self.transport.jmap_query(folder,query,limit)
    def draft(self,recipient,subject,text,idempotency_key):
        r=self._recipient(recipient); subject=_require_text(subject,"subject",500);text=_require_text(text,"text");key=_key(idempotency_key)
        op="draft:"+key;prior=self.store.start(op,_fingerprint(r,subject,text))
        if prior:return prior
        result=self.transport.jmap_draft(r,subject,text,key)
        if not result.get("read_back"):raise TransportError("draft read-back failed")
        self.store.finish(op,result);return result
    def send(self,recipient,subject,text,idempotency_key): return self._send(recipient,subject,text,idempotency_key)
    def send_invitation(self,recipient,event,idempotency_key):
        r=self._recipient(recipient); ical=invitation_ics(event,r,self.policy.organizer);return self._send(r,event["summary"],"",idempotency_key,ical,request_data=event)
    def _send(self,recipient,subject,text,key,ical=None,request_data=None):
        r=self._recipient(recipient);subject=_require_text(subject,"subject",500)
        if not ical:text=_require_text(text,"text")
        key=_key(key);op="send:"+key;prior=self.store.start(op,_fingerprint(r,subject,text,request_data if request_data is not None else ical))
        if prior:return prior
        mid=f"<{key}.{uuid.uuid4().hex}@{self.policy.organizer.split('@',1)[1]}>"
        self.transport.smtp_submit(r,subject,text,mid,ical)
        # Stalwart local SMTP does not necessarily save a Sent copy; append once,
        # then read back exact Message-ID, recipient and Sent mailbox membership.
        self.transport.append_sent(r,subject,text,mid,ical)
        found=self.transport.find_sent(mid,r)
        if not found: raise AmbiguousSubmission("sent copy reconciliation required")
        result={"submission":"accepted","remote_delivery":"unconfirmed","message_id":mid,"sent_id":found[0]["id"],"sent_copy_verified":True};self.store.finish(op,result);return result
    def calendar_upsert(self,resource,event,idempotency_key):
        b=self._calendar(resource,True)
        if not isinstance(event,dict):raise PolicyError("invalid event")
        uid=_require_text(event.get("uid"),"uid",200)
        if not _UID.fullmatch(uid):raise PolicyError("invalid event")
        ical=invitation_ics({**event,"method":"REQUEST"},self.policy.organizer,self.policy.organizer)
        key=_key(idempotency_key);op="calput:"+key;prior=self.store.start(op,_fingerprint(resource,event))
        if prior:return prior
        old=self.transport.caldav_get(b,uid);etag=self.transport.caldav_put(b,uid,ical,old.get("etag") if old else None);got=self.transport.caldav_get(b,uid)
        if not got or got.get("uid")!=uid or got.get("icalendar")!=ical:raise TransportError("calendar read-back failed")
        result={"uid":uid,"etag":etag,"read_back":True};self.store.finish(op,result);return result
    def calendar_delete(self,resource,uid,idempotency_key):
        b=self._calendar(resource,True);uid=_require_text(uid,"uid",200)
        if not _UID.fullmatch(uid):raise PolicyError("invalid event")
        key=_key(idempotency_key);op="caldel:"+key;prior=self.store.start(op,_fingerprint(resource,uid))
        if prior:return prior
        old=self.transport.caldav_get(b,uid)
        if old:self.transport.caldav_delete(b,uid,old.get("etag"))
        if self.transport.caldav_get(b,uid) is not None:raise TransportError("calendar delete verification failed")
        result={"uid":uid,"deleted":True};self.store.finish(op,result);return result
    def calendar_list(self,resource): return self.transport.caldav_list(self._calendar(resource))
    def register_bridge(self,source):
        validate_bridge_url(source,self.policy.bridge_hosts,self.resolver); bid=hashlib.sha256(source.encode()).hexdigest()[:24]
        return {"bridge_id":bid,"registered":True}
    def refresh_bridge(self,source,resource,state):
        from .bridge import refresh
        binding=self._calendar(resource)
        if binding.write:raise PolicyError("bridge target must be reference-only")
        target=CalDAVBridgeTarget(self.transport,binding)
        return refresh(source,self.policy.bridge_hosts,target,state,resolver=self.resolver)
