import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, "src")
from stalwart_agent_tools.core import (CalendarBinding, IdempotencyStore, PolicyError,
 ProfilePolicy, StalwartAdapter, AmbiguousSubmission, invitation_ics, validate_bridge_url)

class FakeTransport:
 def __init__(self): self.calls=[]; self.events={}; self.sent=[]
 def jmap_query(self,*x): self.calls.append(("query",x)); return {"list":[]}
 def prepare_mailboxes(self,*roles): self.calls.append(("prepare",roles))
 def jmap_draft(self,*x): self.calls.append(("draft",x)); return {"draft_id":"d1","read_back":True}
 def jmap_set_seen(self,message_id,seen): self.calls.append(("seen",message_id,seen)); return {"message_id":message_id,"seen":seen,"read_back":True}
 def smtp_submit(self,r,s,t,mid,ical=None): self.calls.append(("smtp",r,mid)); self.sent.append({"message_id":mid,"recipient":r,"id":"sent1"})
 def append_sent(self,*x): self.calls.append(("sent-copy",x)); return "sent1"
 def find_sent(self,mid,r): return [x for x in self.sent if x["message_id"]==mid and x["recipient"]==r]
 def caldav_get(self,b,u): return self.events.get(u)
 def caldav_put(self,b,u,ical,etag=None): self.events[u]={"uid":u,"etag":"E1","icalendar":ical}; return "E1"
 def caldav_delete(self,b,u,etag): self.events.pop(u,None)

def policy(): return ProfilePolicy("ops","acc","agent","agent@example.test",frozenset({"ok@example.test"}),frozenset({"Inbox","Junk Mail","Sent"}),{"planning":CalendarBinding("p","plan",True,True),"reference":CalendarBinding("r","ref",True,False)},frozenset({"safe.example"}),"https://mail.example.test/jmap/","https://mail.example.test","smtp.example.test",465,"JMAP_TOKEN")
def adapter(fake=None):
 d=tempfile.TemporaryDirectory()
 unittest.addModuleCleanup(d.cleanup)
 return StalwartAdapter(policy(),fake or FakeTransport(),IdempotencyStore(Path(d.name)/"state.sqlite"),resolver=lambda h:["93.184.216.34"])

class AdapterTests(unittest.TestCase):
 def test_recipient_denied_before_smtp(self):
  f=FakeTransport();a=adapter(f)
  with self.assertRaises(PolicyError):a.send("bad@example.test","subject","body","abcdefgh")
  self.assertFalse(f.calls)
 def test_send_readback_and_atomic_replay(self):
  f=FakeTransport();a=adapter(f);one=a.send("ok@example.test","subject","body","abcdefgh");two=a.send("ok@example.test","subject","body","abcdefgh")
  self.assertTrue(one["sent_copy_verified"]);self.assertEqual(one,two);self.assertEqual(len([x for x in f.calls if x[0]=="smtp"]),1)
 def test_seen_state_readback_and_atomic_replay(self):
  f=FakeTransport();a=adapter(f)
  one=a.set_seen("m1",True,"abcdefgh");two=a.set_seen("m1",True,"abcdefgh")
  self.assertEqual(one,{"message_id":"m1","seen":True,"read_back":True});self.assertEqual(one,two)
  self.assertEqual([x for x in f.calls if x[0]=="seen"],[("seen","m1",True)])
  with self.assertRaises(PolicyError):a.set_seen("m1",False,"abcdefgh")
 def test_key_reuse_different_payload_denied(self):
  f=FakeTransport();a=adapter(f)
  a.send("ok@example.test","subject","body","abcdefgh")
  with self.assertRaises(PolicyError):a.send("ok@example.test","subject","changed","abcdefgh")
  self.assertEqual(len([x for x in f.calls if x[0]=="smtp"]),1)
 def test_reference_write_denial_does_not_poison_key(self):
  a=adapter();event={"uid":"u","summary":"x","start":"20260101T010000Z","end":"20260101T020000Z"}
  with self.assertRaises(PolicyError):a.calendar_upsert("reference",event,"abcdefgh")
  self.assertTrue(a.calendar_upsert("planning",event,"abcdefgh")["read_back"])
 def test_no_duplicate_after_readback_ambiguity(self):
  class Missing(FakeTransport):
   def find_sent(self,mid,r):return []
  f=Missing();a=adapter(f)
  with self.assertRaises(AmbiguousSubmission):a.send("ok@example.test","subject","body","abcdefgh")
  with self.assertRaises(AmbiguousSubmission):a.send("ok@example.test","subject","body","abcdefgh")
  self.assertEqual(len([x for x in f.calls if x[0]=="smtp"]),1)
 def test_draft_and_calendar_ownership(self):
  f=FakeTransport();a=adapter(f);self.assertTrue(a.draft("ok@example.test","s","b","abcdefgh")["read_back"])
  with self.assertRaises(PolicyError):a.calendar_upsert("reference",{"uid":"u","summary":"x","start":"20260101T010000Z","end":"20260101T020000Z"},"abcdefgh")
  self.assertFalse(f.events)
 def test_calendar_invitation_has_verified_sent_copy(self):
  f=FakeTransport();a=adapter(f);event={"uid":"u","summary":"appointment","start":"20260101T010000Z","end":"20260101T020000Z"}
  result=a.send_invitation("ok@example.test",event,"abcdefgh")
  sent=[call for call in f.calls if call[0]=="sent-copy"]
  self.assertTrue(result["sent_copy_verified"]);self.assertEqual(len(sent),1)
  self.assertIn("METHOD:REQUEST",sent[0][1][4])
 def test_calendar_readback_and_delete(self):
  a=adapter();event={"uid":"u","summary":"x","start":"20260101T010000Z","end":"20260101T020000Z"};self.assertTrue(a.calendar_upsert("planning",event,"abcdefgh")["read_back"]);self.assertTrue(a.calendar_delete("planning","u","ijklmnop")["deleted"])
 def test_ics_unicode_folding_and_cancel(self):
  ics=invitation_ics({"uid":"u","summary":"é"*100,"start":"20260101T010000Z","end":"20260101T020000Z","method":"CANCEL","sequence":1},"ok@example.test","agent@example.test")
  self.assertIn("METHOD:CANCEL",ics);self.assertIn("STATUS:CANCELLED",ics);self.assertIn("é"*100,ics.replace("\r\n ",""));self.assertTrue(all(len(x.encode())<=75 for x in ics.split("\r\n") if x))
 def test_ssrf_rejects_private_cgnat_and_redirect_host(self):
  for ip in ("127.0.0.1","100.64.0.1","224.0.0.1"):
   with self.assertRaises(PolicyError):validate_bridge_url("https://safe.example/x",frozenset({"safe.example"}),lambda h:[ip])
  with self.assertRaises(PolicyError):validate_bridge_url("https://evil.example/x",frozenset({"safe.example"}),lambda h:["93.184.216.34"])

class State:
 def __init__(self,p):self.data_dir=p;self.saved={}
 def set(self,k,v):self.saved[k]=v
 def get(self,k,default=None):return self.saved.get(k,default)
class Context:
 def __init__(self,name,binding,p):self.profile_name=name;self.binding=binding;self.state=State(p);self.tools={}
 def get_config(self,key,default=None):return self.binding if key=="binding" else default
 def register_tool(self,**kw):self.tools[kw["name"]]=kw

def binding(profile="ops"):
 return {"enabled":True,"profile":profile,"mail":{"account_id":"a","account_name":"agent","organizer":"agent@example.test","allowed_recipients":["ok@example.test"],"folders":["Inbox","Sent"]},"calendars":{"planning":{"calendar_id":"p","slug":"plan","read":True,"write":True}},"bridge_hosts":["safe.example"],"transport":{"jmap_url":"https://mail.example.test/jmap/","caldav_base_url":"https://mail.example.test","smtp_host":"smtp.example.test","smtp_port":465,"credential_env":"JMAP_TOKEN"}}
def load_plugin():
 spec=importlib.util.spec_from_file_location("plugin",Path("__init__.py"));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
class PluginTests(unittest.TestCase):
 def test_json_handlers_and_profile_dispatch(self):
  os.environ["JMAP_TOKEN"]="synthetic";m=load_plugin()
  with tempfile.TemporaryDirectory() as d:
   good=Context("ops",binding(),Path(d));bad=Context("other",binding(),Path(d));m.register(good);m.register(bad)
   self.assertTrue(good.tools["stalwart_mail_list"]["check_fn"]());self.assertFalse(bad.tools["stalwart_mail_list"]["check_fn"]())
   response=json.loads(bad.tools["stalwart_mail_list"]["handler"]({}))
   self.assertFalse(response["ok"]);self.assertNotIn("mail.example",json.dumps(response))
 def test_malformed_calendar_permissions_fail_closed(self):
  from stalwart_agent_tools.core import resolve_policy
  config=binding()
  config["calendars"]["planning"]["write"]="false"
  with self.assertRaises(PolicyError):resolve_policy("ops",config)
 def test_bridge_source_reference_is_config_only(self):
  from unittest.mock import patch
  os.environ["JMAP_TOKEN"]="synthetic"
  os.environ["ICS_SECRET"]="https://safe.example/private?bearer-test"
  m=load_plugin();config=binding();config["bridge"]={"source_credential_env":"ICS_SECRET","reference_resource":"reference"}
  config["calendars"]["reference"]={"calendar_id":"r","slug":"ref","read":True,"write":False}
  with tempfile.TemporaryDirectory() as d:
   c=Context("ops",config,Path(d));m.register(c)
   schema=c.tools["stalwart_calendar_subscribe_external"]["schema"]
   self.assertEqual(schema["parameters"]["properties"],{})
   with patch.object(m.StalwartAdapter,"register_bridge",return_value={"bridge_id":"opaque","registered":True}):
    result=json.loads(c.tools["stalwart_calendar_subscribe_external"]["handler"]({}))
   self.assertTrue(result["ok"])
   self.assertNotIn("bearer-test",json.dumps(result)+json.dumps(c.state.saved))
 def test_missing_credential_hides_tools(self):
  os.environ.pop("JMAP_TOKEN",None);m=load_plugin()
  with tempfile.TemporaryDirectory() as d:
   c=Context("ops",binding(),Path(d));m.register(c);self.assertFalse(c.tools["stalwart_mail_list"]["check_fn"]())
if __name__=="__main__":unittest.main()
