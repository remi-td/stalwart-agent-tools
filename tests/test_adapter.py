import sys, unittest
sys.path.insert(0, "src")
from stalwart_agent_tools.adapter import *
class Fake:
 def __init__(self): self.sent={}; self.events={}; self.calls=0
 def jmap_list(self,*x): return []
 def jmap_search(self,*x): return []
 def jmap_draft(self,*x): return {"draft":"d"}
 def smtp_submit(self,a,r,s,t,k,**kw): assert kw["tls_verify"] is True; self.sent[k]={"id":k}; return {"message_id":k}
 def smtp_submit_calendar(self,a,r,s,ics,k,**kw): assert "METHOD:REQUEST" in ics and "\\," in ics and "\r\n" in ics; return self.smtp_submit(a,r,s,ics,k,**kw)
 def jmap_get_sent(self,a,i): return self.sent.get(i)
 def caldav_list(self,*x): return list(self.events.values())
 def caldav_upsert(self,a,c,e,k): self.calls+=1; self.events[e["uid"]]=dict(e); return dict(e)
 def caldav_get(self,a,c,u): return self.events.get(u)
 def caldav_delete(self,a,c,u,k): self.events.pop(u,None)
 def store_secret(self,p,k,v): assert v.startswith("https://"); return "opaque"
def adapter():
 return StalwartAdapter(ProfilePolicy("synthetic","opaque-account",frozenset({"ok@example.test"}),{"planning":{"calendar_id":"p","write":True},"reference":{"calendar_id":"r","write":False}},frozenset({"safe.example"})),Fake(),resolve=lambda h:["93.184.216.34"])
class TestAdapter(unittest.TestCase):
 def test_send_requires_sent_readback(self): self.assertEqual(adapter().send("ok@example.test","s","b","k")["sent_id"],"k")
 def test_allowlist_before_backend(self):
  a=adapter(); self.assertRaises(PolicyError,a.send,"bad@example.test","s","b","k"); self.assertFalse(a.backend.sent)
 def test_reference_write_denied_before_backend(self):
  a=adapter(); self.assertRaises(PolicyError,a.upsert_calendar,"reference",{"uid":"u"},"k"); self.assertEqual(a.backend.calls,0)
 def test_calendar_crud_readback(self):
  a=adapter(); self.assertEqual(a.upsert_calendar("planning",{"uid":"u","summary":"x"},"k")["uid"],"u"); self.assertTrue(a.delete_calendar("planning","u","d")["deleted"])
 def test_invitation_is_respondable(self): self.assertEqual(adapter().send_invitation("ok@example.test",{"uid":"u","summary":"a,b","start":"20260101T010000Z","end":"20260101T020000Z"},"i")["sent_id"],"i")
 def test_bridge_ssrf_and_secret_url_suppression(self):
  a=adapter(); self.assertNotIn("https",str(a.register_bridge("https://safe.example/feed"))); self.assertRaises(PolicyError,a.register_bridge,"http://safe.example/feed"); a.resolve=lambda h:["127.0.0.1"]; self.assertRaises(PolicyError,a.register_bridge,"https://safe.example/feed")
 def test_redirect_is_revalidated(self): self.assertRaises(PolicyError,adapter().fetch_bridge,"https://safe.example/f",lambda u,**k:{"redirect":"https://evil.example/f"})
 def test_mail_bounds(self):
  a=adapter(); self.assertRaises(PolicyError,a.list_mail,"All Mail"); self.assertRaises(PolicyError,a.search_mail,"x"*257)
if __name__ == "__main__": unittest.main()
