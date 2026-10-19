"""Synthetic JMAP/CalDAV protocol contracts, no live service or secrets."""
import os
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, 'src')
from stalwart_agent_tools.core import StalwartTransport, TransportError, CalendarBinding
from test_adapter import policy

class HttpFixture:
    def __init__(self): self.calls=[]; self.fail_readback=False; self.seen={"e1":False}
    def request(self,url,method,*,headers,body=None):
        import json
        self.calls.append((url,method,body))
        if method=='GET' and url.endswith('/jmap/'):
            return 200,{},json.dumps({'apiUrl':'https://mail.example.test/jmap/api','accounts':{'acc':{}}}).encode()
        if method=='POST':
            data=json.loads(body); name,args,_=data['methodCalls'][0]
            if name=='Mailbox/get': result={'list':[{'id':'in','name':'Inbox'},{'id':'d','name':'Brouillons','role':'drafts'},{'id':'s','name':'Sent Items','role':'sent'}]}
            elif name=='Email/query':
                self.query=args
                result={'ids':['e1'] if args['filter'].get('inMailbox')=='in' else ['sent1']}
            elif name=='Email/get':
                if args.get('properties') == ['id','keywords']:
                    email_id=args['ids'][0]
                    result={'list':[{'id':email_id,'keywords':{'$seen':True} if self.seen[email_id] else {}}]}
                else:
                    result={'list': [] if self.fail_readback else ([{'id':'e1','subject':'hello','from':[],'keywords':{}}] if args['ids']==['e1'] else [{'id':args['ids'][0],'subject':'subject','to':[{'email':'ok@example.test'}],'mailboxIds':{'d':True,'s':True},'keywords':{'$draft':True},'bodyValues':{'1':{'value':'body'}},'messageId':['mid@example.test']}])}
            elif name=='Email/set':
                if 'update' in args:
                    email_id, patch=next(iter(args['update'].items()))
                    self.seen[email_id]=patch['keywords/$seen']
                    result={'updated':{email_id:None}}
                else: result={'created':{list(args['create'])[0]:{'id':'draft1'}}}
            else: raise AssertionError(name)
            return 200,{},json.dumps({'methodResponses':[[name,result,'x']]}).encode()
        if method=='GET': return 200,{'etag':'"v1"'},b'BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n'
        if method=='PUT': return 201,{'etag':'"v2"'},b''
        if method=='DELETE': return 204,{},b''
        if method=='REPORT': return 207,{},b'<d:multistatus xmlns:d="DAV:"/>'
        raise AssertionError((url,method))

class TransportContracts(unittest.TestCase):
    def setUp(self): self.fixture=HttpFixture();self.env=patch.dict(os.environ,{'JMAP_TOKEN':'synthetic-password'});self.env.start();self.addCleanup(self.env.stop);self.t=StalwartTransport(policy(),self.fixture)
    def test_jmap_folder_scoped_list(self):
        output=self.t.jmap_query('Inbox',None,10)
        self.assertEqual(output['messages'][0]['id'],'e1')
        self.assertEqual(self.fixture.query['filter'],{'inMailbox':'in'})
    def test_jmap_draft_readback(self):
        result=self.t.jmap_draft('ok@example.test','subject','body','abcdefgh')
        self.assertTrue(result['read_back'])
        self.fixture.fail_readback=True
        with self.assertRaises(TransportError): self.t.jmap_draft('ok@example.test','subject','body','abcdefgh')
    def test_jmap_seen_state_is_reported_from_keyword_membership(self):
        self.assertEqual(self.t.jmap_set_seen('e1',True), {'message_id':'e1','seen':True,'read_back':True})
        self.assertTrue(self.fixture.seen['e1'])
        self.assertEqual(self.t.jmap_set_seen('e1',False), {'message_id':'e1','seen':False,'read_back':True})
        self.assertFalse(self.fixture.seen['e1'])
    def test_caldav_conditional_write(self):
        b=CalendarBinding('p','plan',True,True)
        self.assertEqual(self.t.caldav_put(b,'uid','BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n'), '"v2"')
        self.assertEqual(self.t.caldav_query(b, __import__('datetime').datetime(2026,1,1,tzinfo=__import__('datetime').timezone.utc), __import__('datetime').datetime(2026,1,2,tzinfo=__import__('datetime').timezone.utc), ('summary','start','end'), 10),[])
        self.assertEqual(self.t.caldav_get(b,'uid')['etag'],'"v1"')
        self.t.caldav_delete(b,'uid','"v1"')
    def test_jmap_rejects_cross_origin_api(self):
        old=self.fixture.request
        def changed(url,method,*,headers,body=None):
            if method=='GET' and url.endswith('/jmap/'):
                return 200,{},b'{"apiUrl":"https://evil.example.test/jmap/api","accounts":{"acc":{}}}'
            return old(url,method,headers=headers,body=body)
        self.fixture.request=changed
        with self.assertRaises(TransportError): self.t.jmap_query('Inbox',None,10)
if __name__=='__main__':unittest.main()
