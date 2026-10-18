from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent / "src"))

def _schema(name, required):
    return {"name": name, "description": "Configured profile-scoped Stalwart operation.", "parameters": {"type":"object", "properties": {x:{"type":"string"} for x in required}, "required":list(required)}}

def register(ctx):
    # Never activates against an arbitrary profile: an operator-installed binding supplies a backend.
    def unavailable(args, **kwargs): return {"ok":False,"error":"explicit profile binding required"}
    tools={"stalwart_mail_list":("folder",),"stalwart_mail_search":("query",),"stalwart_mail_draft":("recipient","subject","text","idempotency_key"),"stalwart_mail_send":("recipient","subject","text","idempotency_key"),"stalwart_mail_send_calendar_invitation":("recipient","event","idempotency_key"),"stalwart_calendar_list":("resource",),"stalwart_calendar_upsert":("resource","event","idempotency_key"),"stalwart_calendar_delete":("resource","uid","idempotency_key"),"stalwart_calendar_subscribe_external":("source",)}
    for name, required in tools.items(): ctx.register_tool(name=name,toolset="stalwart",schema=_schema(name,required),handler=unavailable,check_fn=lambda:False)
