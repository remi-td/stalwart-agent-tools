"""Native Hermes wrapper for the profile-scoped Stalwart adapter."""
from __future__ import annotations
import json
import sys
from pathlib import Path
_ROOT = Path(__file__).parent / "src"
if str(_ROOT) not in sys.path: sys.path.insert(0, str(_ROOT))
from stalwart_agent_tools.core import (AmbiguousSubmission, IdempotencyStore, PolicyError,
    StalwartAdapter, StalwartError, StalwartTransport, TransportError, resolve_policy)

_TOOL_ARGS = {
 "stalwart_mail_list": {"folder":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},
 "stalwart_mail_search": {"query":{"type":"string","maxLength":256},"folder":{"type":"string"},"limit":{"type":"integer","minimum":1,"maximum":100}},
 "stalwart_mail_set_seen": {"message_id":{"type":"string","minLength":1,"maxLength":255},"seen":{"type":"boolean"},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_mail_draft": {"recipient":{"type":"string"},"subject":{"type":"string","maxLength":500},"text":{"type":"string","maxLength":20000},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_mail_send": {"recipient":{"type":"string"},"subject":{"type":"string","maxLength":500},"text":{"type":"string","maxLength":20000},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_mail_send_calendar_invitation": {"recipient":{"type":"string"},"event":{"type":"object","additionalProperties":False,"properties":{"uid":{"type":"string"},"summary":{"type":"string"},"start":{"type":"string"},"end":{"type":"string"},"sequence":{"type":"integer","minimum":0,"maximum":9999},"method":{"type":"string","enum":["REQUEST","CANCEL"]}},"required":["uid","summary","start","end"]},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "personal_calendar_query": {"resource":{"type":"string","enum":["reference","planning","combined"]},"start":{"type":"string","maxLength":40},"end":{"type":"string","maxLength":40},"fields":{"type":"array","minItems":1,"maxItems":4,"items":{"type":"string","enum":["summary","start","end","status"]},"uniqueItems":True},"limit":{"type":"integer","minimum":1,"maximum":50}},
 "stalwart_calendar_upsert": {"resource":{"type":"string"},"event":{"type":"object"},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_calendar_delete": {"resource":{"type":"string"},"uid":{"type":"string"},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_calendar_subscribe_external": {},
 "stalwart_calendar_refresh_external": {},
}
_REQUIRED = {"stalwart_mail_list":[],"stalwart_mail_search":["query"],"stalwart_mail_set_seen":["message_id","seen","idempotency_key"],"stalwart_mail_draft":["recipient","subject","text","idempotency_key"],"stalwart_mail_send":["recipient","subject","text","idempotency_key"],"stalwart_mail_send_calendar_invitation":["recipient","event","idempotency_key"],"personal_calendar_query":["resource","start","end"],"stalwart_calendar_upsert":["resource","event","idempotency_key"],"stalwart_calendar_delete":["resource","uid","idempotency_key"],"stalwart_calendar_subscribe_external":[],"stalwart_calendar_refresh_external":[]}
def _schema(name):
    return {"name":name,"description":"Configured profile-scoped Stalwart operation; never accepts endpoint, account, calendar ID, or credentials.","parameters":{"type":"object","properties":_TOOL_ARGS[name],"required":_REQUIRED[name],"additionalProperties":False}}
def _error(exc):
    code = exc.code if isinstance(exc,StalwartError) else "operation_failed"
    return {"ok":False,"error":{"code":code,"message":"operation could not be completed"}}
def register(ctx):
    # A single plugin registration is scoped by Hermes. Resolve per invocation so profile/config reloads
    # cannot accidentally reuse another profile's binding.
    def adapter():
        policy=resolve_policy(ctx.profile_name,ctx.get_config("binding",{}))
        state_dir=ctx.state.data_dir
        return StalwartAdapter(policy,StalwartTransport(policy),IdempotencyStore(state_dir/"idempotency.sqlite"))
    def available():
        try:
            policy=resolve_policy(ctx.profile_name,ctx.get_config("binding",{}))
            # Probe only the required credential reference; no transport or network call.
            import os
            return bool(os.getenv(policy.credential_env)) and (not policy.smtp_credential_env or bool(os.getenv(policy.smtp_credential_env)))
        except Exception: return False
    def handler_for(name):
        def handler(args, **kwargs):
            try:
                if not isinstance(args,dict): raise PolicyError("invalid request")
                a=adapter()
                if name=="stalwart_mail_list": result=a.list_mail(args.get("folder","Inbox"),args.get("limit",20))
                elif name=="stalwart_mail_search": result=a.search_mail(args["query"],args.get("folder","Inbox"),args.get("limit",20))
                elif name=="stalwart_mail_set_seen": result=a.set_seen(args["message_id"],args["seen"],args["idempotency_key"])
                elif name=="stalwart_mail_draft": result=a.draft(args["recipient"],args["subject"],args["text"],args["idempotency_key"])
                elif name=="stalwart_mail_send": result=a.send(args["recipient"],args["subject"],args["text"],args["idempotency_key"])
                elif name=="stalwart_mail_send_calendar_invitation": result=a.send_invitation(args["recipient"],args["event"],args["idempotency_key"])
                elif name=="personal_calendar_query": result=a.calendar_query(args["resource"],args["start"],args["end"],args.get("fields"),args.get("limit",20))
                elif name=="stalwart_calendar_upsert": result=a.calendar_upsert(args["resource"],args["event"],args["idempotency_key"])
                elif name=="stalwart_calendar_delete": result=a.calendar_delete(args["resource"],args["uid"],args["idempotency_key"])
                elif name in ("stalwart_calendar_subscribe_external","stalwart_calendar_refresh_external"):
                    import os
                    bridge=ctx.get_config("binding",{}).get("bridge",{})
                    ref=bridge.get("source_credential_env") if isinstance(bridge,dict) else None
                    target=bridge.get("reference_resource") if isinstance(bridge,dict) else None
                    if not isinstance(ref,str) or not __import__('re').fullmatch(r"[A-Z][A-Z0-9_]{0,127}",ref) or not os.getenv(ref) or not isinstance(target,str):raise PolicyError("bridge not configured")
                    # Profile policy binds the source reference and target. The model supplies neither.
                    source=os.environ[ref]
                    if name=="stalwart_calendar_subscribe_external":
                        a._calendar(target)
                        if a.policy.calendars[target].write:raise PolicyError("bridge target must be reference-only")
                        result=a.register_bridge(source)
                        ctx.state.set("ics_bridge",{"source_credential_env":ref,"bridge_id":result["bridge_id"]})
                    else:
                        registered=ctx.state.get("ics_bridge",default={})
                        if registered.get("source_credential_env")!=ref:raise PolicyError("bridge not registered")
                        result=a.refresh_bridge(source,target,ctx.state.data_dir)
                else:raise PolicyError("unknown operation")
                return json.dumps({"ok":True,"result":result},separators=(",",":"))
            except Exception as exc: return json.dumps(_error(exc),separators=(",",":"))
        return handler
    for name in _TOOL_ARGS: ctx.register_tool(name=name,toolset="stalwart",schema=_schema(name),handler=handler_for(name),check_fn=available)
