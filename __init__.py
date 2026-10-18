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
 "stalwart_mail_draft": {"recipient":{"type":"string"},"subject":{"type":"string","maxLength":500},"text":{"type":"string","maxLength":20000},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_mail_send": {"recipient":{"type":"string"},"subject":{"type":"string","maxLength":500},"text":{"type":"string","maxLength":20000},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_mail_send_calendar_invitation": {"recipient":{"type":"string"},"event":{"type":"object","additionalProperties":False,"properties":{"uid":{"type":"string"},"summary":{"type":"string"},"start":{"type":"string"},"end":{"type":"string"},"sequence":{"type":"integer","minimum":0,"maximum":9999},"method":{"type":"string","enum":["REQUEST","CANCEL"]}},"required":["uid","summary","start","end"]},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_calendar_list": {"resource":{"type":"string"}},
 "stalwart_calendar_upsert": {"resource":{"type":"string"},"event":{"type":"object"},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_calendar_delete": {"resource":{"type":"string"},"uid":{"type":"string"},"idempotency_key":{"type":"string","minLength":8,"maxLength":128}},
 "stalwart_calendar_subscribe_external": {"source_credential_env":{"type":"string","pattern":"^[A-Z][A-Z0-9_]{0,127}$"}},
}
_REQUIRED = {"stalwart_mail_list":[],"stalwart_mail_search":["query"],"stalwart_mail_draft":["recipient","subject","text","idempotency_key"],"stalwart_mail_send":["recipient","subject","text","idempotency_key"],"stalwart_mail_send_calendar_invitation":["recipient","event","idempotency_key"],"stalwart_calendar_list":["resource"],"stalwart_calendar_upsert":["resource","event","idempotency_key"],"stalwart_calendar_delete":["resource","uid","idempotency_key"],"stalwart_calendar_subscribe_external":["source_credential_env"]}
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
                elif name=="stalwart_mail_draft": result=a.draft(args["recipient"],args["subject"],args["text"],args["idempotency_key"])
                elif name=="stalwart_mail_send": result=a.send(args["recipient"],args["subject"],args["text"],args["idempotency_key"])
                elif name=="stalwart_mail_send_calendar_invitation": result=a.send_invitation(args["recipient"],args["event"],args["idempotency_key"])
                elif name=="stalwart_calendar_list": result=a.calendar_list(args["resource"])
                elif name=="stalwart_calendar_upsert": result=a.calendar_upsert(args["resource"],args["event"],args["idempotency_key"])
                elif name=="stalwart_calendar_delete": result=a.calendar_delete(args["resource"],args["uid"],args["idempotency_key"])
                else:
                    # Store only an env reference and opaque bridge id in durable profile state.
                    import os
                    ref=args["source_credential_env"]
                    if not isinstance(ref,str) or not __import__('re').fullmatch(r"[A-Z][A-Z0-9_]{0,127}",ref) or not os.getenv(ref): raise PolicyError("credential unavailable")
                    result=a.register_bridge(os.environ[ref]); ctx.state.set("ics_bridge",{"source_credential_env":ref,"bridge_id":result["bridge_id"]})
                return json.dumps({"ok":True,"result":result},separators=(",",":"))
            except Exception as exc: return json.dumps(_error(exc),separators=(",",":"))
        return handler
    for name in _TOOL_ARGS: ctx.register_tool(name=name,toolset="stalwart",schema=_schema(name),handler=handler_for(name),check_fn=available)
