import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "src")
from stalwart_agent_tools.bridge import (ConflictError, PinnedHTTPSClient, PolicyError,
                                         Response, parse_calendar, refresh,
                                         validate_source_url)


def ics(*events):
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n" + "".join(events) + "END:VCALENDAR\r\n").encode()


def event(uid="a", summary="hello"):
    return ("BEGIN:VEVENT\r\nUID:%s\r\nDTSTAMP:20260101T000000Z\r\n"
            "DTSTART:20260102T010000Z\r\nDTEND:20260102T020000Z\r\nSUMMARY:%s\r\nEND:VEVENT\r\n") % (uid, summary)


class FakeHTTP:
    def __init__(self, *responses): self.responses = list(responses); self.calls = []
    def request(self, url, ips, headers, max_bytes):
        self.calls.append((url, ips, headers, max_bytes))
        return self.responses.pop(0)


class Target:
    def __init__(self): self.events = {}; self.puts = []; self.deletes = []
    def get(self, uid): return self.events.get(uid)
    def put(self, uid, value, etag=None):
        if uid in self.events and etag != self.events[uid]["etag"]: raise ConflictError("conflict")
        if uid not in self.events and etag is not None: raise ConflictError("conflict")
        tag = "e" + str(len(self.puts) + 1)
        self.events[uid] = {"etag": tag, "icalendar": value}; self.puts.append((uid, etag)); return tag
    def delete(self, uid, etag):
        if self.events[uid]["etag"] != etag: raise ConflictError("conflict")
        self.deletes.append((uid, etag)); del self.events[uid]


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.hosts = {"calendar.example"}
        self.resolve = lambda h: ["93.184.216.34"]
        self.temp = tempfile.TemporaryDirectory()
        self.target = Target()
        self.url = "https://calendar.example/team.ics?private-token"

    def tearDown(self):
        self.temp.cleanup()

    def call(self, http):
        return refresh(self.url, self.hosts, self.target, Path(self.temp.name), resolver=self.resolve, http=http)

    def test_create_idempotent_and_no_url_in_state(self):
        first = self.call(FakeHTTP(Response(200, {"content-type": "text/calendar", "etag": '"v1"'}, ics(event()))))
        second_http = FakeHTTP(Response(304, {}, b""))
        second = self.call(second_http)
        self.assertEqual(first, {"not_modified": False, "created": 1, "updated": 0, "deleted": 0, "skipped": 0})
        self.assertTrue(second["not_modified"])
        self.assertEqual(len(self.target.puts), 1)
        self.assertEqual(second_http.calls[0][2], {"If-None-Match": '"v1"'})
        db = (Path(self.temp.name) / "ics-bridge.sqlite").read_bytes()
        self.assertNotIn(self.url.encode(), db)
        self.assertNotIn(b"private-token", db)

    def test_redirect_revalidates_and_strips_validator(self):
        http = FakeHTTP(Response(302, {"location": "https://calendar.example/new.ics"}, b""),
                        Response(200, {"content-type": "text/calendar"}, ics(event())))
        self.call(http)
        self.assertEqual(http.calls[1][2], {})
        with self.assertRaises(PolicyError):
            self.call(FakeHTTP(Response(302, {"location": "https://evil.example/x"}, b"")))

    def test_parser_rejects_dtd_duplicates_and_unsafe_components(self):
        for raw in (b"<!DOCTYPE x>",
                    ics(event("a") + event("a")),
                    ics("BEGIN:VEVENT\r\nUID:a\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260102T010000Z\r\nDTEND:20260102T020000Z\r\nBEGIN:VALARM\r\nEND:VALARM\r\nEND:VEVENT\r\n")):
            with self.assertRaises(PolicyError): parse_calendar(raw)

    def test_parser_strips_unsafe_properties_and_only_preserves_safe_event(self):
        parsed = parse_calendar(ics(event("a", "hello")[:-12] + "ATTENDEE:mailto:x@example.test\r\nEND:VEVENT\r\n"))
        self.assertNotIn("ATTENDEE", parsed["a"])
        self.assertIn("SUMMARY:hello", parsed["a"])

    def test_does_not_overwrite_or_delete_unowned_or_manually_changed(self):
        self.target.events["a"] = {"etag": "foreign", "icalendar": parse_calendar(ics(event("a")))["a"]}
        result = self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics(event("a")))))
        self.assertEqual(result["skipped"], 1); self.assertFalse(self.target.puts)
        # Establish ownership, then manually alter it before the source removes it.
        self.target.events.clear(); self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics(event("b")))))
        self.target.events["b"]["icalendar"] += "X-MANUAL:1\r\n"
        result = self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics())))
        self.assertEqual(result["deleted"], 0); self.assertEqual(result["skipped"], 1); self.assertIn("b", self.target.events)

    def test_conditional_update_delete_and_readback(self):
        self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics(event("a", "one")))))
        changed = self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics(event("a", "two")))))
        self.assertEqual(changed["updated"], 1); self.assertEqual(self.target.puts[-1][1], "e1")
        removed = self.call(FakeHTTP(Response(200, {"content-type": "text/calendar"}, ics())))
        self.assertEqual(removed["deleted"], 1); self.assertEqual(self.target.deletes[-1][1], "e2")

    def test_validation_blocks_nonpublic_and_bad_mime(self):
        for ip in ("127.0.0.1", "10.0.0.1", "100.64.0.1", "224.0.0.1"):
            with self.assertRaises(PolicyError): validate_source_url(self.url, self.hosts, lambda host: [ip])
        with self.assertRaises(Exception):
            self.call(FakeHTTP(Response(200, {"content-type": "text/html"}, b"no")))

    def test_pinned_client_uses_ip_but_sni_hostname(self):
        class Wire:
            def __init__(self): self.sent = b""; self.closed = False
            def sendall(self, value): self.sent += value
            def makefile(self, mode):
                from io import BytesIO
                return BytesIO(b"HTTP/1.1 200 OK\r\nContent-Type: text/calendar\r\nContent-Length: 2\r\n\r\nok")
            def close(self): self.closed = True
        class Context:
            def __init__(self): self.name = None; self.wire = Wire()
            def wrap_socket(self, raw, server_hostname): self.name = server_hostname; return self.wire
        raw = Wire(); context = Context()
        with patch("stalwart_agent_tools.bridge.socket.create_connection", return_value=raw) as connect:
            with patch("stalwart_agent_tools.bridge.ssl.create_default_context", return_value=context):
                reply = PinnedHTTPSClient().request("https://calendar.example/a.ics", ("93.184.216.34",), {}, 100)
        connect.assert_called_once_with(("93.184.216.34", 443), timeout=15)
        self.assertEqual(context.name, "calendar.example")
        self.assertIn(b"Host: calendar.example", context.wire.sent)
        self.assertEqual(reply.body, b"ok")

if __name__ == "__main__":
    unittest.main()
