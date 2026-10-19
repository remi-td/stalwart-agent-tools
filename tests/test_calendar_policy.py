import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "src")
from stalwart_agent_tools.core import CalendarBinding, IdempotencyStore, PolicyError, ProfilePolicy, StalwartAdapter, TransportError
from stalwart_agent_tools.bridge import PolicyError as BridgePolicyError, expand_calendar


def policy():
    return ProfilePolicy("ops", "a", "agent", "agent@example.test", frozenset({"ok@example.test"}), frozenset({"Inbox"}), {"planning": CalendarBinding("p", "plan", True, True), "reference": CalendarBinding("r", "ref", True, False)}, frozenset({"safe.example"}), "https://mail.example.test/jmap/", "https://mail.example.test", "smtp.example.test", 465, "TOKEN")


class CalendarTransport:
    def __init__(self): self.calls=[]
    def caldav_query(self, binding, start, end, fields, limit):
        self.calls.append((binding.slug, start, end, fields, limit))
        return [{"summary":"private", "start":"2026-10-20T09:00:00Z", "end":"2026-10-20T10:00:00Z", "location":"must-not-leak", "uid":"must-not-leak"}]


def adapter(transport):
    temp=tempfile.TemporaryDirectory(); unittest.addModuleCleanup(temp.cleanup)
    return StalwartAdapter(policy(), transport, IdempotencyStore(Path(temp.name)/"state.sqlite"))


class CalendarPolicyTests(unittest.TestCase):
    def test_range_projection_and_global_budget(self):
        transport=CalendarTransport(); result=adapter(transport).calendar_query("reference", "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z")
        self.assertEqual(result["events"], [{"summary":"private", "start":"2026-10-20T09:00:00Z", "end":"2026-10-20T10:00:00Z"}])
        self.assertNotIn("location", json.dumps(result)); self.assertNotIn("uid", json.dumps(result))
        self.assertLessEqual(len(json.dumps(result, separators=(",", ":")).encode()), 8192)
        self.assertEqual(transport.calls[0][1:3], (datetime(2026,10,20,tzinfo=timezone.utc), datetime(2026,10,21,tzinfo=timezone.utc)))
    def test_invalid_ranges_fields_and_limits_fail_before_transport(self):
        for args in (("reference", "2026-10-20", "2026-10-21T00:00:00Z"), ("reference", "2026-10-21T00:00:00Z", "2026-10-20T00:00:00Z"), ("reference", "2026-10-01T00:00:00Z", "2026-11-02T00:00:00Z")):
            with self.assertRaises(PolicyError): adapter(CalendarTransport()).calendar_query(*args)
        with self.assertRaises(PolicyError): adapter(CalendarTransport()).calendar_query("reference", "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z", ["description"])
        with self.assertRaises(PolicyError): adapter(CalendarTransport()).calendar_query("reference", "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z", limit=51)
    def test_combined_is_logical_and_bounded(self):
        result=adapter(CalendarTransport()).calendar_query("combined", "2026-10-20T00:00:00Z", "2026-10-21T00:00:00Z", limit=1)
        self.assertEqual(len(result["events"]), 1); self.assertIn(result["events"][0]["resource"], {"reference", "planning"})


class BridgeExpansionTests(unittest.TestCase):
    def test_vtimezone_weekly_recurrence_and_exception_are_bounded(self):
        raw=b"""BEGIN:VCALENDAR\r
VERSION:2.0\r
BEGIN:VTIMEZONE\r
TZID:Europe/Paris\r
END:VTIMEZONE\r
BEGIN:VEVENT\r
UID:weekly\r
DTSTAMP:20261001T000000Z\r
DTSTART;TZID=Europe/Paris:20261018T090000\r
DTEND;TZID=Europe/Paris:20261018T100000\r
RRULE:FREQ=WEEKLY;COUNT=3\r
SUMMARY:Sensitive title\r
END:VEVENT\r
BEGIN:VEVENT\r
UID:weekly\r
RECURRENCE-ID;TZID=Europe/Paris:20261025T090000\r
DTSTAMP:20261001T000000Z\r
DTSTART;TZID=Europe/Paris:20261025T110000\r
DTEND;TZID=Europe/Paris:20261025T120000\r
SUMMARY:Moved\r
END:VEVENT\r
END:VCALENDAR\r
"""
        events=expand_calendar(raw, datetime(2026,10,18,tzinfo=timezone.utc), datetime(2026,11,1,tzinfo=timezone.utc))
        self.assertEqual(len(events), 2)
        rendered="".join(events.values())
        self.assertIn("SUMMARY:Moved", rendered); self.assertIn("DTSTART:20261025T100000Z", rendered)
        self.assertNotIn("VTIMEZONE", rendered); self.assertNotIn("RECURRENCE-ID", rendered)
    def test_unsupported_timezone_fails_opaque(self):
        raw=b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID=No/Such:20261018T090000\r\nDTEND;TZID=No/Such:20261018T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
        with self.assertRaises(BridgePolicyError): expand_calendar(raw, datetime(2026,10,18,tzinfo=timezone.utc), datetime(2026,10,19,tzinfo=timezone.utc))

if __name__ == "__main__": unittest.main()
