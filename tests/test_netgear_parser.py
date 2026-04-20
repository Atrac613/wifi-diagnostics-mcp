from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.models import EventType, RawSyslogRecord, utc_now
from wifi_diagnostics_mcp.parsers.netgear import NetgearParser


class NetgearParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = NetgearParser()
        self.fixture_lines = (
            (ROOT / "tests" / "fixtures" / "netgear" / "sample.log")
            .read_text(encoding="utf-8")
            .splitlines()
        )

    def test_association_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=10,
            received_at=utc_now(),
            sender_ip="198.51.100.20",
            raw_message=self.fixture_lines[0],
            vendor_guess="netgear",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_ASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "NG-Lobby")
        self.assertEqual(outcome.event.client_mac, "aa:bb:cc:dd:ee:11")
        self.assertEqual(outcome.event.ssid, "GuestWiFi")

    def test_roam_failure_is_detected(self) -> None:
        record = RawSyslogRecord(
            id=11,
            received_at=utc_now(),
            sender_ip="198.51.100.20",
            raw_message=self.fixture_lines[4],
            vendor_guess="netgear",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.ROAM_FAILURE.value)
        self.assertEqual(outcome.event.reason_code, "target:NG-Conf")

    def test_unknown_event_is_kept(self) -> None:
        record = RawSyslogRecord(
            id=12,
            received_at=utc_now(),
            sender_ip="198.51.100.20",
            raw_message="NETGEAR_AP[123]: AP=NG-Lobby custom vendor extension happened",
            vendor_guess="netgear",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.status.value, "unknown_event")
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)


if __name__ == "__main__":
    unittest.main()
