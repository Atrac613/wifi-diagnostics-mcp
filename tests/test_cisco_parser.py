from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.config import AppConfig
from wifi_diagnostics_mcp.models import APMetadata, EventType, RawSyslogRecord, utc_now
from wifi_diagnostics_mcp.parsers.cisco import CiscoParser
from wifi_diagnostics_mcp.service import WiFiDiagnosticsService
from wifi_diagnostics_mcp.storage import SQLiteRepository


class CiscoParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = CiscoParser()
        self.fixture_lines = (
            (ROOT / "tests" / "fixtures" / "cisco" / "sample.log")
            .read_text(encoding="utf-8")
            .splitlines()
        )

    def test_client_association_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=1,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message=self.fixture_lines[0],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_ASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "AP-Lobby")
        self.assertEqual(outcome.event.client_mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(outcome.event.ssid, "CorpWiFi")
        self.assertEqual(outcome.event.band, "2.4GHz")

    def test_auth_failure_has_reason_code(self) -> None:
        record = RawSyslogRecord(
            id=2,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message=self.fixture_lines[1],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.reason_code, "23")
        self.assertEqual(outcome.event.severity, "error")

    def test_unknown_event_falls_back_to_unknown_wifi_event(self) -> None:
        record = RawSyslogRecord(
            id=3,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message='%LINK-6-UPDOWN: AP "AP-Lobby" uplink changed state',
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.status.value, "unknown_event")
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)

    def test_mobility_express_assoc_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=4,
            received_at=utc_now(),
            sender_ip="198.51.100.20",
            raw_message=self.fixture_lines[9],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_ASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.client_mac, "c2:b2:f9:fd:f9:1f")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "key_mgmt:Open")

    def test_mobility_express_eapol_retrans_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=5,
            received_at=utc_now(),
            sender_ip="198.51.100.21",
            raw_message=self.fixture_lines[10],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "ae:b0:9e:57:34:8c")
        self.assertEqual(outcome.event.reason_code, "max_eapol_key_retrans")
        self.assertEqual(outcome.event.severity, "error")

    def test_osapi_events_are_tagged_as_noise_unknowns(self) -> None:
        record = RawSyslogRecord(
            id=6,
            received_at=utc_now(),
            sender_ip="198.51.100.24",
            raw_message=(
                "<133>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 20 19:36:58.903: "
                "%OSAPI-5-MUTEX_UNLOCK_FAILED: osapi_sem.c:1253 Failed to release a mutual "
                "exclusion object. mutex unlock failed"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "noise:osapi_5_mutex_unlock_failed")
        self.assertEqual(outcome.event.severity, "debug")

    def test_radius_override_disabled_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=7,
            received_at=utc_now(),
            sender_ip="198.51.100.25",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 20 19:37:50.888: "
                "%APF-6-RADIUS_OVERRIDE_DISABLED: apf_ms_radius_override.c:213 "
                "Radius overrides disabled, ignoring source 4"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "noise:apf_6_radius_override_disabled")
        self.assertEqual(outcome.event.severity, "debug")

    def test_default_cipher_suite_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=8,
            received_at=utc_now(),
            sender_ip="198.51.100.26",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 20 19:37:28.624: "
                "%APF-6-USE_DEFAULT_CIPHER_SUITE: apf_rsn_utils.c:3136 Using default settings "
                "for Group Management Cipher Suite for mobile 50:14:79:25:f4:12"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:25:f4:12")
        self.assertEqual(outcome.event.reason_code, "noise:apf_6_use_default_cipher_suite")
        self.assertEqual(outcome.event.severity, "debug")

    def test_assocreq_proc_failed_is_mapped_to_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=9,
            received_at=utc_now(),
            sender_ip="198.51.100.22",
            raw_message=self.fixture_lines[11],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:25:f4:12")
        self.assertEqual(outcome.event.ssid, "ChaCha")
        self.assertEqual(
            outcome.event.reason_code,
            "assocreq_proc_failed:max_sta_load_balance_decision_failure",
        )
        self.assertEqual(outcome.event.severity, "error")

    def test_mobility_express_disassoc_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=10,
            received_at=utc_now(),
            sender_ip="198.51.100.23",
            raw_message=self.fixture_lines[12],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_DISASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.client_mac, "b0:95:75:f5:19:a2")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "sending_station_has_left_the_bss")
        self.assertEqual(outcome.event.severity, "warning")

    def test_timestamp_uses_nearest_year_with_configured_timezone(self) -> None:
        parser = CiscoParser(syslog_timestamp_tzinfo=timezone(timedelta(hours=9)))
        record = RawSyslogRecord(
            id=11,
            received_at=datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC),
            sender_ip="198.51.100.27",
            raw_message=(
                "<133>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Dec 31 23:59:59: "
                "%OSAPI-5-MUTEX_UNLOCK_FAILED: mutex unlock failed"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(
            outcome.event.ts,
            datetime(2025, 12, 31, 14, 59, 59, tzinfo=UTC),
        )

    def test_ap_metadata_prefers_friendly_name_for_same_ap_mac(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            service = WiFiDiagnosticsService(repository, AppConfig(db_path=db_path))
            try:
                service.ingest_syslog(
                    self.fixture_lines[10],
                    sender_ip="198.51.100.21",
                    vendor_override="cisco",
                )
                service.repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name="AP-Office",
                        vendor="cisco",
                        ap_mac="00:f8:2c:26:65:80",
                        mgmt_ip="198.51.100.21",
                    )
                )
                metadata = service.find_ap_metadata("00:f8:2c:26:65:80")
                assert metadata is not None
                self.assertEqual(metadata["ap_name"], "AP-Office")
                self.assertEqual(metadata["ap_mac"], "00:f8:2c:26:65:80")
            finally:
                repository.close()


if __name__ == "__main__":
    unittest.main()
