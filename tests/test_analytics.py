from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.config import AppConfig
from wifi_diagnostics_mcp.models import APMetadata, NormalizedEvent, utc_now
from wifi_diagnostics_mcp.service import WiFiDiagnosticsService
from wifi_diagnostics_mcp.storage import SQLiteRepository


class AnalyticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "wifi.db"
        self.config = AppConfig(db_path=self.db_path, default_lookback_minutes=60)
        self.repository = SQLiteRepository(self.db_path)
        self.repository.initialize()
        self.service = WiFiDiagnosticsService(self.repository, self.config)

        self.service.ingest_sample_logs(str(ROOT / "tests" / "fixtures" / "cisco" / "sample.log"))
        self.service.ingest_sample_logs(str(ROOT / "tests" / "fixtures" / "netgear" / "sample.log"))

    def tearDown(self) -> None:
        self.repository.close()
        self.temp_dir.cleanup()

    def test_wifi_health_counts_problem_categories(self) -> None:
        result = self.service.get_wifi_health(60)
        self.assertGreaterEqual(result["total_events"], 10)
        self.assertGreaterEqual(result["auth_failure_count"], 2)
        self.assertGreaterEqual(result["ap_down_count"], 2)
        self.assertTrue(result["top_noisy_aps"])
        self.assertIn("wifi_health_score", result)

    def test_compare_windows_returns_delta(self) -> None:
        result = self.service.compare_wifi_windows(60)
        self.assertIn("current", result)
        self.assertIn("previous", result)
        self.assertIn("delta", result)
        self.assertEqual(result["current"]["total_events"], self.service.get_wifi_health(60)["total_events"])

    def test_network_slowdown_context_is_fact_centered(self) -> None:
        result = self.service.explain_network_slowdown_context(60)
        self.assertIn("wifi_health", result)
        self.assertIn("compare_windows", result)
        self.assertIn("fact_summary", result)
        self.assertTrue(result["dominant_issue_categories"])

    def test_osapi_noise_unknowns_do_not_reduce_health_score(self) -> None:
        noise_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "osapi-noise.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "osapi-noise.db"),
        )
        noise_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<133>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: {timestamp}.903: "
                "%OSAPI-5-MUTEX_UNLOCK_FAILED: osapi_sem.c:1253 Failed to release a mutual "
                "exclusion object. mutex unlock failed"
            )
            for _ in range(20):
                noise_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = noise_service.get_wifi_health(60)
            self.assertEqual(result["total_events"], 20)
            self.assertEqual(result["wifi_health_score"], 100)
            self.assertEqual(result["auth_failure_count"], 0)
            self.assertEqual(result["top_noisy_aps"], [])
            self.assertEqual(result["top_unstable_clients"], [])
            self.assertNotIn("unknown_wifi_event=", result["interpretation_hint"])
        finally:
            noise_service.repository.close()

    def test_noise_tagged_events_do_not_dominate_top_clients(self) -> None:
        noise_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "cipher-noise.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "cipher-noise.db"),
        )
        noise_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: {timestamp}.624: "
                "%APF-6-USE_DEFAULT_CIPHER_SUITE: apf_rsn_utils.c:3136 Using default settings "
                "for Group Management Cipher Suite for mobile 50:14:79:25:f4:12"
            )
            for _ in range(10):
                noise_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            self.assertEqual(noise_service.top_unstable_clients(), [])
        finally:
            noise_service.repository.close()

    def test_ap_status_filters_noise_from_issue_sections(self) -> None:
        noise_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "ap-status-noise.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "ap-status-noise.db"),
        )
        noise_service.repository.initialize()
        try:
            line = (
                "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 20 19:37:28.624: "
                "%APF-6-USE_DEFAULT_CIPHER_SUITE: apf_rsn_utils.c:3136 Using default settings "
                "for Group Management Cipher Suite for mobile 50:14:79:25:f4:12"
            )
            for _ in range(5):
                noise_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = noise_service.get_ap_status("00:f8:2c:26:65:80", 60)
            self.assertEqual(result["event_counts_by_type"], {})
            self.assertEqual(result["top_clients"], [])
            self.assertEqual(result["latest_events"], [])
        finally:
            noise_service.repository.close()

    def test_mobile_station_not_found_does_not_reduce_score_or_rankings(self) -> None:
        aux_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "mobile-station-not-found.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "mobile-station-not-found.db"),
        )
        aux_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<132>Cisco-00f8.2c26.6580: *spamApTask0: {timestamp}.358: "
                "%APF-4-MOBILESTATION_NOT_FOUND: apf_api.c:57734 Could not find the mobile "
                "50:14:79:c8:69:55 in internal database"
            )
            for _ in range(10):
                aux_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = aux_service.get_wifi_health(60)
            self.assertEqual(result["total_events"], 10)
            self.assertEqual(result["wifi_health_score"], 100)
            self.assertEqual(result["top_noisy_aps"], [])
            self.assertEqual(result["top_unstable_clients"], [])
            self.assertNotIn("unknown_wifi_event=", result["interpretation_hint"])
        finally:
            aux_service.repository.close()

    def test_ap_status_keeps_mobile_station_not_found_in_latest_events(self) -> None:
        aux_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "ap-status-aux.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "ap-status-aux.db"),
        )
        aux_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<132>Cisco-00f8.2c26.6580: *spamApTask0: {timestamp}.358: "
                "%APF-4-MOBILESTATION_NOT_FOUND: apf_api.c:57734 Could not find the mobile "
                "50:14:79:c8:69:55 in internal database"
            )
            for _ in range(5):
                aux_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = aux_service.get_ap_status("00:f8:2c:26:65:80", 60)
            self.assertEqual(result["event_counts_by_type"], {})
            self.assertEqual(result["top_clients"], [])
            self.assertEqual(len(result["latest_events"]), 5)
            self.assertTrue(
                all(event["reason_code"] == "mobile_station_not_found" for event in result["latest_events"])
            )
        finally:
            aux_service.repository.close()

    def test_safec_error_does_not_reduce_score_or_rankings(self) -> None:
        aux_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "safec-error.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "safec-error.db"),
        )
        aux_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<131>Cisco-00f8.2c26.6580: *apfMsConnTask_0: {timestamp}.103: "
                "%SAFEC-3-SAFEC_ERROR: safecWrapper.c:57 DATA INCONSISTENCY: (22) "
                "memcpy_s: n exceeds dmax"
            )
            for _ in range(8):
                aux_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = aux_service.get_wifi_health(60)
            self.assertEqual(result["total_events"], 8)
            self.assertEqual(result["wifi_health_score"], 100)
            self.assertEqual(result["top_noisy_aps"], [])
            self.assertEqual(result["top_unstable_clients"], [])
            self.assertNotIn("unknown_wifi_event=", result["interpretation_hint"])
        finally:
            aux_service.repository.close()

    def test_ap_status_keeps_safec_error_in_latest_events(self) -> None:
        aux_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "ap-status-safec.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "ap-status-safec.db"),
        )
        aux_service.repository.initialize()
        try:
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<131>Cisco-00f8.2c26.6580: *apfMsConnTask_0: {timestamp}.103: "
                "%SAFEC-3-SAFEC_ERROR: safecWrapper.c:57 DATA INCONSISTENCY: (22) "
                "memcpy_s: n exceeds dmax"
            )
            for _ in range(4):
                aux_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = aux_service.get_ap_status("00:f8:2c:26:65:80", 60)
            self.assertEqual(result["event_counts_by_type"], {})
            self.assertEqual(result["top_clients"], [])
            self.assertEqual(len(result["latest_events"]), 4)
            self.assertTrue(
                all(event["reason_code"] == "safec_error:memcpy_s_n_exceeds_dmax" for event in result["latest_events"])
            )
        finally:
            aux_service.repository.close()

    def test_ap_status_matches_aliases_by_name_or_mac(self) -> None:
        alias_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "ap-alias.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "ap-alias.db"),
        )
        alias_service.repository.initialize()
        try:
            alias_service.repository.upsert_ap_metadata(
                APMetadata(
                    ap_name="AP-Lobby",
                    vendor="cisco",
                    ap_mac="00:f8:2c:26:65:80",
                    mgmt_ip="198.51.100.200",
                )
            )
            now = utc_now()
            alias_service.repository.insert_normalized_event(
                NormalizedEvent(
                    ts=now,
                    vendor="cisco",
                    device_id="Cisco-00f8.2c26.6580",
                    ap_name="AP-Lobby",
                    ap_mac=None,
                    client_mac="aa:bb:cc:dd:ee:01",
                    client_ip=None,
                    ssid="CorpWiFi",
                    band=None,
                    radio=None,
                    channel=None,
                    event_type="auth_failure",
                    severity="warning",
                    reason_code="radius_timeout",
                    message="Auth failure on AP-Lobby",
                    raw_event_id=None,
                    parser_version="test",
                )
            )
            alias_service.repository.insert_normalized_event(
                NormalizedEvent(
                    ts=now,
                    vendor="cisco",
                    device_id="Cisco-00f8.2c26.6580",
                    ap_name=None,
                    ap_mac="00:f8:2c:26:65:80",
                    client_mac="aa:bb:cc:dd:ee:02",
                    client_ip=None,
                    ssid="CorpWiFi",
                    band=None,
                    radio=None,
                    channel=None,
                    event_type="client_disassociated",
                    severity="warning",
                    reason_code="client_left",
                    message="Disassoc on AP MAC identity",
                    raw_event_id=None,
                    parser_version="test",
                )
            )

            result = alias_service.get_ap_status("AP-Lobby", 60)
            self.assertEqual(result["ap_summary"]["ap_name"], "AP-Lobby")
            self.assertEqual(result["ap_summary"]["total_events"], 2)
            self.assertEqual({item["client_mac"] for item in result["top_clients"]}, {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"})
        finally:
            alias_service.repository.close()

    def test_ap_status_uses_mgmt_ip_when_only_mac_alias_exists(self) -> None:
        alias_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "ap-mgmt-ip.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "ap-mgmt-ip.db"),
        )
        alias_service.repository.initialize()
        try:
            alias_service.repository.upsert_ap_metadata(
                APMetadata(
                    ap_name="00:f8:2c:26:65:80",
                    vendor="cisco",
                    ap_mac="00:f8:2c:26:65:80",
                    mgmt_ip="198.51.100.200",
                )
            )
            timestamp = utc_now().strftime("%b %d %H:%M:%S")
            line = (
                f"<131>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: {timestamp}.903: "
                "%DOT1X-3-INVALID_REPLAY_CTR: 1x_eapkey.c:458 Invalid replay counter "
                "from client e2:c9:fa:b6:ff:47 - got 00 00 00 00 00 00 00 02, expected "
                "00 00 00 00 00 00 00 03"
            )
            alias_service.ingest_syslog(line, sender_ip="198.51.100.200", vendor_override="cisco")
            result = alias_service.get_ap_status("198.51.100.200", 60)
            self.assertEqual(result["ap_summary"]["ap_name"], "198.51.100.200")
            self.assertEqual(result["event_counts_by_type"]["auth_failure"], 1)
            self.assertEqual(result["latest_events"][0]["ap_name"], "198.51.100.200")
        finally:
            alias_service.repository.close()

    def test_client_instability_canonicalizes_top_ap_names(self) -> None:
        alias_service = WiFiDiagnosticsService(
            SQLiteRepository(Path(self.temp_dir.name) / "client-alias.db"),
            AppConfig(db_path=Path(self.temp_dir.name) / "client-alias.db"),
        )
        alias_service.repository.initialize()
        try:
            alias_service.repository.upsert_ap_metadata(
                APMetadata(
                    ap_name="AP-Lobby",
                    vendor="cisco",
                    ap_mac="00:f8:2c:26:65:80",
                    mgmt_ip="198.51.100.200",
                )
            )
            now = utc_now()
            for ap_name, ap_mac in (("AP-Lobby", None), (None, "00:f8:2c:26:65:80")):
                alias_service.repository.insert_normalized_event(
                    NormalizedEvent(
                        ts=now,
                        vendor="cisco",
                        device_id="Cisco-00f8.2c26.6580",
                        ap_name=ap_name,
                        ap_mac=ap_mac,
                        client_mac="aa:bb:cc:dd:ee:01",
                        client_ip=None,
                        ssid="CorpWiFi",
                        band=None,
                        radio=None,
                        channel=None,
                        event_type="auth_failure",
                        severity="warning",
                        reason_code="radius_timeout",
                        message="Client instability event",
                        raw_event_id=None,
                        parser_version="test",
                    )
                )

            result = alias_service.get_client_instability("aa:bb:cc:dd:ee:01", 60)
            self.assertEqual(result["top_aps"], [{"ap_name": "AP-Lobby", "count": 2}])
        finally:
            alias_service.repository.close()


if __name__ == "__main__":
    unittest.main()
