from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.models import APMetadata, NormalizedEvent, RawSyslogRecord, SearchFilters, utc_now
from wifi_diagnostics_mcp.storage import SQLiteRepository


class StorageMigrationTests(unittest.TestCase):
    def test_initialize_migrates_legacy_ap_metadata_without_ap_mac(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "legacy.db"
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE ap_metadata (
                    ap_name TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    mgmt_ip TEXT,
                    location TEXT,
                    model TEXT,
                    notes TEXT
                );
                """
            )
            conn.close()

            repository = SQLiteRepository(db_path)
            repository.initialize()

            columns = {
                row["name"] for row in repository._conn.execute("PRAGMA table_info(ap_metadata)").fetchall()
            }
            self.assertIn("ap_mac", columns)

            index_names = {
                row["name"] for row in repository._conn.execute("PRAGMA index_list(ap_metadata)").fetchall()
            }
            self.assertIn("idx_ap_metadata_ap_mac", index_names)

    def test_upsert_ap_metadata_promotes_friendly_name_over_mac_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            try:
                repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name="00:f8:2c:26:65:80",
                        vendor="cisco",
                        ap_mac="00:f8:2c:26:65:80",
                        mgmt_ip="198.51.100.200",
                    )
                )
                repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name="AP-Office",
                        vendor="cisco",
                        ap_mac="00:f8:2c:26:65:80",
                        mgmt_ip="198.51.100.200",
                    )
                )
                metadata = repository.find_ap_metadata("00:f8:2c:26:65:80")
                assert metadata is not None
                self.assertEqual(metadata.ap_name, "AP-Office")
            finally:
                repository.close()

    def test_canonicalize_ap_events_rewrites_existing_ap_names_for_same_mac(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            try:
                repository.insert_normalized_event(
                    NormalizedEvent(
                        ts=utc_now(),
                        vendor="cisco",
                        device_id="Cisco-00f8.2c26.6580",
                        ap_name="00:f8:2c:26:65:80",
                        ap_mac="00:f8:2c:26:65:80",
                        client_mac="aa:bb:cc:dd:ee:01",
                        client_ip=None,
                        ssid="CorpWiFi",
                        band=None,
                        radio=None,
                        channel=None,
                        event_type="auth_failure",
                        severity="warning",
                        reason_code="radius_timeout",
                        message="Auth failure",
                        raw_event_id=None,
                        parser_version="test",
                    )
                )
                repository.canonicalize_ap_events("00:f8:2c:26:65:80", "AP-Office")
                rows = repository.search_events(
                    SearchFilters(
                        since=utc_now().replace(year=2000),
                        ap_mac="00:f8:2c:26:65:80",
                        limit=10,
                    )
                )
                self.assertEqual(rows[0].ap_name, "AP-Office")
            finally:
                repository.close()

    def test_normalized_event_timestamps_by_raw_id_returns_saved_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            try:
                raw_id = repository.insert_raw_syslog(
                    RawSyslogRecord(
                        id=None,
                        received_at=utc_now(),
                        sender_ip="198.51.100.200",
                        raw_message="test",
                        vendor_guess="cisco",
                        parse_status="received",
                    )
                )
                event_ts = utc_now()
                repository.insert_normalized_event(
                    NormalizedEvent(
                        ts=event_ts,
                        vendor="cisco",
                        device_id="device",
                        ap_name="AP-Office",
                        ap_mac="00:f8:2c:26:65:80",
                        client_mac=None,
                        client_ip=None,
                        ssid=None,
                        band=None,
                        radio=None,
                        channel=None,
                        event_type="auth_failure",
                        severity="warning",
                        reason_code="test",
                        message="test",
                        raw_event_id=raw_id,
                        parser_version="test",
                    )
                )
                mapping = repository.normalized_event_timestamps_by_raw_id()
                self.assertEqual(mapping[raw_id], event_ts)
                repository.delete_all_normalized_events()
                self.assertEqual(repository.normalized_event_timestamps_by_raw_id(), {})
            finally:
                repository.close()


if __name__ == "__main__":
    unittest.main()
