from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.config import AppConfig
from wifi_diagnostics_mcp.service import WiFiDiagnosticsService
from wifi_diagnostics_mcp.storage import SQLiteRepository
from wifi_diagnostics_mcp.models import SearchFilters, utc_now


class ServiceReparseTests(unittest.TestCase):
    def test_reparse_saved_raw_syslog_recomputes_timestamps_with_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            utc_service = WiFiDiagnosticsService(
                repository,
                AppConfig(
                    db_path=db_path,
                    syslog_timestamp_timezone="UTC",
                ),
            )
            try:
                utc_service.ingest_syslog(
                    (
                        "<131>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 21 09:53:13.456: "
                        "%DOT1X-3-INVALID_REPLAY_CTR: 1x_eapkey.c:458 Invalid replay counter "
                        "from client e2:c9:fa:b6:ff:47 - got 00 00 00 00 00 00 00 02, expected "
                        "00 00 00 00 00 00 00 03"
                    ),
                    sender_ip="198.51.100.200",
                    vendor_override="cisco",
                )
                before = repository.search_events(
                    SearchFilters(since=utc_now().replace(year=2000), limit=10)
                )[0].ts
            finally:
                repository.close()

            reparsed_repository = SQLiteRepository(db_path)
            reparsed_repository.initialize()
            jst_service = WiFiDiagnosticsService(
                reparsed_repository,
                AppConfig(
                    db_path=db_path,
                    syslog_timestamp_timezone="Asia/Tokyo",
                ),
            )
            try:
                result = jst_service.reparse_saved_raw_syslog()
                after = reparsed_repository.search_events(
                    SearchFilters(since=utc_now().replace(year=2000), limit=10)
                )[0].ts
            finally:
                reparsed_repository.close()

        self.assertEqual(result["raw_records"], 1)
        self.assertEqual(result["reparsed_rows"], 1)
        self.assertEqual(result["parsed_rows"], 1)
        self.assertEqual(result["corrected_timestamps"], 1)
        self.assertEqual(before.isoformat(), "2026-04-21T09:53:13+00:00")
        self.assertEqual(after.isoformat(), "2026-04-21T00:53:13+00:00")
        self.assertEqual(after.tzinfo, UTC)


if __name__ == "__main__":
    unittest.main()
