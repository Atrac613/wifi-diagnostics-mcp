from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

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


if __name__ == "__main__":
    unittest.main()
