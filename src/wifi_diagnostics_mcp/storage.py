from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Protocol

from .models import APMetadata, ClientAlias, NormalizedEvent, RawSyslogRecord, SearchFilters


class Repository(Protocol):
    def initialize(self) -> None: ...

    def insert_raw_syslog(self, record: RawSyslogRecord) -> int: ...

    def update_raw_syslog_parse(
        self, raw_id: int, parse_status: str, vendor_guess: str, parse_error: str | None
    ) -> None: ...

    def insert_normalized_event(self, event: NormalizedEvent) -> int: ...

    def search_events(self, filters: SearchFilters) -> list[NormalizedEvent]: ...

    def get_raw_records(self, raw_ids: list[int]) -> dict[int, RawSyslogRecord]: ...

    def list_raw_syslog(self) -> list[RawSyslogRecord]: ...

    def normalized_event_timestamps_by_raw_id(self) -> dict[int, datetime]: ...

    def delete_all_normalized_events(self) -> None: ...

    def list_ap_metadata(self) -> list[APMetadata]: ...

    def find_ap_metadata(self, ap_name: str) -> APMetadata | None: ...

    def upsert_ap_metadata(self, metadata: APMetadata) -> None: ...

    def canonicalize_ap_events(self, ap_mac: str, ap_name: str) -> None: ...

    def upsert_client_alias(self, alias: ClientAlias) -> None: ...


class SQLiteRepository:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def initialize(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS raw_syslog (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at TEXT NOT NULL,
                    sender_ip TEXT NOT NULL,
                    raw_message TEXT NOT NULL,
                    vendor_guess TEXT NOT NULL,
                    parse_status TEXT NOT NULL,
                    parse_error TEXT
                );

                CREATE TABLE IF NOT EXISTS normalized_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    device_id TEXT,
                    ap_name TEXT,
                    ap_mac TEXT,
                    client_mac TEXT,
                    client_ip TEXT,
                    ssid TEXT,
                    band TEXT,
                    radio TEXT,
                    channel INTEGER,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason_code TEXT,
                    message TEXT NOT NULL,
                    raw_event_id INTEGER,
                    parser_version TEXT NOT NULL,
                    FOREIGN KEY(raw_event_id) REFERENCES raw_syslog(id)
                );

                CREATE TABLE IF NOT EXISTS ap_metadata (
                    ap_name TEXT PRIMARY KEY,
                    vendor TEXT NOT NULL,
                    ap_mac TEXT,
                    mgmt_ip TEXT,
                    location TEXT,
                    model TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS client_aliases (
                    client_mac TEXT PRIMARY KEY,
                    alias TEXT NOT NULL,
                    notes TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_raw_syslog_received_at
                    ON raw_syslog(received_at);
                CREATE INDEX IF NOT EXISTS idx_raw_syslog_vendor_guess
                    ON raw_syslog(vendor_guess);
                CREATE INDEX IF NOT EXISTS idx_normalized_events_ts
                    ON normalized_events(ts);
                CREATE INDEX IF NOT EXISTS idx_normalized_events_ap_name
                    ON normalized_events(ap_name);
                CREATE INDEX IF NOT EXISTS idx_normalized_events_client_mac
                    ON normalized_events(client_mac);
                CREATE INDEX IF NOT EXISTS idx_normalized_events_event_type
                    ON normalized_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_normalized_events_vendor
                    ON normalized_events(vendor);
                """
            )
            existing_columns = {
                row["name"] for row in self._conn.execute("PRAGMA table_info(ap_metadata)").fetchall()
            }
            if "ap_mac" not in existing_columns:
                self._conn.execute("ALTER TABLE ap_metadata ADD COLUMN ap_mac TEXT")
            self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ap_metadata_ap_mac ON ap_metadata(ap_mac)")

    def insert_raw_syslog(self, record: RawSyslogRecord) -> int:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO raw_syslog (
                    received_at, sender_ip, raw_message, vendor_guess, parse_status, parse_error
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    record.received_at.isoformat(),
                    record.sender_ip,
                    record.raw_message,
                    record.vendor_guess,
                    record.parse_status,
                    record.parse_error,
                ),
            )
            return int(cursor.lastrowid)

    def update_raw_syslog_parse(
        self, raw_id: int, parse_status: str, vendor_guess: str, parse_error: str | None
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE raw_syslog
                SET parse_status = ?, vendor_guess = ?, parse_error = ?
                WHERE id = ?
                """,
                (parse_status, vendor_guess, parse_error, raw_id),
            )

    def insert_normalized_event(self, event: NormalizedEvent) -> int:
        payload = asdict(event)
        payload["ts"] = event.ts.isoformat()
        with self._lock, self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO normalized_events (
                    ts, vendor, device_id, ap_name, ap_mac, client_mac, client_ip, ssid,
                    band, radio, channel, event_type, severity, reason_code, message,
                    raw_event_id, parser_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["ts"],
                    payload["vendor"],
                    payload["device_id"],
                    payload["ap_name"],
                    payload["ap_mac"],
                    payload["client_mac"],
                    payload["client_ip"],
                    payload["ssid"],
                    payload["band"],
                    payload["radio"],
                    payload["channel"],
                    payload["event_type"],
                    payload["severity"],
                    payload["reason_code"],
                    payload["message"],
                    payload["raw_event_id"],
                    payload["parser_version"],
                ),
            )
            return int(cursor.lastrowid)

    def search_events(self, filters: SearchFilters) -> list[NormalizedEvent]:
        clauses = ["ts >= ?"]
        params: list[object] = [filters.since.isoformat()]
        if filters.until is not None:
            clauses.append("ts < ?")
            params.append(filters.until.isoformat())
        if filters.vendor:
            clauses.append("vendor = ?")
            params.append(filters.vendor)
        ap_alias_clauses: list[str] = []
        ap_alias_params: list[object] = []
        if filters.ap_name:
            ap_alias_clauses.append("ap_name = ?")
            ap_alias_params.append(filters.ap_name)
        elif filters.ap_names:
            placeholders = ", ".join(["?"] * len(filters.ap_names))
            ap_alias_clauses.append(f"ap_name IN ({placeholders})")
            ap_alias_params.extend(filters.ap_names)
        if filters.ap_mac:
            ap_alias_clauses.append("ap_mac = ?")
            ap_alias_params.append(filters.ap_mac)
        if ap_alias_clauses:
            clauses.append("(" + " OR ".join(ap_alias_clauses) + ")")
            params.extend(ap_alias_params)
        if filters.client_mac:
            clauses.append("client_mac = ?")
            params.append(filters.client_mac.lower())
        if filters.event_type:
            clauses.append("event_type = ?")
            params.append(filters.event_type)
        if filters.query:
            like_value = f"%{filters.query.lower()}%"
            clauses.append(
                """
                (
                    lower(coalesce(ap_name, '')) LIKE ?
                    OR lower(coalesce(client_mac, '')) LIKE ?
                    OR lower(coalesce(client_ip, '')) LIKE ?
                    OR lower(coalesce(ssid, '')) LIKE ?
                    OR lower(coalesce(reason_code, '')) LIKE ?
                    OR lower(coalesce(message, '')) LIKE ?
                    OR lower(coalesce(device_id, '')) LIKE ?
                )
                """
            )
            params.extend([like_value] * 7)
        query = f"""
            SELECT *
            FROM normalized_events
            WHERE {' AND '.join(clauses)}
            ORDER BY ts DESC
            LIMIT ?
        """
        params.append(max(1, min(filters.limit, 10000)))
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_normalized_event(row) for row in rows]

    def get_raw_records(self, raw_ids: list[int]) -> dict[int, RawSyslogRecord]:
        if not raw_ids:
            return {}
        placeholders = ", ".join(["?"] * len(raw_ids))
        query = f"SELECT * FROM raw_syslog WHERE id IN ({placeholders})"
        with self._lock:
            rows = self._conn.execute(query, raw_ids).fetchall()
        return {
            int(row["id"]): RawSyslogRecord(
                id=int(row["id"]),
                received_at=datetime.fromisoformat(row["received_at"]),
                sender_ip=row["sender_ip"],
                raw_message=row["raw_message"],
                vendor_guess=row["vendor_guess"],
                parse_status=row["parse_status"],
                parse_error=row["parse_error"],
            )
            for row in rows
        }

    def list_raw_syslog(self) -> list[RawSyslogRecord]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM raw_syslog ORDER BY id").fetchall()
        return [
            RawSyslogRecord(
                id=int(row["id"]),
                received_at=datetime.fromisoformat(row["received_at"]),
                sender_ip=row["sender_ip"],
                raw_message=row["raw_message"],
                vendor_guess=row["vendor_guess"],
                parse_status=row["parse_status"],
                parse_error=row["parse_error"],
            )
            for row in rows
        ]

    def normalized_event_timestamps_by_raw_id(self) -> dict[int, datetime]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT raw_event_id, ts
                FROM normalized_events
                WHERE raw_event_id IS NOT NULL
                """
            ).fetchall()
        return {
            int(row["raw_event_id"]): datetime.fromisoformat(row["ts"])
            for row in rows
        }

    def delete_all_normalized_events(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM normalized_events")

    def list_ap_metadata(self) -> list[APMetadata]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ap_name, vendor, ap_mac, mgmt_ip, location, model, notes FROM ap_metadata ORDER BY ap_name"
            ).fetchall()
        return [
            APMetadata(
                ap_name=row["ap_name"],
                vendor=row["vendor"],
                ap_mac=row["ap_mac"],
                mgmt_ip=row["mgmt_ip"],
                location=row["location"],
                model=row["model"],
                notes=row["notes"],
            )
            for row in rows
        ]

    def find_ap_metadata(self, ap_name: str) -> APMetadata | None:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT ap_name, vendor, ap_mac, mgmt_ip, location, model, notes
                FROM ap_metadata
                WHERE ap_name = ? OR ap_mac = ? OR mgmt_ip = ?
                ORDER BY CASE
                    WHEN ap_name = ? THEN 0
                    WHEN ap_mac = ? THEN 1
                    ELSE 2
                END
                LIMIT 1
                """,
                (ap_name, ap_name, ap_name, ap_name, ap_name),
            ).fetchone()
        if row is None:
            return None
        return APMetadata(
            ap_name=row["ap_name"],
            vendor=row["vendor"],
            ap_mac=row["ap_mac"],
            mgmt_ip=row["mgmt_ip"],
            location=row["location"],
            model=row["model"],
            notes=row["notes"],
        )

    def upsert_ap_metadata(self, metadata: APMetadata) -> None:
        with self._lock, self._conn:
            canonical_name = metadata.ap_name
            if metadata.ap_mac:
                existing_by_mac = self._conn.execute(
                    "SELECT ap_name FROM ap_metadata WHERE ap_mac = ?",
                    (metadata.ap_mac,),
                ).fetchone()
                if existing_by_mac is not None:
                    existing_name = existing_by_mac["ap_name"]
                    if self._looks_like_mac(existing_name) and not self._looks_like_mac(metadata.ap_name):
                        canonical_name = metadata.ap_name
                    else:
                        canonical_name = existing_name
                    if canonical_name != existing_name:
                        conflicting_name = self._conn.execute(
                            "SELECT ap_mac FROM ap_metadata WHERE ap_name = ?",
                            (canonical_name,),
                        ).fetchone()
                        if conflicting_name is not None and conflicting_name["ap_mac"] != metadata.ap_mac:
                            self._conn.execute(
                                """
                                UPDATE ap_metadata
                                SET vendor = ?, ap_mac = ?, mgmt_ip = ?, location = ?, model = ?, notes = ?
                                WHERE ap_name = ?
                                """,
                                (
                                    metadata.vendor,
                                    metadata.ap_mac,
                                    metadata.mgmt_ip,
                                    metadata.location,
                                    metadata.model,
                                    metadata.notes,
                                    canonical_name,
                                ),
                            )
                            self._conn.execute(
                                "DELETE FROM ap_metadata WHERE ap_mac = ? AND ap_name != ?",
                                (metadata.ap_mac, canonical_name),
                            )
                        else:
                            self._conn.execute(
                                """
                                UPDATE ap_metadata
                                SET ap_name = ?, vendor = ?, mgmt_ip = ?, location = ?, model = ?, notes = ?
                                WHERE ap_mac = ?
                                """,
                                (
                                    canonical_name,
                                    metadata.vendor,
                                    metadata.mgmt_ip,
                                    metadata.location,
                                    metadata.model,
                                    metadata.notes,
                                    metadata.ap_mac,
                                ),
                            )
                    else:
                        self._conn.execute(
                            """
                            UPDATE ap_metadata
                            SET vendor = ?, mgmt_ip = ?, location = ?, model = ?, notes = ?
                            WHERE ap_mac = ?
                            """,
                            (
                                metadata.vendor,
                                metadata.mgmt_ip,
                                metadata.location,
                                metadata.model,
                                metadata.notes,
                                metadata.ap_mac,
                            ),
                        )
                    return
                if self._looks_like_mac(metadata.ap_name):
                    canonical_name = metadata.ap_mac
            self._conn.execute(
                """
                INSERT INTO ap_metadata (ap_name, vendor, ap_mac, mgmt_ip, location, model, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ap_name) DO UPDATE SET
                    vendor = excluded.vendor,
                    ap_mac = coalesce(excluded.ap_mac, ap_metadata.ap_mac),
                    mgmt_ip = excluded.mgmt_ip,
                    location = excluded.location,
                    model = excluded.model,
                    notes = excluded.notes
                """,
                (
                    canonical_name,
                    metadata.vendor,
                    metadata.ap_mac,
                    metadata.mgmt_ip,
                    metadata.location,
                    metadata.model,
                    metadata.notes,
                ),
            )

    def canonicalize_ap_events(self, ap_mac: str, ap_name: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                UPDATE normalized_events
                SET ap_name = ?
                WHERE ap_mac = ?
                """,
                (ap_name, ap_mac),
            )

    def upsert_client_alias(self, alias: ClientAlias) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO client_aliases (client_mac, alias, notes)
                VALUES (?, ?, ?)
                ON CONFLICT(client_mac) DO UPDATE SET
                    alias = excluded.alias,
                    notes = excluded.notes
                """,
                (alias.client_mac.lower(), alias.alias, alias.notes),
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_normalized_event(row: sqlite3.Row) -> NormalizedEvent:
        return NormalizedEvent(
            id=int(row["id"]),
            ts=datetime.fromisoformat(row["ts"]),
            vendor=row["vendor"],
            device_id=row["device_id"],
            ap_name=row["ap_name"],
            ap_mac=row["ap_mac"],
            client_mac=row["client_mac"],
            client_ip=row["client_ip"],
            ssid=row["ssid"],
            band=row["band"],
            radio=row["radio"],
            channel=row["channel"],
            event_type=row["event_type"],
            severity=row["severity"],
            reason_code=row["reason_code"],
            message=row["message"],
            raw_event_id=row["raw_event_id"],
            parser_version=row["parser_version"],
        )

    @staticmethod
    def _looks_like_mac(value: str | None) -> bool:
        if value is None:
            return False
        compact = "".join(ch for ch in value if ch.isalnum())
        return len(compact) == 12 and all(ch in "0123456789abcdefABCDEF" for ch in compact)
