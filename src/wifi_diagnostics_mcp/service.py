from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Any

from .analytics import WiFiAnalytics
from .config import AppConfig
from .models import APMetadata, ParseOutcome, ParseStatus, RawSyslogRecord, Vendor, utc_now
from .parsers import CiscoParser, GenericParser, NetgearParser
from .storage import Repository
from .vendor_detection import VendorDetector


logger = logging.getLogger(__name__)


class WiFiDiagnosticsService:
    def __init__(self, repository: Repository, config: AppConfig) -> None:
        self.repository = repository
        self.config = config
        self.vendor_detector = VendorDetector()
        parser_tzinfo = config.syslog_timestamp_tzinfo
        self.parsers = {
            Vendor.CISCO.value: CiscoParser(parser_tzinfo),
            Vendor.NETGEAR.value: NetgearParser(parser_tzinfo),
            Vendor.UNKNOWN.value: GenericParser(parser_tzinfo),
        }
        self.analytics = WiFiAnalytics(repository, config)

    def ingest_syslog(
        self,
        raw_message: str,
        *,
        sender_ip: str = "0.0.0.0",
        received_at: datetime | None = None,
        vendor_override: str | None = None,
    ) -> dict[str, Any]:
        timestamp = received_at or utc_now()
        vendor = self._resolve_vendor(raw_message, vendor_override)
        record = RawSyslogRecord(
            id=None,
            received_at=timestamp,
            sender_ip=sender_ip,
            raw_message=raw_message.strip(),
            vendor_guess=vendor,
            parse_status=ParseStatus.RECEIVED.value,
            parse_error=None,
        )
        raw_id = self.repository.insert_raw_syslog(record)
        record.id = raw_id

        parser = self.parsers.get(vendor, self.parsers[Vendor.UNKNOWN.value])
        try:
            outcome = parser.parse(record)
        except Exception as exc:  # pragma: no cover - defensive fallback
            unknown_event = self.parsers[Vendor.UNKNOWN.value].build_unknown_event(record, vendor=vendor)
            outcome = ParseOutcome(status=ParseStatus.FAILED, event=unknown_event.event, error=str(exc))

        self.repository.update_raw_syslog_parse(
            raw_id,
            outcome.status.value,
            vendor,
            outcome.error,
        )
        self._archive_raw_syslog(
            record=record,
            parse_status=outcome.status.value,
            parse_error=outcome.error,
            vendor=vendor,
        )

        event_id: int | None = None
        if outcome.event is not None:
            event_id = self.repository.insert_normalized_event(outcome.event)
            if outcome.event.ap_name:
                self.repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name=outcome.event.ap_name,
                        vendor=outcome.event.vendor,
                        ap_mac=outcome.event.ap_mac,
                        mgmt_ip=sender_ip,
                    )
                )

        return {
            "raw_event_id": raw_id,
            "normalized_event_id": event_id,
            "vendor_detected": vendor,
            "parse_status": outcome.status.value,
            "event_type": outcome.event.event_type if outcome.event else None,
            "parse_error": outcome.error,
        }

    def ingest_sample_logs(self, file_path: str, vendor: str | None = None) -> dict[str, Any]:
        path = self._resolve_sample_log_path(file_path)

        total_lines = 0
        parsed_lines = 0
        failed_lines = 0
        detected_vendors: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            total_lines += 1
            result = self.ingest_syslog(stripped, sender_ip="127.0.0.1", vendor_override=vendor)
            detected_vendors.append(result["vendor_detected"])
            if result["parse_status"] in {ParseStatus.PARSED.value, ParseStatus.UNKNOWN_EVENT.value}:
                parsed_lines += 1
            else:
                failed_lines += 1

        return {
            "total_lines": total_lines,
            "parsed_lines": parsed_lines,
            "failed_lines": failed_lines,
            "vendor_detected": Counter(detected_vendors).most_common(1)[0][0] if detected_vendors else vendor or "unknown",
            "sample_normalized_events": self.analytics.search_wifi_events(
                limit=5,
                minutes=24 * 60,
                vendor=vendor.lower() if vendor else None,
            ),
        }

    def _resolve_sample_log_path(self, file_path: str) -> Path:
        candidate = Path(file_path).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        resolved = candidate.resolve()
        allowed_roots = tuple(root.expanduser().resolve() for root in self.config.sample_log_roots)
        if not any(resolved == root or root in resolved.parents for root in allowed_roots):
            allowed_display = ", ".join(str(root) for root in allowed_roots)
            raise PermissionError(
                "sample log ingestion is restricted to configured sample roots: "
                f"{allowed_display}"
            )
        if not resolved.exists() or not resolved.is_file():
            raise FileNotFoundError(f"sample log file not found: {file_path}")
        return resolved

    def get_wifi_health(self, minutes: int | None = None) -> dict[str, Any]:
        return self.analytics.get_wifi_health(minutes or self.config.default_lookback_minutes)

    def compare_wifi_windows(self, window_minutes: int = 5) -> dict[str, Any]:
        return self.analytics.compare_wifi_windows(window_minutes)

    def get_ap_status(self, ap_name: str, minutes: int = 30) -> dict[str, Any]:
        return self.analytics.get_ap_status(ap_name, minutes)

    def get_client_instability(self, client_mac: str, minutes: int = 60) -> dict[str, Any]:
        return self.analytics.get_client_instability(client_mac, minutes)

    def get_auth_failures(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        return self.analytics.get_auth_failures(minutes, top_n)

    def get_disconnect_reasons(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        return self.analytics.get_disconnect_reasons(minutes, top_n)

    def get_roaming_issues(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        return self.analytics.get_roaming_issues(minutes, top_n)

    def search_wifi_events(self, **kwargs: Any) -> dict[str, Any]:
        return {"matched_events": self.analytics.search_wifi_events(**kwargs)}

    def explain_network_slowdown_context(self, lookback_minutes: int = 30) -> dict[str, Any]:
        return self.analytics.explain_network_slowdown_context(lookback_minutes)

    def parser_inventory(self) -> list[dict[str, str]]:
        return [
            {
                "vendor": vendor,
                "parser": parser.__class__.__name__,
                "parser_version": parser.parser_version,
            }
            for vendor, parser in self.parsers.items()
        ]

    def list_ap_metadata(self) -> list[dict[str, Any]]:
        return [item.as_dict() for item in self.repository.list_ap_metadata()]

    def find_ap_metadata(self, ap_name: str) -> dict[str, Any] | None:
        finder = getattr(self.repository, "find_ap_metadata", None)
        if finder is None:
            return None
        item = finder(ap_name)
        return item.as_dict() if item else None

    def top_unstable_clients(self) -> list[dict[str, Any]]:
        return self.analytics.top_unstable_clients(self.config.default_lookback_minutes)

    def _resolve_vendor(self, raw_message: str, vendor_override: str | None) -> str:
        if vendor_override:
            normalized = vendor_override.strip().lower()
            if normalized in self.parsers:
                return normalized
        if self.config.enable_vendor_auto_detect:
            return self.vendor_detector.detect(raw_message).value
        return Vendor.UNKNOWN.value

    def _archive_raw_syslog(
        self,
        *,
        record: RawSyslogRecord,
        parse_status: str,
        parse_error: str | None,
        vendor: str,
    ) -> None:
        archive_path = self.config.raw_syslog_archive_path
        if archive_path is None:
            return
        try:
            archive_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "id": record.id,
                "received_at": record.received_at.isoformat(),
                "sender_ip": record.sender_ip,
                "vendor_guess": vendor,
                "parse_status": parse_status,
                "parse_error": parse_error,
                "raw_message": record.raw_message,
            }
            with archive_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except OSError as exc:  # pragma: no cover - defensive logging path
            logger.warning("failed to archive raw syslog to %s: %s", archive_path, exc)
