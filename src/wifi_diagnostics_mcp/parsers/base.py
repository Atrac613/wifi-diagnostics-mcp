from __future__ import annotations

import re
from abc import ABC, abstractmethod
from calendar import month_abbr
from datetime import UTC, datetime, tzinfo

from ..models import EventType, NormalizedEvent, ParseOutcome, ParseStatus, RawSyslogRecord, Severity


MAC_PATTERN = re.compile(r"(?P<mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})")
IP_PATTERN = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
SSID_PATTERN = re.compile(r'(?:SSID|ssid)[ ="]+"?(?P<ssid>[^", ]+)')
SYSLOG_TS_PATTERN = re.compile(
    r"(?:<\d+>)?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.\d+)?"
)


class BaseParser(ABC):
    vendor_name = "unknown"
    parser_version = "base-1.0"

    def __init__(self, syslog_timestamp_tzinfo: tzinfo = UTC) -> None:
        self.syslog_timestamp_tzinfo = syslog_timestamp_tzinfo

    @abstractmethod
    def parse(self, record: RawSyslogRecord) -> ParseOutcome:
        raise NotImplementedError

    def build_unknown_event(
        self,
        record: RawSyslogRecord,
        vendor: str | None = None,
        error: str | None = None,
    ) -> ParseOutcome:
        return ParseOutcome(
            status=ParseStatus.UNKNOWN_EVENT,
            event=NormalizedEvent(
                ts=self.extract_timestamp(record),
                vendor=vendor or self.vendor_name,
                device_id=None,
                ap_name=self.extract_ap_name(record.raw_message),
                ap_mac=None,
                client_mac=self.extract_first_mac(record.raw_message),
                client_ip=self.extract_first_ip(record.raw_message),
                ssid=self.extract_ssid(record.raw_message),
                band=None,
                radio=None,
                channel=self.extract_channel(record.raw_message),
                event_type=EventType.UNKNOWN_WIFI_EVENT.value,
                severity=self.extract_severity(record.raw_message).value,
                reason_code=self.extract_reason_code(record.raw_message),
                message=record.raw_message,
                raw_event_id=record.id,
                parser_version=self.parser_version,
            ),
            error=error,
        )

    def make_event(
        self,
        record: RawSyslogRecord,
        *,
        event_type: EventType,
        message: str | None = None,
        device_id: str | None = None,
        ap_name: str | None = None,
        ap_mac: str | None = None,
        client_mac: str | None = None,
        client_ip: str | None = None,
        ssid: str | None = None,
        band: str | None = None,
        radio: str | None = None,
        channel: int | None = None,
        severity: Severity | None = None,
        reason_code: str | None = None,
    ) -> NormalizedEvent:
        derived_channel = channel if channel is not None else self.extract_channel(record.raw_message)
        derived_radio = radio
        derived_band = band or derive_band(derived_channel, derived_radio)
        return NormalizedEvent(
            ts=self.extract_timestamp(record),
            vendor=self.vendor_name,
            device_id=device_id or ap_name or record.sender_ip,
            ap_name=ap_name,
            ap_mac=ap_mac,
            client_mac=normalize_mac(client_mac),
            client_ip=client_ip,
            ssid=ssid,
            band=derived_band,
            radio=derived_radio,
            channel=derived_channel,
            event_type=event_type.value,
            severity=(severity or self.extract_severity(record.raw_message)).value,
            reason_code=reason_code,
            message=message or record.raw_message,
            raw_event_id=record.id,
            parser_version=self.parser_version,
        )

    def extract_timestamp(self, record: RawSyslogRecord) -> datetime:
        match = SYSLOG_TS_PATTERN.search(record.raw_message)
        if not match:
            return record.received_at.astimezone(UTC)
        values = match.groupdict()
        month = list(month_abbr).index(values["month"])
        anchor = record.received_at.astimezone(self.syslog_timestamp_tzinfo)
        candidates: list[datetime] = []
        for year in (anchor.year - 1, anchor.year, anchor.year + 1):
            try:
                candidates.append(
                    datetime(
                        year=year,
                        month=month,
                        day=int(values["day"]),
                        hour=int(values["hour"]),
                        minute=int(values["minute"]),
                        second=int(values["second"]),
                        tzinfo=self.syslog_timestamp_tzinfo,
                    )
                )
            except ValueError:
                continue
        if not candidates:
            return record.received_at.astimezone(UTC)
        parsed = min(candidates, key=lambda candidate: abs((candidate - anchor).total_seconds()))
        return parsed.astimezone(UTC)

    @staticmethod
    def extract_severity(raw_message: str) -> Severity:
        cisco = re.search(r"%[A-Z0-9_-]+-(?P<level>[0-7])-", raw_message)
        if cisco:
            mapping = {
                "0": Severity.CRITICAL,
                "1": Severity.CRITICAL,
                "2": Severity.CRITICAL,
                "3": Severity.ERROR,
                "4": Severity.WARNING,
                "5": Severity.NOTICE,
                "6": Severity.INFO,
                "7": Severity.DEBUG,
            }
            return mapping.get(cisco.group("level"), Severity.INFO)
        lowered = raw_message.lower()
        if "critical" in lowered:
            return Severity.CRITICAL
        if "error" in lowered or "failed" in lowered:
            return Severity.ERROR
        if "warning" in lowered or "deauth" in lowered:
            return Severity.WARNING
        if "notice" in lowered:
            return Severity.NOTICE
        if "debug" in lowered:
            return Severity.DEBUG
        return Severity.INFO

    @staticmethod
    def extract_first_mac(raw_message: str) -> str | None:
        match = MAC_PATTERN.search(raw_message)
        if not match:
            return None
        return normalize_mac(match.group("mac"))

    @staticmethod
    def extract_first_ip(raw_message: str) -> str | None:
        match = IP_PATTERN.search(raw_message)
        return match.group("ip") if match else None

    @staticmethod
    def extract_ssid(raw_message: str) -> str | None:
        match = SSID_PATTERN.search(raw_message)
        return match.group("ssid") if match else None

    @staticmethod
    def extract_ap_name(raw_message: str) -> str | None:
        for pattern in (
            re.compile(r'AP "(?P<ap_name>[^"]+)"'),
            re.compile(r"\bAP=(?P<ap_name>[A-Za-z0-9._-]+)"),
            re.compile(r"\bAP_NAME=(?P<ap_name>[A-Za-z0-9._-]+)"),
        ):
            match = pattern.search(raw_message)
            if match:
                return match.group("ap_name")
        return None

    @staticmethod
    def extract_channel(raw_message: str) -> int | None:
        match = re.search(r"\bchannel[ =](?P<channel>\d+)", raw_message, re.IGNORECASE)
        if match:
            return int(match.group("channel"))
        return None

    @staticmethod
    def extract_reason_code(raw_message: str) -> str | None:
        match = re.search(r"\breason(?:_code)?[ =:]+(?P<reason>[A-Za-z0-9._-]+)", raw_message, re.IGNORECASE)
        if match:
            return match.group("reason")
        return None


def normalize_mac(value: str | None) -> str | None:
    if value is None:
        return None
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) != 12:
        return value.lower()
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2)).lower()


def derive_band(channel: int | None, radio: str | None) -> str | None:
    if channel is not None:
        if channel <= 14:
            return "2.4GHz"
        if channel <= 196:
            return "5GHz"
        return "6GHz"
    if not radio:
        return None
    lowered = radio.lower()
    if "2.4" in lowered or lowered.endswith("0"):
        return "2.4GHz"
    if "5" in lowered or lowered.endswith("1"):
        return "5GHz"
    if "6" in lowered:
        return "6GHz"
    return None
