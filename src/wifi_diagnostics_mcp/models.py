from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class Vendor(str, Enum):
    CISCO = "cisco"
    NETGEAR = "netgear"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    CLIENT_ASSOCIATED = "client_associated"
    CLIENT_DISASSOCIATED = "client_disassociated"
    CLIENT_DEAUTHENTICATED = "client_deauthenticated"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    ROAM_SUCCESS = "roam_success"
    ROAM_FAILURE = "roam_failure"
    DHCP_ISSUE = "dhcp_issue"
    DNS_ISSUE = "dns_issue"
    POOR_RSSI = "poor_rssi"
    CHANNEL_INTERFERENCE = "channel_interference"
    AP_UP = "ap_up"
    AP_DOWN = "ap_down"
    RADAR_OR_DFS_EVENT = "radar_or_dfs_event"
    UNKNOWN_WIFI_EVENT = "unknown_wifi_event"


class ParseStatus(str, Enum):
    RECEIVED = "received"
    PARSED = "parsed"
    UNKNOWN_EVENT = "unknown_event"
    FAILED = "failed"


class Severity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(slots=True)
class RawSyslogRecord:
    id: int | None
    received_at: datetime
    sender_ip: str
    raw_message: str
    vendor_guess: str
    parse_status: str
    parse_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["received_at"] = self.received_at.isoformat()
        return data


@dataclass(slots=True)
class NormalizedEvent:
    ts: datetime
    vendor: str
    device_id: str | None
    ap_name: str | None
    ap_mac: str | None
    client_mac: str | None
    client_ip: str | None
    ssid: str | None
    band: str | None
    radio: str | None
    channel: int | None
    event_type: str
    severity: str
    reason_code: str | None
    message: str
    raw_event_id: int | None
    parser_version: str
    id: int | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ts"] = self.ts.isoformat()
        return data


@dataclass(slots=True)
class ParseOutcome:
    status: ParseStatus
    event: NormalizedEvent | None
    error: str | None = None


@dataclass(slots=True)
class APMetadata:
    ap_name: str
    vendor: str
    ap_mac: str | None = None
    mgmt_ip: str | None = None
    location: str | None = None
    model: str | None = None
    notes: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ClientAlias:
    client_mac: str
    alias: str
    notes: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SearchFilters:
    since: datetime
    until: datetime | None = None
    vendor: str | None = None
    ap_name: str | None = None
    ap_names: tuple[str, ...] | None = None
    ap_mac: str | None = None
    client_mac: str | None = None
    event_type: str | None = None
    query: str = ""
    limit: int = 50


def utc_now() -> datetime:
    return datetime.now(tz=UTC)
