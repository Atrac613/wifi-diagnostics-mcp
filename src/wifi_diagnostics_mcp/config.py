from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import tzinfo
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_HEALTH_SCORE_THRESHOLDS: dict[str, Any] = {
    "observation_floor": 5,
    "insufficient_data_ceiling": 72,
    "weights": {
        "auth_failure": 6,
        "client_disassociated": 4,
        "client_deauthenticated": 5,
        "roam_failure": 7,
        "ap_down": 22,
        "poor_rssi": 3,
        "channel_interference": 5,
        "dhcp_issue": 6,
        "dns_issue": 4,
        "unknown_wifi_event": 1,
    },
    "issue_trigger_count": 3,
}

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLE_LOG_ROOTS: tuple[Path, ...] = (PROJECT_ROOT / "tests" / "fixtures",)


@dataclass(slots=True)
class AppConfig:
    syslog_udp_port: int = 5514
    syslog_tcp_port: int = 5515
    syslog_timestamp_timezone: str = "UTC"
    db_path: Path = Path("wifi_diagnostics.db")
    raw_syslog_archive_path: Path | None = None
    sample_log_roots: tuple[Path, ...] = field(default_factory=lambda: DEFAULT_SAMPLE_LOG_ROOTS)
    enable_dev_tools: bool = False
    enable_tcp_syslog: bool = False
    enable_http_mcp: bool = False
    mcp_http_host: str = "127.0.0.1"
    mcp_http_port: int = 8765
    mcp_http_auth_token: str | None = None
    mcp_http_allowed_origins: tuple[str, ...] = ()
    default_lookback_minutes: int = 30
    health_score_thresholds: dict[str, Any] = field(
        default_factory=lambda: dict(DEFAULT_HEALTH_SCORE_THRESHOLDS)
    )
    enable_vendor_auto_detect: bool = True
    supported_vendors: tuple[str, ...] = ("cisco", "netgear")

    @classmethod
    def from_env(cls) -> "AppConfig":
        raw_thresholds = os.getenv("HEALTH_SCORE_THRESHOLDS", "").strip()
        thresholds = dict(DEFAULT_HEALTH_SCORE_THRESHOLDS)
        if raw_thresholds:
            loaded = json.loads(raw_thresholds)
            thresholds = _deep_merge_dicts(thresholds, loaded)
        return cls(
            syslog_udp_port=int(os.getenv("SYSLOG_UDP_PORT", "5514")),
            syslog_tcp_port=int(os.getenv("SYSLOG_TCP_PORT", "5515")),
            syslog_timestamp_timezone=os.getenv("SYSLOG_TIMESTAMP_TIMEZONE", "UTC"),
            db_path=Path(os.getenv("DB_PATH", "wifi_diagnostics.db")),
            raw_syslog_archive_path=_optional_path_env("RAW_SYSLOG_ARCHIVE_PATH"),
            sample_log_roots=_path_list_env("SAMPLE_LOG_ROOTS", DEFAULT_SAMPLE_LOG_ROOTS),
            enable_dev_tools=_env_bool("ENABLE_DEV_TOOLS", False),
            enable_tcp_syslog=_env_bool("ENABLE_TCP_SYSLOG", False),
            enable_http_mcp=_env_bool("ENABLE_HTTP_MCP", False),
            mcp_http_host=os.getenv("MCP_HTTP_HOST", "127.0.0.1"),
            mcp_http_port=int(os.getenv("MCP_HTTP_PORT", "8765")),
            mcp_http_auth_token=_optional_str_env("MCP_HTTP_AUTH_TOKEN"),
            mcp_http_allowed_origins=_csv_env("MCP_HTTP_ALLOWED_ORIGINS"),
            default_lookback_minutes=int(os.getenv("DEFAULT_LOOKBACK_MINUTES", "30")),
            health_score_thresholds=thresholds,
            enable_vendor_auto_detect=_env_bool("ENABLE_VENDOR_AUTO_DETECT", True),
        )

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["db_path"] = str(self.db_path)
        data["raw_syslog_archive_path"] = (
            str(self.raw_syslog_archive_path) if self.raw_syslog_archive_path else None
        )
        data["sample_log_roots"] = [str(path) for path in self.sample_log_roots]
        data["mcp_http_auth_token_configured"] = self.mcp_http_auth_token is not None
        data["mcp_http_allowed_origins"] = list(self.mcp_http_allowed_origins)
        data.pop("mcp_http_auth_token", None)
        return data

    @property
    def syslog_timestamp_tzinfo(self) -> tzinfo:
        try:
            return ZoneInfo(self.syslog_timestamp_timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(
                f"invalid SYSLOG_TIMESTAMP_TIMEZONE: {self.syslog_timestamp_timezone}"
            ) from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _optional_path_env(name: str) -> Path | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        return None
    return Path(value)


def _optional_str_env(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    value = raw.strip()
    return value or None


def _path_list_env(name: str, default: tuple[Path, ...]) -> tuple[Path, ...]:
    raw = os.getenv(name)
    if raw is None:
        return default
    values = tuple(
        Path(part.strip()).expanduser()
        for part in raw.split(os.pathsep)
        if part.strip()
    )
    return values or default


def _csv_env(name: str) -> tuple[str, ...]:
    raw = os.getenv(name)
    if raw is None:
        return ()
    values = tuple(part.strip() for part in raw.split(",") if part.strip())
    return values


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged
