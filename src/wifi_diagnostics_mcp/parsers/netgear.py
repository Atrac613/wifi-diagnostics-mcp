from __future__ import annotations

import re

from ..models import EventType, ParseOutcome, ParseStatus, RawSyslogRecord, Severity, Vendor
from .base import BaseParser


class NetgearParser(BaseParser):
    vendor_name = Vendor.NETGEAR.value
    parser_version = "netgear-regex-1.0"

    _assoc = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?associated.*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+).*?(?:radio[ =](?P<radio>[A-Za-z0-9._-]+))?.*?(?:channel[ =](?P<channel>\d+))?"
    )
    _disassoc = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?disassociated.*?reason[ =](?P<reason>[A-Za-z0-9._-]+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _deauth = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?deauthenticated.*?reason[ =](?P<reason>[A-Za-z0-9._-]+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _auth_failure = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?auth failed.*?reason[ =](?P<reason>[A-Za-z0-9._-]+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _auth_success = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?auth success.*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _roam_failure = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?roam failed.*?target[ =](?P<target_ap>[A-Za-z0-9._-]+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _roam_success = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?roam success.*?target[ =](?P<target_ap>[A-Za-z0-9._-]+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _poor_rssi = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?poor_rssi.*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?rssi[ =](?P<rssi>-?\d+).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _interference = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?interference detected.*?channel[ =](?P<channel>\d+)"
    )
    _ap_down = re.compile(r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?(?:state down|ap down)")
    _ap_up = re.compile(r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?(?:state up|ap up)")
    _dfs = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?(?:dfs|radar).*?channel[ =](?P<channel>\d+)"
    )
    _dhcp_issue = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?dhcp (?:timeout|failure|issue).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )
    _dns_issue = re.compile(
        r"\bAP(?:_NAME)?=(?P<ap_name>[A-Za-z0-9._-]+).*?client[ =](?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
        r".*?dns (?:timeout|failure|issue).*?ssid[ =](?P<ssid>[A-Za-z0-9._-]+)"
    )

    def parse(self, record: RawSyslogRecord) -> ParseOutcome:
        text = record.raw_message
        for pattern, builder in (
            (self._assoc, self._build_assoc),
            (self._disassoc, self._build_disassoc),
            (self._deauth, self._build_deauth),
            (self._auth_failure, self._build_auth_failure),
            (self._auth_success, self._build_auth_success),
            (self._roam_failure, self._build_roam_failure),
            (self._roam_success, self._build_roam_success),
            (self._dhcp_issue, self._build_dhcp_issue),
            (self._dns_issue, self._build_dns_issue),
            (self._poor_rssi, self._build_poor_rssi),
            (self._interference, self._build_interference),
            (self._ap_down, self._build_ap_down),
            (self._ap_up, self._build_ap_up),
            (self._dfs, self._build_dfs),
        ):
            match = pattern.search(text)
            if match:
                return ParseOutcome(status=ParseStatus.PARSED, event=builder(record, match))
        return self.build_unknown_event(record, vendor=self.vendor_name)

    def _build_assoc(self, record: RawSyslogRecord, match: re.Match[str]):
        channel = int(match.group("channel")) if match.group("channel") else None
        return self.make_event(
            record,
            event_type=EventType.CLIENT_ASSOCIATED,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            radio=match.group("radio"),
            channel=channel,
            severity=Severity.INFO,
        )

    def _build_disassoc(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.CLIENT_DISASSOCIATED,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            reason_code=match.group("reason"),
            severity=Severity.WARNING,
        )

    def _build_deauth(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.CLIENT_DEAUTHENTICATED,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            reason_code=match.group("reason"),
            severity=Severity.WARNING,
        )

    def _build_auth_failure(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.AUTH_FAILURE,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            reason_code=match.group("reason"),
            severity=Severity.ERROR,
        )

    def _build_auth_success(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.AUTH_SUCCESS,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            severity=Severity.INFO,
        )

    def _build_roam_failure(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.ROAM_FAILURE,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            reason_code=f"target:{match.group('target_ap')}",
            severity=Severity.ERROR,
        )

    def _build_roam_success(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.ROAM_SUCCESS,
            ap_name=match.group("target_ap"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            severity=Severity.INFO,
        )

    def _build_poor_rssi(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.POOR_RSSI,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            reason_code=f"rssi:{match.group('rssi')}",
            severity=Severity.WARNING,
        )

    def _build_interference(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.CHANNEL_INTERFERENCE,
            ap_name=match.group("ap_name"),
            channel=int(match.group("channel")),
            severity=Severity.WARNING,
        )

    def _build_ap_down(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.AP_DOWN,
            ap_name=match.group("ap_name"),
            severity=Severity.CRITICAL,
        )

    def _build_ap_up(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.AP_UP,
            ap_name=match.group("ap_name"),
            severity=Severity.INFO,
        )

    def _build_dfs(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.RADAR_OR_DFS_EVENT,
            ap_name=match.group("ap_name"),
            channel=int(match.group("channel")),
            severity=Severity.WARNING,
        )

    def _build_dhcp_issue(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.DHCP_ISSUE,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            severity=Severity.ERROR,
        )

    def _build_dns_issue(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.DNS_ISSUE,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            severity=Severity.ERROR,
        )
