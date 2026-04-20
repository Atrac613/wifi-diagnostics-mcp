from __future__ import annotations

import re

from ..models import EventType, ParseOutcome, ParseStatus, RawSyslogRecord, Severity, Vendor
from .base import BaseParser, normalize_mac


class CiscoParser(BaseParser):
    vendor_name = Vendor.CISCO.value
    parser_version = "cisco-regex-1.3"

    _assoc = re.compile(
        r'AP "(?P<ap_name>[^"]+)".*?Interface (?P<radio>[A-Za-z0-9/]+), '
        r"Station (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) "
        r'Associated.*?SSID "(?P<ssid>[^"]+)"'
    )
    _mobility_express_assoc = re.compile(
        r"AP:(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%DOT11-6-ASSOC:\s+Interface\s+(?P<radio>\S+),\s+Station\s+"
        r"(?P<client_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?Associated"
        r"(?:\s+KEY_MGMT\[(?P<key_mgmt>[^\]]+)\])?"
    )
    _disassoc = re.compile(
        r'AP "(?P<ap_name>[^"]+)".*?Station (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) '
        r'Disassociated reason (?P<reason>\S+).*?SSID "(?P<ssid>[^"]+)"'
    )
    _mobility_express_disassoc = re.compile(
        r"AP:(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%DOT11-6-DISASSOC:\s+Interface\s+(?P<radio>\S+),\s+Deauthenticating Station\s+"
        r"(?P<client_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})\s+"
        r"(?P<reason>.+)$"
    )
    _deauth = re.compile(
        r'AP "(?P<ap_name>[^"]+)".*?Station (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) '
        r"Deauthenticated reason (?P<reason>\S+).*?SSID \"(?P<ssid>[^\"]+)\""
    )
    _auth_failure = re.compile(
        r'Station (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}).*?AP "(?P<ap_name>[^"]+)".*?'
        r'SSID "(?P<ssid>[^"]+)".*?authentication failed reason (?P<reason>\S+)'
    )
    _mobility_express_auth_failure = re.compile(
        r"(?:Cisco-|AP:)(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%DOT1X-4-MAX_EAPOL_KEY_RETRANS:.*?client\s+"
        r"(?P<client_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
    )
    _osapi_noise = re.compile(
        r"(?:Cisco-|AP:)(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%(?P<mnemonic>OSAPI-[0-9]-[A-Z0-9_]+):"
    )
    _radius_override_disabled = re.compile(
        r"(?:Cisco-|AP:)(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%(?P<mnemonic>APF-6-RADIUS_OVERRIDE_DISABLED):"
    )
    _use_default_cipher_suite = re.compile(
        r"(?:Cisco-|AP:)(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%(?P<mnemonic>APF-6-USE_DEFAULT_CIPHER_SUITE):.*?mobile\s+"
        r"(?P<client_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})"
    )
    _assocreq_proc_failed = re.compile(
        r"(?:Cisco-|AP:)(?P<ap_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}).*?"
        r"%APF-4-ASSOCREQ_PROC_FAILED:.*?association request from\s+"
        r"(?P<client_mac>(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}|(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2})\.\s+"
        r"WLAN:(?P<wlan_id>\d+),\s+SSID:(?P<ssid>[^.]+)\.\s+"
        r"(?P<reason>.*?)(?:\.\[\.\.\.|\.?$)"
    )
    _auth_success = re.compile(
        r'Station (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}).*?AP "(?P<ap_name>[^"]+)".*?'
        r'SSID "(?P<ssid>[^"]+)".*?authenticated'
    )
    _roam_failure = re.compile(
        r'Client (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) roam failed from '
        r'AP "(?P<source_ap>[^"]+)" to AP "(?P<target_ap>[^"]+)".*?SSID "(?P<ssid>[^"]+)"'
    )
    _roam_success = re.compile(
        r'Client (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) roamed successfully to '
        r'AP "(?P<target_ap>[^"]+)".*?SSID "(?P<ssid>[^"]+)"'
    )
    _poor_rssi = re.compile(
        r'AP "(?P<ap_name>[^"]+)".*?client (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}) '
        r"RSSI (?P<rssi>-?\d+).*?SSID \"(?P<ssid>[^\"]+)\""
    )
    _interference = re.compile(
        r'AP "(?P<ap_name>[^"]+)".*?(?:slot|radio) (?P<radio>\S+).*?channel (?P<channel>\d+)'
    )
    _ap_down = re.compile(r'AP "(?P<ap_name>[^"]+)".*?\b(?:is down|state down)\b')
    _ap_up = re.compile(r'AP "(?P<ap_name>[^"]+)".*?\b(?:joined controller|is up|state up)\b')
    _dfs = re.compile(r'AP "(?P<ap_name>[^"]+)".*?slot (?P<radio>\S+).*?channel (?P<channel>\d+)')
    _dhcp_issue = re.compile(
        r'Client (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}).*?SSID "(?P<ssid>[^"]+)".*?'
        r'AP "(?P<ap_name>[^"]+)".*?(?:DHCP failure|DHCP timeout|failed DHCP)'
    )
    _dns_issue = re.compile(
        r'Client (?P<client_mac>(?:[0-9A-Fa-f]{2}[:.-]){5}[0-9A-Fa-f]{2}).*?AP "(?P<ap_name>[^"]+)".*?'
        r'SSID "(?P<ssid>[^"]+)".*?(?:DNS timeout|DNS failure|DNS issue)'
    )

    def parse(self, record: RawSyslogRecord) -> ParseOutcome:
        text = record.raw_message
        for pattern, builder in (
            (self._assoc, self._build_assoc),
            (self._mobility_express_assoc, self._build_mobility_express_assoc),
            (self._disassoc, self._build_disassoc),
            (self._mobility_express_disassoc, self._build_mobility_express_disassoc),
            (self._deauth, self._build_deauth),
            (self._auth_failure, self._build_auth_failure),
            (self._mobility_express_auth_failure, self._build_mobility_express_auth_failure),
            (self._osapi_noise, self._build_osapi_noise),
            (self._radius_override_disabled, self._build_radius_override_disabled),
            (self._use_default_cipher_suite, self._build_use_default_cipher_suite),
            (self._assocreq_proc_failed, self._build_assocreq_proc_failed),
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
                built = builder(record, match)
                if isinstance(built, ParseOutcome):
                    return built
                return ParseOutcome(status=ParseStatus.PARSED, event=built)
        return self.build_unknown_event(record, vendor=self.vendor_name)

    def _build_assoc(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.CLIENT_ASSOCIATED,
            ap_name=match.group("ap_name"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            radio=match.group("radio"),
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

    def _build_mobility_express_assoc(self, record: RawSyslogRecord, match: re.Match[str]):
        ap_mac = normalize_mac(match.group("ap_mac"))
        key_mgmt = match.group("key_mgmt")
        return self.make_event(
            record,
            event_type=EventType.CLIENT_ASSOCIATED,
            device_id=ap_mac or record.sender_ip,
            ap_name=self._mobility_express_ap_name(record, ap_mac),
            ap_mac=ap_mac,
            client_mac=match.group("client_mac"),
            radio=match.group("radio"),
            severity=Severity.INFO,
            reason_code=f"key_mgmt:{key_mgmt}" if key_mgmt else None,
        )

    def _build_mobility_express_disassoc(self, record: RawSyslogRecord, match: re.Match[str]):
        ap_mac = normalize_mac(match.group("ap_mac"))
        reason = self._slug_reason(match.group("reason"))
        return self.make_event(
            record,
            event_type=EventType.CLIENT_DISASSOCIATED,
            device_id=ap_mac or record.sender_ip,
            ap_name=self._mobility_express_ap_name(record, ap_mac),
            ap_mac=ap_mac,
            client_mac=match.group("client_mac"),
            radio=match.group("radio"),
            severity=Severity.WARNING,
            reason_code=reason,
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

    def _build_mobility_express_auth_failure(self, record: RawSyslogRecord, match: re.Match[str]):
        ap_mac = normalize_mac(match.group("ap_mac"))
        return self.make_event(
            record,
            event_type=EventType.AUTH_FAILURE,
            device_id=ap_mac or record.sender_ip,
            ap_name=self._mobility_express_ap_name(record, ap_mac),
            ap_mac=ap_mac,
            client_mac=match.group("client_mac"),
            reason_code="max_eapol_key_retrans",
            severity=Severity.ERROR,
        )

    def _build_osapi_noise(self, record: RawSyslogRecord, match: re.Match[str]):
        return self._build_noise_unknown(record, match.group("ap_mac"), match.group("mnemonic"))

    def _build_radius_override_disabled(self, record: RawSyslogRecord, match: re.Match[str]):
        return self._build_noise_unknown(record, match.group("ap_mac"), match.group("mnemonic"))

    def _build_use_default_cipher_suite(self, record: RawSyslogRecord, match: re.Match[str]):
        return self._build_noise_unknown(
            record,
            match.group("ap_mac"),
            match.group("mnemonic"),
            client_mac=match.group("client_mac"),
        )

    def _build_noise_unknown(
        self,
        record: RawSyslogRecord,
        ap_mac_raw: str,
        mnemonic: str,
        *,
        client_mac: str | None = None,
    ) -> ParseOutcome:
        ap_mac = normalize_mac(ap_mac_raw)
        mnemonic = self._slug_reason(mnemonic)
        return ParseOutcome(
            status=ParseStatus.UNKNOWN_EVENT,
            event=self.make_event(
                record,
                event_type=EventType.UNKNOWN_WIFI_EVENT,
                device_id=ap_mac or record.sender_ip,
                ap_name=self._mobility_express_ap_name(record, ap_mac),
                ap_mac=ap_mac,
                client_mac=client_mac,
                severity=Severity.DEBUG,
                reason_code=f"noise:{mnemonic}" if mnemonic else "noise:osapi",
            ),
        )

    def _build_assocreq_proc_failed(self, record: RawSyslogRecord, match: re.Match[str]):
        ap_mac = normalize_mac(match.group("ap_mac"))
        reason = self._slug_reason(match.group("reason"))
        reason_code = f"assocreq_proc_failed:{reason}" if reason else "assocreq_proc_failed"
        return self.make_event(
            record,
            event_type=EventType.AUTH_FAILURE,
            device_id=ap_mac or record.sender_ip,
            ap_name=self._mobility_express_ap_name(record, ap_mac),
            ap_mac=ap_mac,
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid").strip(),
            severity=Severity.ERROR,
            reason_code=reason_code,
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
            ap_name=match.group("source_ap"),
            client_mac=match.group("client_mac"),
            ssid=match.group("ssid"),
            severity=Severity.ERROR,
            reason_code=f"target:{match.group('target_ap')}",
            message=record.raw_message,
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
            severity=Severity.WARNING,
            reason_code=f"rssi:{match.group('rssi')}",
        )

    def _build_interference(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.CHANNEL_INTERFERENCE,
            ap_name=match.group("ap_name"),
            radio=match.group("radio"),
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
            radio=match.group("radio"),
            channel=int(match.group("channel")),
            severity=Severity.WARNING,
        )

    def _build_dhcp_issue(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.DHCP_ISSUE,
            ap_name=match.group("ap_name"),
            client_mac=normalize_mac(match.group("client_mac")),
            ssid=match.group("ssid"),
            severity=Severity.ERROR,
        )

    @staticmethod
    def _slug_reason(value: str | None) -> str | None:
        if not value:
            return None
        return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")

    def _mobility_express_ap_name(self, record: RawSyslogRecord, ap_mac: str | None) -> str:
        return self.extract_ap_name(record.raw_message) or ap_mac or record.sender_ip

    def _build_dns_issue(self, record: RawSyslogRecord, match: re.Match[str]):
        return self.make_event(
            record,
            event_type=EventType.DNS_ISSUE,
            ap_name=match.group("ap_name"),
            client_mac=normalize_mac(match.group("client_mac")),
            ssid=match.group("ssid"),
            severity=Severity.ERROR,
        )
