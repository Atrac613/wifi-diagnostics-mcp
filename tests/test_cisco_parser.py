from __future__ import annotations

import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.config import AppConfig
from wifi_diagnostics_mcp.models import APMetadata, EventType, RawSyslogRecord, utc_now
from wifi_diagnostics_mcp.parsers.cisco import CiscoParser
from wifi_diagnostics_mcp.service import WiFiDiagnosticsService
from wifi_diagnostics_mcp.storage import SQLiteRepository


class CiscoParserTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = CiscoParser()
        self.fixture_lines = (
            (ROOT / "tests" / "fixtures" / "cisco" / "sample.log")
            .read_text(encoding="utf-8")
            .splitlines()
        )

    def test_client_association_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=1,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message=self.fixture_lines[0],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_ASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "AP-Lobby")
        self.assertEqual(outcome.event.client_mac, "aa:bb:cc:dd:ee:01")
        self.assertEqual(outcome.event.ssid, "CorpWiFi")
        self.assertEqual(outcome.event.band, "2.4GHz")

    def test_auth_failure_has_reason_code(self) -> None:
        record = RawSyslogRecord(
            id=2,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message=self.fixture_lines[1],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.reason_code, "23")
        self.assertEqual(outcome.event.severity, "error")

    def test_unknown_event_falls_back_to_unknown_wifi_event(self) -> None:
        record = RawSyslogRecord(
            id=3,
            received_at=utc_now(),
            sender_ip="198.51.100.10",
            raw_message='%LINK-6-UPDOWN: AP "AP-Lobby" uplink changed state',
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(outcome.status.value, "unknown_event")
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)

    def test_mobility_express_assoc_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=4,
            received_at=utc_now(),
            sender_ip="198.51.100.20",
            raw_message=self.fixture_lines[9],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_ASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.client_mac, "c2:b2:f9:fd:f9:1f")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "key_mgmt:Open")

    def test_mobility_express_eapol_retrans_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=5,
            received_at=utc_now(),
            sender_ip="198.51.100.21",
            raw_message=self.fixture_lines[10],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "ae:b0:9e:57:34:8c")
        self.assertEqual(outcome.event.reason_code, "max_eapol_key_retrans")
        self.assertEqual(outcome.event.severity, "error")

    def test_mobility_express_invalid_replay_counter_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=51,
            received_at=utc_now(),
            sender_ip="198.51.100.28",
            raw_message=(
                "<131>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 21 09:53:13.456: "
                "%DOT1X-3-INVALID_REPLAY_CTR: 1x_eapkey.c:458 Invalid replay counter "
                "from client e2:c9:fa:b6:ff:47 - got 00 00 00 00 00 00 00 02, expected "
                "00 00 00 00 00 00 00 03"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "e2:c9:fa:b6:ff:47")
        self.assertEqual(outcome.event.reason_code, "invalid_replay_counter")
        self.assertEqual(outcome.event.severity, "error")

    def test_mobility_express_dot1x_failures_are_auth_failures(self) -> None:
        cases = (
            (
                (
                    "<132>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 21 09:22:23.685: "
                    "%DOT1X-4-MAX_EAP_RETRIES: 1x_auth_pae.c:6768 Max EAP identity "
                    "request retries (3) exceeded for client 50:14:79:25:f4:12"
                ),
                "max_eap_retries",
            ),
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 21 17:49:07.643: "
                    "%DOT1X-3-INVALID_WPA_KEY_STATE: 1x_eapkey.c:3080 Received EAPOL-key "
                    "message while in invalid state (0) - version 1, type 3, descriptor 2, "
                    "client ae:b0:9e:57:34:8c"
                ),
                "invalid_wpa_key_state",
            ),
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 07:16:45.312: "
                    "%APF-3-PREAUTH_FAILURE: apf_80211.c:15788 There is no PMK cache entry "
                    "for clientd4:e2:cb:11:22:33. Can't do preauth"
                ),
                "preauth_failure",
            ),
            (
                (
                    "<4>16579: AP:00f8.2c26.6580: *Apr 21 21:32:42.075: "
                    "%DOT11-4-CCMP_REPLAY: Client d4:e2:cb:11:22:33 had 1 AES-CCMP TSC replays"
                ),
                "ccmp_replay",
            ),
        )
        for raw_message, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=56,
                    received_at=utc_now(),
                    sender_ip="198.51.100.34",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "parsed")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, "error")

    def test_mobile_excluded_identity_theft_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=57,
            received_at=utc_now(),
            sender_ip="198.51.100.34",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *apfReceiveTask: Apr 21 06:50:15.012: "
                "%APF-6-MOBILE_EXCLUDED: apf_ms.c:7192 Excluded the mobile d4:e2:cb:11:22:33 "
                'Reason: "Identity Theft"'
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "d4:e2:cb:11:22:33")
        self.assertEqual(outcome.event.reason_code, "mobile_excluded:identity_theft")
        self.assertEqual(outcome.event.severity, "error")

    def test_identity_theft_ip_registration_failure_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=60,
            received_at=utc_now(),
            sender_ip="198.51.100.34",
            raw_message=(
                "<132>Cisco-00f8.2c26.6580: *apfReceiveTask: Apr 21 06:50:15.012: "
                "%APF-4-REGISTER_IPADD_ON_MSCB_FAILED: apf_foreignap.c:1978 Could not "
                "Register IP Add on MSCB. Identity theft alert for IP address. mobility "
                "state, apfMsMmInitial and client state, APF_MS_STATE_ASSOCIATEDaddress: "
                "d4:e2:cb:11:22:33"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "d4:e2:cb:11:22:33")
        self.assertEqual(outcome.event.reason_code, "identity_theft_ip_registration_failed")
        self.assertEqual(outcome.event.severity, "error")

    def test_capwap_and_lwapp_echo_timer_expiry_are_ap_down(self) -> None:
        cases = (
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *spamApTask0: Apr 22 17:34:52.872: "
                    "%CAPWAP-3-DTLS_CLOSED_ERR: capwap_ac_sm.c:7521 00f8.2c26.6580: "
                    "DTLS connection closed forAP 192.168.100.14 (5272), Controller: "
                    "192.168.100.200 (5246) Echo Timer Expiry"
                ),
                "capwap_dtls_closed:echo_timer_expiry",
            ),
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *spamApTask0: Apr 22 17:34:52.876: "
                    "%LWAPP-3-AP_DEL: spam_lrad.c:6090 00f8.2c26.6580: Entry deleted "
                    "for AP: 192.168.100.14 (5272) reason : Echo Timer Expiry."
                ),
                "lwapp_ap_deleted:echo_timer_expiry",
            ),
        )
        for raw_message, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=61,
                    received_at=utc_now(),
                    sender_ip="198.51.100.34",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "parsed")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.AP_DOWN.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, "critical")

    def test_osapi_events_are_tagged_as_noise_unknowns(self) -> None:
        record = RawSyslogRecord(
            id=6,
            received_at=utc_now(),
            sender_ip="198.51.100.24",
            raw_message=(
                "<133>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 20 19:36:58.903: "
                "%OSAPI-5-MUTEX_UNLOCK_FAILED: osapi_sem.c:1253 Failed to release a mutual "
                "exclusion object. mutex unlock failed"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "noise:osapi_5_mutex_unlock_failed")
        self.assertEqual(outcome.event.severity, "debug")

    def test_radius_override_disabled_is_tagged_as_noise_unknown(self) -> None:
        cases = (
            "<134>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 20 19:37:50.888: "
            "%APF-6-RADIUS_OVERRIDE_DISABLED: apf_ms_radius_override.c:213 "
            "Radius overrides disabled, ignoring source 4",
            "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 24 10:24:34.590: "
            "%LOG-6-Q_IND: apf_ms_radius_override.c:213 Radius overrides disabled, "
            "ignoring source 4",
        )
        for raw_message in cases:
            with self.subTest(raw_message=raw_message):
                record = RawSyslogRecord(
                    id=7,
                    received_at=utc_now(),
                    sender_ip="198.51.100.25",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "unknown_event")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, "noise:apf_6_radius_override_disabled")
                self.assertEqual(outcome.event.severity, "debug")

    def test_mm_member_sanity_zero_node_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=62,
            received_at=utc_now(),
            sender_ip="198.51.100.25",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *fp_main_task: Apr 20 13:37:25.687: "
                "%MM-6-MEMBER_CFGSANITY_ZERONODE: mm_dir.c:2838 Ignoring Invalid mmCfg "
                "entry from mmdb. Not to panic and no further action needed. i=0,k=72,Cnt=1"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "noise:mm_6_member_cfgsanity_zeronode")
        self.assertEqual(outcome.event.severity, "debug")

    def test_controller_startup_events_are_tagged_as_noise_unknowns(self) -> None:
        cases = (
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *Bonjour_Socket_Task: Apr 20 13:37:31.924: "
                    "%SOCKET_TASK-6-STARTING: socket_task.c:70 Starting socket task for protocol 21"
                ),
                "noise:socket_task_6_starting",
            ),
            (
                (
                    "<135>Cisco-00f8.2c26.6580: *sntpReceiveTask: Apr 21 09:09:17.820: "
                    "%SNTP-7-SET_HW_TIME: timing.c:139 Setting hardware time to 2026 4 25 00:09:17"
                ),
                "noise:sntp_7_set_hw_time",
            ),
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *fp_main_task: Apr 20 13:37:22.514: "
                    "%CCX-6-MSGTAG014: ccx_rm_task.c:62 Created CCX RM Task"
                ),
                "noise:ccx_6_msgtag014",
            ),
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *spamApTask0: Apr 22 17:38:10.739: "
                    "%DTLS-5-ESTABLISHED_TO_PEER: openssl_dtls.c:914 DTLS connection established to 192.0.2.14"
                ),
                "noise:dtls_5_established_to_peer",
            ),
        )
        for raw_message, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=63,
                    received_at=utc_now(),
                    sender_ip="198.51.100.25",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "unknown_event")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, "debug")

    def test_wme_addts_issues_are_preserved_with_reason_codes(self) -> None:
        cases = (
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 09:20:55.278: "
                    "%APF-6-PROCESS_WME_ADDTS_REQ_FAILED: apf_wme_utils.c:5872 Could not "
                    "Process the WME ADDTS Command. Error parsing ADD TS Request from "
                    "STA.STA:50:14:79:25:f4:12 -- IE Tpye:103. IELength:208.DataLen: 69"
                ),
                "wme:addts_request_parse_failed",
            ),
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 04:11:53.180: "
                    "%APF-6-NULL_DATA_IN_ADDTS_REQ: apf_wme_utils.c:5855 NULL data in "
                    "ADD TS Request from STA ae:b0:9e:57:34:8c -- dataLen 2"
                ),
                "wme:addts_request_null_data",
            ),
        )
        for raw_message, reason_code in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=64,
                    received_at=utc_now(),
                    sender_ip="198.51.100.26",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "unknown_event")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, "info")

    def test_client_state_cleanup_events_have_reason_codes(self) -> None:
        cases = (
            (
                (
                    "<132>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 22 12:44:21.113: "
                    "%APF-4-RCV_INVALID_ACTION_CODE: apf_80211v.c:1928 Received invalid "
                    "action code 0 from mobile station 50:14:79:25:f4:12"
                ),
                "client_state:invalid_action_code",
                "warning",
            ),
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 20 15:39:39.510: "
                    "%DOT1X-3-CLIENT_NOT_FOUND: dot1x_msg_task.c:1847 Unable to process "
                    "802.1X 8 msg - client ae:b0:9e:57:34:8c not found"
                ),
                "client_state:dot1x_client_not_found",
                "error",
            ),
            (
                (
                    "<134>Cisco-00f8.2c26.6580: *apfReceiveTask: Apr 21 14:14:45.608: "
                    "%APF-6-AID_STALE_STA: apf_80211.c:18219 Found invalid client: "
                    "d4:e2:cb:11:22:33 on AP: 00f8.2c26.6580 slot 0, AID 8 wlan 2. "
                    "Deleting this client from WLC database"
                ),
                "client_state:aid_stale_station",
                "info",
            ),
        )
        for raw_message, reason_code, severity in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=65,
                    received_at=utc_now(),
                    sender_ip="198.51.100.26",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "unknown_event")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, severity)

    def test_control_plane_events_have_reason_codes(self) -> None:
        cases = (
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *spamReceiveTask: Apr 24 22:00:19.764: "
                    "%LWAPP-3-WLAN_ERR2: spam_lrad.c:40402 The system is unable to find "
                    "WLAN 5 in Slot 1 to be deleted; AP 00f8.2c26.6580"
                ),
                "control_plane:lwapp_3_wlan_err2",
                "error",
            ),
            (
                (
                    "<132>Cisco-00f8.2c26.6580: *apfReceiveTask: Apr 22 17:38:11.125: "
                    "%CAPWAP-4-INVALID_STATE_EVENT: capwap_ac_sm.c:9292 The system detects "
                    "an invalid AP(00f8.2c26.6580) event (Capwap_configuration_update_request) "
                    "and state (Capwap_join) combination"
                ),
                "control_plane:capwap_4_invalid_state_event",
                "warning",
            ),
            (
                (
                    "<131>Cisco-00f8.2c26.6580: *CAPWAP DATA: Apr 22 17:35:07.581: "
                    "%RRM-3-RRM_LOGMSG: rrmClient.c:1362 RRM LOG: iapp chd, "
                    "Unable to find AP 00f8.2c26.6580"
                ),
                "control_plane:rrm_unable_to_find_ap",
                "error",
            ),
        )
        for raw_message, reason_code, severity in cases:
            with self.subTest(reason_code=reason_code):
                record = RawSyslogRecord(
                    id=66,
                    received_at=utc_now(),
                    sender_ip="198.51.100.26",
                    raw_message=raw_message,
                    vendor_guess="cisco",
                    parse_status="received",
                )
                outcome = self.parser.parse(record)
                self.assertEqual(outcome.status.value, "unknown_event")
                assert outcome.event is not None
                self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
                self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
                self.assertEqual(outcome.event.reason_code, reason_code)
                self.assertEqual(outcome.event.severity, severity)

    def test_default_cipher_suite_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=8,
            received_at=utc_now(),
            sender_ip="198.51.100.26",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 20 19:37:28.624: "
                "%APF-6-USE_DEFAULT_CIPHER_SUITE: apf_rsn_utils.c:3136 Using default settings "
                "for Group Management Cipher Suite for mobile 50:14:79:25:f4:12"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:25:f4:12")
        self.assertEqual(outcome.event.reason_code, "noise:apf_6_use_default_cipher_suite")
        self.assertEqual(outcome.event.severity, "debug")

    def test_assocreq_proc_failed_is_mapped_to_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=9,
            received_at=utc_now(),
            sender_ip="198.51.100.22",
            raw_message=self.fixture_lines[11],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:25:f4:12")
        self.assertEqual(outcome.event.ssid, "ChaCha")
        self.assertEqual(
            outcome.event.reason_code,
            "assocreq_proc_failed:max_sta_load_balance_decision_failure",
        )
        self.assertEqual(outcome.event.severity, "error")

    def test_mobility_express_disassoc_is_normalized(self) -> None:
        record = RawSyslogRecord(
            id=10,
            received_at=utc_now(),
            sender_ip="198.51.100.23",
            raw_message=self.fixture_lines[12],
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_DISASSOCIATED.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.client_mac, "b0:95:75:f5:19:a2")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "sending_station_has_left_the_bss")
        self.assertEqual(outcome.event.severity, "warning")

    def test_mobility_express_disassoc_without_reason_is_deauth(self) -> None:
        record = RawSyslogRecord(
            id=58,
            received_at=utc_now(),
            sender_ip="198.51.100.35",
            raw_message=(
                "<6>13319: AP:00f6.6353.1418: *Apr 20 23:00:25.871: "
                "%DOT11-6-DISASSOC: Interface Dot11Radio0, Deauthenticating Station "
                "7c87.ce81.2290"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.CLIENT_DEAUTHENTICATED.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.client_mac, "7c:87:ce:81:22:90")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "deauthenticating_station")
        self.assertEqual(outcome.event.severity, "warning")

    def test_expected_radio_reset_is_normalized_as_ap_down(self) -> None:
        record = RawSyslogRecord(
            id=52,
            received_at=utc_now(),
            sender_ip="198.51.100.29",
            raw_message=(
                "<5>13352: AP:00f6.6353.1418: *Apr 21 00:50:57.427: "
                "%DOT11-5-EXPECTED_RADIO_RESET: Restarting Radio interface Dot11Radio1 "
                "due to the reason code 56"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AP_DOWN.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.radio, "Dot11Radio1")
        self.assertEqual(outcome.event.reason_code, "radio_reset:56")
        self.assertEqual(outcome.event.severity, "warning")

    def test_radio_link_updown_is_normalized(self) -> None:
        down_record = RawSyslogRecord(
            id=53,
            received_at=utc_now(),
            sender_ip="198.51.100.30",
            raw_message=(
                "<6>13353: AP:00f6.6353.1418: *Apr 21 00:50:57.443: "
                "%LINK-6-UPDOWN: Interface Dot11Radio1, changed state to down"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        down_outcome = self.parser.parse(down_record)
        self.assertEqual(down_outcome.status.value, "parsed")
        assert down_outcome.event is not None
        self.assertEqual(down_outcome.event.event_type, EventType.AP_DOWN.value)
        self.assertEqual(down_outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(down_outcome.event.radio, "Dot11Radio1")
        self.assertEqual(down_outcome.event.reason_code, "radio_state:down")
        self.assertEqual(down_outcome.event.severity, "warning")

        up_record = RawSyslogRecord(
            id=54,
            received_at=utc_now(),
            sender_ip="198.51.100.31",
            raw_message=(
                "<5>13357: AP:00f6.6353.1418: *Apr 21 00:50:59.487: "
                "%LINEPROTO-5-UPDOWN: Line protocol on Interface Dot11Radio1, changed state to up"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        up_outcome = self.parser.parse(up_record)
        self.assertEqual(up_outcome.status.value, "parsed")
        assert up_outcome.event is not None
        self.assertEqual(up_outcome.event.event_type, EventType.AP_UP.value)
        self.assertEqual(up_outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(up_outcome.event.radio, "Dot11Radio1")
        self.assertEqual(up_outcome.event.reason_code, "radio_state:up")
        self.assertEqual(up_outcome.event.severity, "info")

    def test_radio_link_reset_is_normalized_as_ap_down(self) -> None:
        record = RawSyslogRecord(
            id=55,
            received_at=utc_now(),
            sender_ip="198.51.100.32",
            raw_message=(
                "<5>13354: AP:00f6.6353.1418: *Apr 21 00:50:57.451: "
                "%LINK-5-CHANGED: Interface Dot11Radio1, changed state to reset"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AP_DOWN.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.radio, "Dot11Radio1")
        self.assertEqual(outcome.event.reason_code, "radio_state:reset")
        self.assertEqual(outcome.event.severity, "warning")

    def test_log_q_ind_assocreq_is_normalized_as_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=59,
            received_at=utc_now(),
            sender_ip="198.51.100.36",
            raw_message=(
                "<132>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 08:00:32.860: "
                "%LOG-4-Q_IND: apf_80211.c:11180 Failed to process an association request "
                "from 50:14:79:21:7e:7c. WLAN:2, SSID:ChaCha. "
                "Max Sta - Load balance decision failure."
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:21:7e:7c")
        self.assertEqual(outcome.event.ssid, "ChaCha")
        self.assertEqual(
            outcome.event.reason_code,
            "assocreq_proc_failed:max_sta_load_balance_decision_failure",
        )
        self.assertEqual(outcome.event.severity, "error")

    def test_log_q_ind_default_cipher_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=61,
            received_at=utc_now(),
            sender_ip="198.51.100.38",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *spamApTask0: Apr 21 10:15:39.358: "
                "%LOG-6-Q_IND: apf_rsn_utils.c:3136 Using default settings for Group "
                "Management Cipher Suite for mobile 50:14:79:c8:69:55"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:c8:69:55")
        self.assertEqual(outcome.event.reason_code, "noise:apf_6_use_default_cipher_suite")
        self.assertEqual(outcome.event.severity, "debug")

    def test_assoc_req_failed_radio_not_enabled_is_auth_failure(self) -> None:
        record = RawSyslogRecord(
            id=62,
            received_at=utc_now(),
            sender_ip="198.51.100.39",
            raw_message=(
                "<131>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 08:00:29.931: "
                "%APF-3-ASSOC_REQ_FAILED: apf_80211.c:10492 Ignoring 802.11 assoc request "
                "from mobile 7c:87:ce:81:22:90 Since Dot11Radio 0 is not Enabled for "
                "AP:AP00f6.6353.1418 MAC:00:81:c4:f6:42:10"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.AUTH_FAILURE.value)
        self.assertEqual(outcome.event.ap_name, "AP00f6.6353.1418")
        self.assertEqual(outcome.event.ap_mac, "00:81:c4:f6:42:10")
        self.assertEqual(outcome.event.client_mac, "7c:87:ce:81:22:90")
        self.assertEqual(outcome.event.radio, "Dot11Radio0")
        self.assertEqual(outcome.event.reason_code, "assoc_req_failed:radio_not_enabled")
        self.assertEqual(outcome.event.severity, "error")

    def test_mobile_station_not_found_is_low_priority_unknown(self) -> None:
        record = RawSyslogRecord(
            id=64,
            received_at=utc_now(),
            sender_ip="198.51.100.41",
            raw_message=(
                "<132>Cisco-00f8.2c26.6580: *spamApTask0: Apr 21 10:15:39.358: "
                "%APF-4-MOBILESTATION_NOT_FOUND: apf_api.c:57734 Could not find the mobile "
                "50:14:79:c8:69:55 in internal database"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "50:14:79:c8:69:55")
        self.assertEqual(outcome.event.reason_code, "mobile_station_not_found")
        self.assertEqual(outcome.event.severity, "info")

    def test_safec_error_is_auxiliary_unknown(self) -> None:
        record = RawSyslogRecord(
            id=65,
            received_at=utc_now(),
            sender_ip="198.51.100.42",
            raw_message=(
                "<131>Cisco-00f8.2c26.6580: *apfMsConnTask_0: Apr 21 08:12:36.103: "
                "%SAFEC-3-SAFEC_ERROR: safecWrapper.c:57 DATA INCONSISTENCY: (22) "
                "memcpy_s: n exceeds dmax"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "safec_error:memcpy_s_n_exceeds_dmax")
        self.assertEqual(outcome.event.severity, "warning")

    def test_dot1x_11r_forced_auth_is_normalized_as_roam_success(self) -> None:
        record = RawSyslogRecord(
            id=60,
            received_at=utc_now(),
            sender_ip="198.51.100.37",
            raw_message=(
                "<134>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Apr 21 08:12:36.110: "
                "%DOT1X-6-11R_FORCED_AUTH: 1x_auth_pae.c:7564 FT Auth successful. "
                "Moving client 12:96:21:e3:ff:b5 to forced auth state"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "parsed")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.ROAM_SUCCESS.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.client_mac, "12:96:21:e3:ff:b5")
        self.assertEqual(outcome.event.reason_code, "ft_auth_success")
        self.assertEqual(outcome.event.severity, "info")

    def test_admin_auth_success_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=63,
            received_at=utc_now(),
            sender_ip="198.51.100.40",
            raw_message=(
                "<133>Cisco-00f8.2c26.6580: *emWeb: Apr 21 09:47:44.436: "
                "%AAA-5-AAA_AUTH_ADMIN_USER: aaa.c:3334 Authentication succeeded for "
                "admin user 'atrac' on 91.100.168.192"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.ap_mac, "00:f8:2c:26:65:80")
        self.assertEqual(outcome.event.reason_code, "noise:aaa_auth_admin_user")
        self.assertEqual(outcome.event.severity, "debug")

    def test_cleanair_enabled_is_tagged_as_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=56,
            received_at=utc_now(),
            sender_ip="198.51.100.33",
            raw_message=(
                "<6>13359: AP:00f6.6353.1418: *Apr 21 00:51:26.967: "
                "%CLEANAIR-6-STATE: Slot 1 enabled"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.radio, "Slot1")
        self.assertEqual(outcome.event.reason_code, "noise:cleanair_state_slot_1_enabled")
        self.assertEqual(outcome.event.severity, "debug")

    def test_cleanair_down_is_preserved_as_non_noise_unknown(self) -> None:
        record = RawSyslogRecord(
            id=57,
            received_at=utc_now(),
            sender_ip="198.51.100.34",
            raw_message=(
                "<6>13358: AP:00f6.6353.1418: *Apr 21 00:51:10.199: "
                "%CLEANAIR-6-STATE: Slot 1 down"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = self.parser.parse(record)
        self.assertEqual(outcome.status.value, "unknown_event")
        assert outcome.event is not None
        self.assertEqual(outcome.event.event_type, EventType.UNKNOWN_WIFI_EVENT.value)
        self.assertEqual(outcome.event.ap_name, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.ap_mac, "00:f6:63:53:14:18")
        self.assertEqual(outcome.event.radio, "Slot1")
        self.assertEqual(outcome.event.reason_code, "cleanair_state_slot_1_down")
        self.assertEqual(outcome.event.severity, "warning")

    def test_timestamp_uses_nearest_year_with_configured_timezone(self) -> None:
        parser = CiscoParser(syslog_timestamp_tzinfo=timezone(timedelta(hours=9)))
        record = RawSyslogRecord(
            id=11,
            received_at=datetime(2026, 1, 1, 0, 1, 0, tzinfo=UTC),
            sender_ip="198.51.100.27",
            raw_message=(
                "<133>Cisco-00f8.2c26.6580: *Dot1x_NW_MsgTask_0: Dec 31 23:59:59: "
                "%OSAPI-5-MUTEX_UNLOCK_FAILED: mutex unlock failed"
            ),
            vendor_guess="cisco",
            parse_status="received",
        )
        outcome = parser.parse(record)
        assert outcome.event is not None
        self.assertEqual(
            outcome.event.ts,
            datetime(2025, 12, 31, 14, 59, 59, tzinfo=UTC),
        )

    def test_ap_metadata_prefers_friendly_name_for_same_ap_mac(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            service = WiFiDiagnosticsService(repository, AppConfig(db_path=db_path))
            try:
                service.ingest_syslog(
                    self.fixture_lines[10],
                    sender_ip="198.51.100.21",
                    vendor_override="cisco",
                )
                service.repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name="AP-Office",
                        vendor="cisco",
                        ap_mac="00:f8:2c:26:65:80",
                        mgmt_ip="198.51.100.21",
                    )
                )
                metadata = service.find_ap_metadata("00:f8:2c:26:65:80")
                assert metadata is not None
                self.assertEqual(metadata["ap_name"], "AP-Office")
                self.assertEqual(metadata["ap_mac"], "00:f8:2c:26:65:80")
            finally:
                repository.close()

    def test_ingest_uses_friendly_ap_name_when_metadata_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "wifi.db"
            repository = SQLiteRepository(db_path)
            repository.initialize()
            service = WiFiDiagnosticsService(repository, AppConfig(db_path=db_path))
            try:
                service.repository.upsert_ap_metadata(
                    APMetadata(
                        ap_name="AP-Office",
                        vendor="cisco",
                        ap_mac="00:f8:2c:26:65:80",
                        mgmt_ip="198.51.100.21",
                    )
                )
                service.ingest_syslog(
                    self.fixture_lines[10],
                    sender_ip="198.51.100.21",
                    vendor_override="cisco",
                )
                result = service.search_wifi_events(
                    vendor="cisco",
                    client_mac="ae:b0:9e:57:34:8c",
                    minutes=366 * 24 * 60,
                    limit=5,
                )
                self.assertEqual(result["matched_events"][0]["ap_name"], "AP-Office")
            finally:
                repository.close()


if __name__ == "__main__":
    unittest.main()
