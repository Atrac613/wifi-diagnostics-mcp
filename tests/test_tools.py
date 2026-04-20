from __future__ import annotations

import io
import json
import sys
import tempfile
import urllib.error
import urllib.request
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from wifi_diagnostics_mcp.config import AppConfig
from wifi_diagnostics_mcp.mcp.prompts import build_prompt_definitions
from wifi_diagnostics_mcp.mcp.resources import build_resource_definitions
from wifi_diagnostics_mcp.mcp.tools import build_tool_definitions
from wifi_diagnostics_mcp.server import HTTPMCPServer, MCPServerCore, SUPPORTED_PROTOCOL_VERSION
from wifi_diagnostics_mcp.service import WiFiDiagnosticsService
from wifi_diagnostics_mcp.storage import SQLiteRepository


class MCPDefinitionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "wifi.db"
        self.config = AppConfig(db_path=self.db_path, default_lookback_minutes=60, enable_dev_tools=True)
        self.repository = SQLiteRepository(self.db_path)
        self.repository.initialize()
        self.service = WiFiDiagnosticsService(self.repository, self.config)
        self.service.ingest_sample_logs(str(ROOT / "tests" / "fixtures" / "cisco" / "sample.log"))

    def tearDown(self) -> None:
        self.repository.close()
        self.temp_dir.cleanup()

    def test_tool_registry_contains_required_tools(self) -> None:
        tools = {tool.name: tool for tool in build_tool_definitions(self.service)}
        for required_name in (
            "get_wifi_health",
            "compare_wifi_windows",
            "get_ap_status",
            "get_client_instability",
            "get_auth_failures",
            "get_disconnect_reasons",
            "get_roaming_issues",
            "search_wifi_events",
            "explain_network_slowdown_context",
        ):
            self.assertIn(required_name, tools)
        self.assertIn("ingest_sample_logs", tools)

        payload = tools["get_wifi_health"].handler({"minutes": 60})
        self.assertIn("wifi_health_score", payload)

    def test_dev_tools_are_hidden_by_default(self) -> None:
        default_config = AppConfig(db_path=Path(self.temp_dir.name) / "default.db")
        default_repository = SQLiteRepository(default_config.db_path)
        default_repository.initialize()
        default_service = WiFiDiagnosticsService(default_repository, default_config)
        try:
            tools = {tool.name: tool for tool in build_tool_definitions(default_service)}
            self.assertNotIn("ingest_sample_logs", tools)
        finally:
            default_repository.close()

    def test_tool_schemas_use_client_friendly_scalar_types(self) -> None:
        tools = build_tool_definitions(self.service)
        for tool in tools:
            properties = tool.input_schema.get("properties", {})
            for schema in properties.values():
                self.assertFalse(
                    isinstance(schema.get("type"), list),
                    f"{tool.name} contains a union type in inputSchema: {schema}",
                )

    def test_resource_registry_contains_required_resources(self) -> None:
        resources = {resource.uri: resource for resource in build_resource_definitions(self.service)}
        self.assertIn("wifi://health/latest", resources)
        self.assertIn("wifi://config", resources)
        self.assertIn("wifi://aps", resources)
        self.assertIn("wifi://clients/top-unstable", resources)
        self.assertIn("wifi://parsers", resources)
        self.assertIn("syslog_udp_port", resources["wifi://config"].reader())

    def test_raw_syslog_archive_path_can_be_configured(self) -> None:
        archive_path = Path(self.temp_dir.name) / "logs" / "raw-syslog.jsonl"
        archive_config = AppConfig(
            db_path=Path(self.temp_dir.name) / "archive.db",
            raw_syslog_archive_path=archive_path,
        )
        archive_repository = SQLiteRepository(archive_config.db_path)
        archive_repository.initialize()
        archive_service = WiFiDiagnosticsService(archive_repository, archive_config)
        try:
            archive_service.ingest_syslog(
                '%APF-6-CLIENT_ASSOC: AP "AP-Lobby" Interface Dot11Radio0, Station aa:bb:cc:dd:ee:01 Associated KEY_MGMT[WPA2] SSID "CorpWiFi"',
                sender_ip="198.51.100.1",
            )
            self.assertTrue(archive_path.exists())
            lines = archive_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            payload = json.loads(lines[0])
            self.assertEqual(payload["sender_ip"], "198.51.100.1")
            self.assertEqual(payload["parse_status"], "parsed")
            self.assertIn('AP "AP-Lobby"', payload["raw_message"])
        finally:
            archive_repository.close()

    def test_search_wifi_events_only_returns_raw_when_requested(self) -> None:
        default_payload = self.service.search_wifi_events(limit=1)
        self.assertTrue(default_payload["matched_events"])
        self.assertNotIn("raw_message", default_payload["matched_events"][0])

        with_raw = self.service.search_wifi_events(limit=1, include_raw=True)
        self.assertIn("raw_message", with_raw["matched_events"][0])

    def test_ingest_sample_logs_is_restricted_to_configured_roots(self) -> None:
        outside_path = Path(self.temp_dir.name) / "outside.log"
        outside_path.write_text("test line\n", encoding="utf-8")
        with self.assertRaises(PermissionError):
            self.service.ingest_sample_logs(str(outside_path))

    def test_prompt_templates_reference_tool_flow(self) -> None:
        prompts = {prompt.name: prompt for prompt in build_prompt_definitions()}
        self.assertIn("diagnose_wifi_issue", prompts)
        response = prompts["diagnose_wifi_issue"].renderer(
            {"question": "今ネット重くない？", "lookback_minutes": 30}
        )
        text = response["messages"][0]["content"]["text"]
        self.assertIn("get_wifi_health", text)
        self.assertIn("compare_wifi_windows", text)

    def test_http_transport_serves_mcp_requests(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            initialize_status, initialize_headers, initialize_body = self._http_request(
                http_server.bind_port,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"},
                },
            )
            self.assertEqual(initialize_status, 200)
            self.assertEqual(
                initialize_headers["Content-Type"],
                "application/json",
            )
            initialize_payload = json.loads(initialize_body.decode("utf-8"))
            self.assertEqual(
                initialize_payload["result"]["serverInfo"]["name"],
                "wifi-diagnostics-mcp",
            )
            self.assertEqual(
                initialize_payload["result"]["protocolVersion"],
                SUPPORTED_PROTOCOL_VERSION,
            )

            tool_status, tool_headers, tool_body = self._http_request(
                http_server.bind_port,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )
            self.assertEqual(tool_status, 200)
            self.assertEqual(tool_headers["Content-Type"], "application/json")
            tool_payload = json.loads(tool_body.decode("utf-8"))
            self.assertEqual(tool_payload["jsonrpc"], "2.0")
            self.assertEqual(tool_payload["id"], 2)
            tools = tool_payload["result"]["tools"]
            self.assertEqual(tools[0]["name"], "get_wifi_health")
            self.assertTrue(any(tool["name"] == "get_wifi_health" for tool in tools))
        finally:
            http_server.stop()

    def test_http_transport_serves_tool_call_in_standard_jsonrpc_shape(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            tool_status, tool_headers, tool_body = self._http_request(
                http_server.bind_port,
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "get_wifi_health",
                        "arguments": {"minutes": 60},
                    },
                },
            )
            self.assertEqual(tool_status, 200)
            self.assertEqual(tool_headers["Content-Type"], "application/json")
            tool_payload = json.loads(tool_body.decode("utf-8"))
            structured = tool_payload["result"]["structuredContent"]
            self.assertIn("wifi_health_score", structured)
            self.assertIn("top_noisy_aps", structured)
        finally:
            http_server.stop()

    def test_http_streamable_transport_emits_sse_events(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            stream_body = self._http_sse(
                http_server.bind_port,
                [
                    {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "get_wifi_health",
                            "arguments": {"minutes": 60},
                        },
                    },
                ],
            )
            events = self._parse_sse(stream_body)
            self.assertEqual(len(events), 2)
            self.assertTrue(all(event["event"] == "message" for event in events))
            self.assertEqual(events[0]["data"]["id"], 1)
            second_message = events[1]["data"]
            self.assertEqual(second_message["id"], 2)
            self.assertNotIn("response", second_message)
            self.assertNotIn("sequence", second_message)
            structured = second_message["result"]["structuredContent"]
            self.assertIn("wifi_health_score", structured)
        finally:
            http_server.stop()

    def test_http_notification_returns_202_with_empty_body(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            status, headers, body = self._http_request(
                http_server.bind_port,
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            self.assertEqual(status, 202)
            self.assertEqual(headers["Content-Length"], "0")
            self.assertEqual(body, b"")
        finally:
            http_server.stop()

    def test_http_get_mcp_returns_405_for_non_stream_get(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(f"http://127.0.0.1:{http_server.bind_port}/mcp", timeout=5)
            self.assertEqual(exc_info.exception.code, 405)
            payload = json.loads(exc_info.exception.read().decode("utf-8"))
            self.assertEqual(payload["transport"], "streamable-http")
            self.assertEqual(payload["protocolVersion"], SUPPORTED_PROTOCOL_VERSION)
        finally:
            http_server.stop()

    def test_http_transport_requires_bearer_token_when_configured(self) -> None:
        secured_config = AppConfig(
            db_path=Path(self.temp_dir.name) / "secured.db",
            default_lookback_minutes=60,
            mcp_http_auth_token="topsecret",
        )
        secured_repository = SQLiteRepository(secured_config.db_path)
        secured_repository.initialize()
        secured_service = WiFiDiagnosticsService(secured_repository, secured_config)
        secured_service.ingest_sample_logs(str(ROOT / "tests" / "fixtures" / "cisco" / "sample.log"))
        http_server = HTTPMCPServer(MCPServerCore(secured_service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as exc_info:
                self._http_request(
                    http_server.bind_port,
                    {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )
            self.assertEqual(exc_info.exception.code, 401)
            self.assertEqual(exc_info.exception.headers["WWW-Authenticate"], "Bearer")

            status, headers, body = self._http_request(
                http_server.bind_port,
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                extra_headers={"Authorization": "Bearer topsecret"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/json")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["result"], {})
        finally:
            http_server.stop()
            secured_repository.close()

    def test_http_transport_rejects_untrusted_origin_by_default(self) -> None:
        http_server = HTTPMCPServer(MCPServerCore(self.service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as exc_info:
                self._http_request(
                    http_server.bind_port,
                    {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                    extra_headers={"Origin": "https://evil.example"},
                )
            self.assertEqual(exc_info.exception.code, 403)
            payload = json.loads(exc_info.exception.read().decode("utf-8"))
            self.assertEqual(payload["error"], "Forbidden Origin")

            status, _, body = self._http_request(
                http_server.bind_port,
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                extra_headers={"Origin": "http://127.0.0.1:3000"},
            )
            self.assertEqual(status, 200)
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["result"], {})
        finally:
            http_server.stop()

    def test_http_transport_allows_configured_origin(self) -> None:
        origin_config = AppConfig(
            db_path=Path(self.temp_dir.name) / "origin.db",
            mcp_http_allowed_origins=("https://console.example",),
        )
        origin_repository = SQLiteRepository(origin_config.db_path)
        origin_repository.initialize()
        origin_service = WiFiDiagnosticsService(origin_repository, origin_config)
        http_server = HTTPMCPServer(MCPServerCore(origin_service), host="127.0.0.1", port=0)
        http_server.start()
        try:
            status, headers, body = self._http_request(
                http_server.bind_port,
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                extra_headers={"Origin": "https://console.example"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/json")
            payload = json.loads(body.decode("utf-8"))
            self.assertEqual(payload["result"], {})
        finally:
            http_server.stop()
            origin_repository.close()

    def test_stdio_supports_newline_json_and_legacy_content_length_reads(self) -> None:
        newline_payload = MCPServerCore._read_payload_from_stream(
            io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        )
        self.assertEqual(newline_payload["method"], "ping")

        legacy_body = b'{"jsonrpc":"2.0","id":2,"method":"ping"}'
        legacy_payload = MCPServerCore._read_payload_from_stream(
            io.BytesIO(
                f"Content-Length: {len(legacy_body)}\r\n\r\n".encode("utf-8")
                + legacy_body
            )
        )
        self.assertEqual(legacy_payload["id"], 2)

    def test_stdio_writes_newline_delimited_jsonrpc(self) -> None:
        output = io.BytesIO()

        class _FakeStdout:
            def __init__(self, buffer: io.BytesIO) -> None:
                self.buffer = buffer

        original_stdout = sys.stdout
        try:
            sys.stdout = _FakeStdout(output)
            MCPServerCore._write_payload({"jsonrpc": "2.0", "id": 7, "result": {}})
        finally:
            sys.stdout = original_stdout

        self.assertEqual(output.getvalue(), b'{"jsonrpc":"2.0","id":7,"result":{}}\n')

    @staticmethod
    def _http_request(
        port: int,
        payload: dict[str, object],
        *,
        accept: str = "application/json, text/event-stream",
        path: str = "/mcp",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {
            "Content-Type": "application/json",
            "Accept": accept,
        }
        if extra_headers:
            headers.update(extra_headers)
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            body = response.read()
            return response.status, dict(response.headers.items()), body

    @staticmethod
    def _http_sse(port: int, payload: list[dict[str, object]]) -> str:
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/mcp?stream=1",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.headers["Content-Type"].startswith("text/event-stream")
            body = response.read()
        return body.decode("utf-8")

    @staticmethod
    def _parse_sse(raw: str) -> list[dict[str, object]]:
        events: list[dict[str, object]] = []
        for block in raw.strip().split("\n\n"):
            event_name = "message"
            data_lines: list[str] = []
            for line in block.splitlines():
                if line.startswith("event:"):
                    event_name = line.split(":", 1)[1].strip()
                elif line.startswith("data:"):
                    data_lines.append(line.split(":", 1)[1].strip())
            if data_lines:
                events.append({"event": event_name, "data": json.loads("\n".join(data_lines))})
        return events


if __name__ == "__main__":
    unittest.main()
