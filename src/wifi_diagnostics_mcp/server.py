from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import logging
import secrets
import urllib.parse
import signal
import sys
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any, BinaryIO

from .config import AppConfig
from .mcp import build_prompt_definitions, build_resource_definitions, build_tool_definitions
from .receiver import SyslogReceiverManager
from .service import WiFiDiagnosticsService
from .storage import SQLiteRepository


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSION = "2025-03-26"


@dataclass(slots=True)
class JSONRPCError(Exception):
    code: int
    message: str


def _format_sse_event(event_name: str, payload: dict[str, Any]) -> str:
    data = json.dumps(payload, ensure_ascii=False)
    return f"event: {event_name}\ndata: {data}\n\n"


class MCPServerCore:
    def __init__(self, service: WiFiDiagnosticsService) -> None:
        self.service = service
        self.tools = {tool.name: tool for tool in build_tool_definitions(service)}
        self.resources = {resource.uri: resource for resource in build_resource_definitions(service)}
        self.prompts = {prompt.name: prompt for prompt in build_prompt_definitions()}
        self.protocol_version: str | None = None

    def process_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if "method" not in message:
            return self._error_response(message.get("id"), -32600, "Invalid Request")
        if "id" not in message:
            self._handle_notification(message)
            return None
        return self._handle_request(message)

    def process_payload(self, payload: Any) -> tuple[int, dict[str, str], bytes]:
        status_code, envelope = self.collect_payload_responses(payload)
        if envelope is None:
            return 202, {}, b""
        return self._json_response(envelope)

    def collect_payload_responses(self, payload: Any) -> tuple[int, dict[str, Any] | list[dict[str, Any]] | None]:
        if isinstance(payload, list):
            responses: list[dict[str, Any]] = []
            for item in payload:
                if not isinstance(item, dict):
                    responses.append(self._error_response(None, -32600, "Invalid Request"))
                    continue
                response = self.process_message(item)
                if response is not None:
                    responses.append(response)
            if not responses:
                return 202, None
            return 200, responses
        if not isinstance(payload, dict):
            return 200, self._error_response(None, -32600, "Invalid Request")
        response = self.process_message(payload)
        if response is None:
            return 202, None
        return 200, response

    def iter_payload_responses(self, payload: Any) -> tuple[int, list[dict[str, Any]]]:
        status_code, envelope = self.collect_payload_responses(payload)
        if envelope is None:
            return status_code, []
        if isinstance(envelope, list):
            return status_code, envelope
        return status_code, [envelope]

    def run(self) -> None:
        while True:
            payload = self._read_payload()
            if payload is None:
                return
            _, envelope = self.collect_payload_responses(payload)
            if envelope is not None:
                self._write_payload(envelope)

    def _handle_notification(self, message: dict[str, Any]) -> None:
        if message.get("method") == "notifications/initialized":
            logger.info("MCP client initialized")

    def _handle_request(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message["id"]
        method = message["method"]
        params = message.get("params", {})
        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [tool.as_mcp_dict() for tool in self.tools.values()]}
            elif method == "tools/call":
                result = self._call_tool(params)
            elif method == "resources/list":
                result = {"resources": [resource.as_mcp_dict() for resource in self.resources.values()]}
            elif method == "resources/read":
                result = self._read_resource(params)
            elif method == "prompts/list":
                result = {"prompts": [prompt.as_mcp_dict() for prompt in self.prompts.values()]}
            elif method == "prompts/get":
                result = self._get_prompt(params)
            else:
                raise JSONRPCError(-32601, f"Method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except JSONRPCError as exc:
            return self._error_response(request_id, exc.code, exc.message)
        except Exception as exc:  # pragma: no cover - defensive path
            logger.exception("Unhandled MCP error")
            return self._error_response(request_id, -32000, str(exc))

    def _initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested_version = params.get("protocolVersion") or SUPPORTED_PROTOCOL_VERSION
        self.protocol_version = (
            requested_version
            if requested_version == SUPPORTED_PROTOCOL_VERSION
            else SUPPORTED_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": self.protocol_version,
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"listChanged": False, "subscribe": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {"name": "wifi-diagnostics-mcp", "version": "0.1.0"},
        }

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not name or name not in self.tools:
            raise JSONRPCError(-32602, f"Unknown tool: {name}")
        arguments = params.get("arguments", {}) or {}
        result = self.tools[name].handler(arguments)
        return self._content_result(result)

    def _read_resource(self, params: dict[str, Any]) -> dict[str, Any]:
        uri = params.get("uri")
        if not uri or uri not in self.resources:
            raise JSONRPCError(-32602, f"Unknown resource: {uri}")
        payload = self.resources[uri].reader()
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": self.resources[uri].mime_type,
                    "text": json.dumps(payload, ensure_ascii=False, indent=2),
                }
            ]
        }

    def _get_prompt(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not name or name not in self.prompts:
            raise JSONRPCError(-32602, f"Unknown prompt: {name}")
        arguments = params.get("arguments", {}) or {}
        return self.prompts[name].renderer(arguments)

    @staticmethod
    def _content_result(result: Any) -> dict[str, Any]:
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(result, ensure_ascii=False, indent=2),
                }
            ],
            "structuredContent": result,
            "isError": False,
        }

    @staticmethod
    def _error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    @staticmethod
    def _json_response(payload: Any) -> tuple[int, dict[str, str], bytes]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        return 200, {"Content-Type": "application/json"}, body

    @staticmethod
    def _read_payload() -> dict[str, Any] | list[dict[str, Any]] | None:
        return MCPServerCore._read_payload_from_stream(sys.stdin.buffer)

    @staticmethod
    def _read_payload_from_stream(
        stream: BinaryIO,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        while True:
            first_line = stream.readline()
            if not first_line:
                return None
            if first_line.strip():
                break

        if first_line.lower().startswith(b"content-length:"):
            headers = MCPServerCore._read_legacy_headers(first_line, stream)
            content_length = int(headers.get("content-length", "0"))
            if content_length <= 0:
                return None
            body = stream.read(content_length)
            if not body:
                return None
            return json.loads(body.decode("utf-8"))

        return json.loads(first_line.decode("utf-8"))

    @staticmethod
    def _read_legacy_headers(first_line: bytes, stream: BinaryIO) -> dict[str, str]:
        headers: dict[str, str] = {}
        current = first_line
        while current:
            if current in {b"\r\n", b"\n"}:
                break
            name, value = current.decode("utf-8").split(":", 1)
            headers[name.strip().lower()] = value.strip()
            current = stream.readline()
        return headers

    @staticmethod
    def _write_payload(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        sys.stdout.buffer.write(body + b"\n")
        sys.stdout.buffer.flush()


class StdioMCPServer:
    def __init__(self, core: MCPServerCore) -> None:
        self.core = core

    def run(self) -> None:
        self.core.run()


class HTTPMCPServer:
    def __init__(self, core: MCPServerCore, host: str, port: int) -> None:
        self.core = core
        self.host = host
        self.port = port
        self._httpd = http.server.ThreadingHTTPServer(
            (host, port),
            self._build_handler(),
        )
        self._thread: Thread | None = None

    @property
    def bind_host(self) -> str:
        return str(self._httpd.server_address[0])

    @property
    def bind_port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> None:
        self._thread = Thread(target=self._httpd.serve_forever, name="wifi-mcp-http", daemon=True)
        self._thread.start()
        logger.info("HTTP MCP server listening on http://%s:%s/mcp", self.bind_host, self.bind_port)
        if not _is_loopback_host(self.bind_host) and not self.core.service.config.mcp_http_auth_token:
            logger.warning(
                "HTTP MCP server is listening on a non-loopback address without MCP_HTTP_AUTH_TOKEN."
            )

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _build_handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        core = self.core

        class MCPHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/health":
                    self._send_json(200, {"status": "ok", "transport": "http", "path": "/mcp"})
                    return
                if parsed.path == "/mcp":
                    if not self._is_authorized():
                        self._send_unauthorized()
                        return
                    if not self._is_origin_allowed():
                        self._send_forbidden_origin()
                        return
                    self._send_json(
                        405,
                        {
                            "error": "GET /mcp SSE stream is not supported by this server; use POST /mcp.",
                            "transport": "streamable-http",
                            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                        },
                        extra_headers={"Allow": "POST"},
                    )
                    return
                self._send_json(404, {"error": "Not Found"})

            def do_DELETE(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/mcp":
                    if not self._is_authorized():
                        self._send_unauthorized()
                        return
                    if not self._is_origin_allowed():
                        self._send_forbidden_origin()
                        return
                    self._send_json(
                        405,
                        {
                            "error": "Session termination is not supported; this server is stateless over HTTP.",
                            "transport": "streamable-http",
                            "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                        },
                        extra_headers={"Allow": "POST"},
                    )
                    return
                self._send_json(404, {"error": "Not Found"})

            def do_POST(self) -> None:  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/mcp":
                    self._send_json(404, {"error": "Not Found"})
                    return
                if not self._is_authorized():
                    self._send_unauthorized()
                    return
                if not self._is_origin_allowed():
                    self._send_forbidden_origin()
                    return
                content_length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(content_length)
                try:
                    payload = json.loads(raw_body.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send_json(
                        400,
                        MCPServerCore._error_response(None, -32700, "Parse error"),
                    )
                    return
                status_code, envelope = core.collect_payload_responses(payload)
                if envelope is None:
                    self.send_response(status_code)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self._wants_stream(parsed):
                    self._send_sse_payload(status_code, envelope)
                    return
                status_code, headers, body = core._json_response(envelope)
                self.send_response(status_code)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                logger.info("HTTP MCP %s - %s", self.address_string(), format % args)

            def _wants_stream(self, parsed: urllib.parse.ParseResult) -> bool:
                accept = self.headers.get("Accept", "")
                query = urllib.parse.parse_qs(parsed.query)
                if query.get("stream", ["0"])[0] in {
                    "1",
                    "true",
                    "yes",
                }:
                    return True
                lowered_accept = accept.lower()
                wants_sse = "text/event-stream" in lowered_accept
                wants_json = "application/json" in lowered_accept
                return wants_sse and not wants_json

            def _is_authorized(self) -> bool:
                configured = core.service.config.mcp_http_auth_token
                if not configured:
                    return True
                header = self.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    return False
                presented = header[len("Bearer ") :].strip()
                return secrets.compare_digest(presented, configured)

            def _send_unauthorized(self) -> None:
                self._send_json(
                    401,
                    {"error": "Unauthorized"},
                    extra_headers={"WWW-Authenticate": "Bearer"},
                )

            def _is_origin_allowed(self) -> bool:
                origin = self.headers.get("Origin")
                if not origin:
                    return True

                configured = core.service.config.mcp_http_allowed_origins
                if configured:
                    return origin in configured

                parsed_origin = urllib.parse.urlparse(origin)
                origin_host = parsed_origin.hostname
                if not origin_host:
                    return False

                if _is_loopback_host(core.service.config.mcp_http_host) or _is_loopback_host(
                    self.server.server_address[0]
                ):
                    return _is_loopback_host(origin_host)

                return False

            def _send_forbidden_origin(self) -> None:
                self._send_json(
                    403,
                    {
                        "error": "Forbidden Origin",
                        "detail": "Configure MCP_HTTP_ALLOWED_ORIGINS to permit browser-originated requests.",
                    },
                )

            def _send_sse_payload(
                self,
                status_code: int,
                envelope: dict[str, Any] | list[dict[str, Any]],
            ) -> None:
                responses = envelope if isinstance(envelope, list) else [envelope]
                self.close_connection = True
                self.send_response(status_code)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()

                for response in responses:
                    self._write_sse_event("message", response)

            def _write_sse_event(self, event_name: str, payload: dict[str, Any]) -> None:
                body = _format_sse_event(event_name, payload).encode("utf-8")
                self.wfile.write(body)
                self.wfile.flush()

            def _send_json(
                self,
                status_code: int,
                payload: Any,
                extra_headers: dict[str, str] | None = None,
            ) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status_code)
                if extra_headers:
                    for key, value in extra_headers.items():
                        self.send_header(key, value)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return MCPHTTPRequestHandler


def _is_loopback_host(host: str) -> bool:
    if host in {"0.0.0.0", "::"}:
        return False
    if host in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_application(config: AppConfig | None = None) -> tuple[WiFiDiagnosticsService, SQLiteRepository]:
    app_config = config or AppConfig.from_env()
    repository = SQLiteRepository(app_config.db_path)
    repository.initialize()
    return WiFiDiagnosticsService(repository, app_config), repository


def main() -> None:
    parser = argparse.ArgumentParser(description="Wi-Fi Diagnostics MCP Server")
    parser.add_argument("--no-receiver", action="store_true", help="Do not start UDP/TCP syslog listeners.")
    parser.add_argument(
        "--transport",
        choices=("stdio", "http", "both"),
        default=None,
        help="MCP transport to start. Defaults to stdio, or both when ENABLE_HTTP_MCP=true.",
    )
    parser.add_argument("--http-host", default=None, help="Bind host for HTTP MCP transport.")
    parser.add_argument("--http-port", type=int, default=None, help="Bind port for HTTP MCP transport.")
    args = parser.parse_args()

    service, repository = build_application()
    if args.http_host:
        service.config.mcp_http_host = args.http_host
    if args.http_port is not None:
        service.config.mcp_http_port = args.http_port

    transport = args.transport or ("both" if service.config.enable_http_mcp else "stdio")
    receiver = (
        None
        if args.no_receiver
        else SyslogReceiverManager(
            service.config,
            lambda message, sender_ip, received_at: service.ingest_syslog(
                message,
                sender_ip=sender_ip,
                received_at=received_at,
            ),
        )
    )
    http_transport = None
    core = MCPServerCore(service)

    if receiver is not None:
        receiver.start()
    if transport in {"http", "both"}:
        http_transport = HTTPMCPServer(
            core,
            host=service.config.mcp_http_host,
            port=service.config.mcp_http_port,
        )
        http_transport.start()

    def _shutdown(*_: Any) -> None:
        if http_transport is not None:
            http_transport.stop()
        if receiver is not None:
            receiver.stop()
        repository.close()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        if transport in {"stdio", "both"}:
            StdioMCPServer(core).run()
        elif transport == "http":
            Event().wait()
    finally:
        if http_transport is not None:
            http_transport.stop()
        if receiver is not None:
            receiver.stop()
        repository.close()


if __name__ == "__main__":
    main()
