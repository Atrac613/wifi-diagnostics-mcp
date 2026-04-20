from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..service import WiFiDiagnosticsService


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler

    def as_mcp_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def build_tool_definitions(service: WiFiDiagnosticsService) -> list[ToolDefinition]:
    tools = [
        ToolDefinition(
            name="get_wifi_health",
            description="Return Wi-Fi health facts for the most recent N minutes.",
            input_schema=_schema(
                {"minutes": {"type": "integer", "default": 5, "minimum": 1}},
            ),
            handler=lambda args: service.get_wifi_health(args.get("minutes", 5)),
        ),
        ToolDefinition(
            name="compare_wifi_windows",
            description="Compare current and previous Wi-Fi windows.",
            input_schema=_schema(
                {"window_minutes": {"type": "integer", "default": 5, "minimum": 1}},
            ),
            handler=lambda args: service.compare_wifi_windows(args.get("window_minutes", 5)),
        ),
        ToolDefinition(
            name="get_ap_status",
            description="Inspect instability around a single AP.",
            input_schema=_schema(
                {
                    "ap_name": {"type": "string"},
                    "minutes": {"type": "integer", "default": 30, "minimum": 1},
                },
                required=["ap_name"],
            ),
            handler=lambda args: service.get_ap_status(args["ap_name"], args.get("minutes", 30)),
        ),
        ToolDefinition(
            name="get_client_instability",
            description="Inspect instability around a single client MAC.",
            input_schema=_schema(
                {
                    "client_mac": {"type": "string"},
                    "minutes": {"type": "integer", "default": 60, "minimum": 1},
                },
                required=["client_mac"],
            ),
            handler=lambda args: service.get_client_instability(args["client_mac"], args.get("minutes", 60)),
        ),
        ToolDefinition(
            name="get_auth_failures",
            description="Summarize recent authentication failures.",
            input_schema=_schema(
                {
                    "minutes": {"type": "integer", "default": 30, "minimum": 1},
                    "top_n": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100},
                }
            ),
            handler=lambda args: service.get_auth_failures(args.get("minutes", 30), args.get("top_n", 10)),
        ),
        ToolDefinition(
            name="get_disconnect_reasons",
            description="Summarize recent disassociation and deauthentication reasons.",
            input_schema=_schema(
                {
                    "minutes": {"type": "integer", "default": 30, "minimum": 1},
                    "top_n": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100},
                }
            ),
            handler=lambda args: service.get_disconnect_reasons(args.get("minutes", 30), args.get("top_n", 10)),
        ),
        ToolDefinition(
            name="get_roaming_issues",
            description="Summarize recent roaming failures.",
            input_schema=_schema(
                {
                    "minutes": {"type": "integer", "default": 30, "minimum": 1},
                    "top_n": {"type": "integer", "default": 10, "minimum": 1, "maximum": 100},
                }
            ),
            handler=lambda args: service.get_roaming_issues(args.get("minutes", 30), args.get("top_n", 10)),
        ),
        ToolDefinition(
            name="search_wifi_events",
            description="Search normalized Wi-Fi events with normalized fields first.",
            input_schema=_schema(
                {
                    "query": {"type": "string", "default": ""},
                    "vendor": {"type": "string"},
                    "ap_name": {"type": "string"},
                    "client_mac": {"type": "string"},
                    "event_type": {"type": "string"},
                    "minutes": {"type": "integer", "default": 60, "minimum": 1},
                    "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
                    "include_raw": {"type": "boolean", "default": False},
                }
            ),
            handler=lambda args: service.search_wifi_events(
                query=args.get("query", ""),
                vendor=args.get("vendor"),
                ap_name=args.get("ap_name"),
                client_mac=args.get("client_mac"),
                event_type=args.get("event_type"),
                minutes=args.get("minutes", 60),
                limit=args.get("limit", 50),
                include_raw=args.get("include_raw", False),
            ),
        ),
        ToolDefinition(
            name="explain_network_slowdown_context",
            description="Bundle Wi-Fi facts useful for answering whether the network feels slow.",
            input_schema=_schema(
                {"lookback_minutes": {"type": "integer", "default": 30, "minimum": 1}},
            ),
            handler=lambda args: service.explain_network_slowdown_context(args.get("lookback_minutes", 30)),
        ),
    ]
    if service.config.enable_dev_tools:
        tools.append(
            ToolDefinition(
                name="ingest_sample_logs",
                description="Developer-focused tool to ingest a Cisco or Netgear sample log file from configured sample roots.",
                input_schema=_schema(
                    {
                        "file_path": {"type": "string"},
                        "vendor": {"type": "string"},
                    },
                    required=["file_path"],
                ),
                handler=lambda args: service.ingest_sample_logs(args["file_path"], args.get("vendor")),
            )
        )
    return tools


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }
