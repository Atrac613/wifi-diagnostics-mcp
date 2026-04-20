from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ..service import WiFiDiagnosticsService


ResourceReader = Callable[[], Any]


@dataclass(slots=True)
class ResourceDefinition:
    uri: str
    name: str
    description: str
    mime_type: str
    reader: ResourceReader

    def as_mcp_dict(self) -> dict[str, Any]:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


def build_resource_definitions(service: WiFiDiagnosticsService) -> list[ResourceDefinition]:
    return [
        ResourceDefinition(
            uri="wifi://health/latest",
            name="Latest Wi-Fi Health",
            description="Latest Wi-Fi health summary using the default lookback window.",
            mime_type="application/json",
            reader=lambda: service.get_wifi_health(),
        ),
        ResourceDefinition(
            uri="wifi://config",
            name="Wi-Fi MCP Config",
            description="Runtime configuration such as ports, DB path, thresholds, and supported vendors.",
            mime_type="application/json",
            reader=lambda: service.config.as_dict(),
        ),
        ResourceDefinition(
            uri="wifi://aps",
            name="AP Metadata",
            description="Known AP metadata gathered or enriched in the repository.",
            mime_type="application/json",
            reader=service.list_ap_metadata,
        ),
        ResourceDefinition(
            uri="wifi://clients/top-unstable",
            name="Top Unstable Clients",
            description="Most unstable clients in the default lookback window.",
            mime_type="application/json",
            reader=service.top_unstable_clients,
        ),
        ResourceDefinition(
            uri="wifi://parsers",
            name="Parser Inventory",
            description="Active parser plugins and their supported vendors.",
            mime_type="application/json",
            reader=service.parser_inventory,
        ),
    ]

