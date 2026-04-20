from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


PromptRenderer = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(slots=True)
class PromptDefinition:
    name: str
    description: str
    arguments: list[dict[str, Any]]
    renderer: PromptRenderer

    def as_mcp_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments,
        }


def build_prompt_definitions() -> list[PromptDefinition]:
    return [
        PromptDefinition(
            name="diagnose_wifi_issue",
            description="Guide an LLM through the best tool order for a general Wi-Fi issue.",
            arguments=[
                {"name": "question", "required": True},
                {"name": "lookback_minutes", "required": False},
            ],
            renderer=_diagnose_wifi_issue_prompt,
        ),
        PromptDefinition(
            name="investigate_ap_instability",
            description="Guide an LLM through an AP-focused Wi-Fi investigation.",
            arguments=[
                {"name": "ap_name", "required": True},
                {"name": "lookback_minutes", "required": False},
            ],
            renderer=_investigate_ap_instability_prompt,
        ),
        PromptDefinition(
            name="investigate_client_wifi_problem",
            description="Guide an LLM through a client-focused Wi-Fi investigation.",
            arguments=[
                {"name": "client_mac", "required": True},
                {"name": "lookback_minutes", "required": False},
            ],
            renderer=_investigate_client_wifi_problem_prompt,
        ),
    ]


def _diagnose_wifi_issue_prompt(arguments: dict[str, Any]) -> dict[str, Any]:
    question = arguments["question"]
    lookback = int(arguments.get("lookback_minutes", 30))
    text = f"""
You are diagnosing a Wi-Fi issue.
User question: {question}
Lookback window: {lookback} minutes.

Recommended tool order:
1. Call `get_wifi_health` with `minutes={lookback}` to establish overall health.
2. Call `compare_wifi_windows` with `window_minutes={max(5, lookback // 2)}` to see whether the issue is rising or falling.
3. Call `explain_network_slowdown_context` if the question is about "slow network" or a broad feeling of slowness.
4. If one AP stands out, call `get_ap_status`.
5. If one client stands out, call `get_client_instability`.
6. Use `get_auth_failures`, `get_disconnect_reasons`, or `get_roaming_issues` to deepen the dominant symptom.
7. Use `search_wifi_events` only to confirm concrete examples, not to dump raw logs.

Keep conclusions fact-centered and distinguish Wi-Fi symptoms from upstream DHCP/DNS problems.
""".strip()
    return _prompt_response(text)


def _investigate_ap_instability_prompt(arguments: dict[str, Any]) -> dict[str, Any]:
    ap_name = arguments["ap_name"]
    lookback = int(arguments.get("lookback_minutes", 60))
    text = f"""
Investigate Wi-Fi instability around AP `{ap_name}` over the last {lookback} minutes.

Suggested sequence:
1. Call `get_ap_status` with `ap_name="{ap_name}"` and `minutes={lookback}`.
2. Review `event_counts_by_type`, `top_clients`, and `latest_events`.
3. If auth failures are visible, call `get_auth_failures` scoped by time and compare the AP against other APs.
4. If disconnects dominate, call `get_disconnect_reasons`.
5. If roaming issues dominate, call `get_roaming_issues`.
6. Use `search_wifi_events` with `ap_name="{ap_name}"` to pull a few recent normalized examples.

Favor statements like "AP-down events were observed" or "disconnect volume is concentrated on one client" over broad guesses.
""".strip()
    return _prompt_response(text)


def _investigate_client_wifi_problem_prompt(arguments: dict[str, Any]) -> dict[str, Any]:
    client_mac = arguments["client_mac"]
    lookback = int(arguments.get("lookback_minutes", 60))
    text = f"""
Investigate Wi-Fi instability around client `{client_mac}` over the last {lookback} minutes.

Suggested sequence:
1. Call `get_client_instability` with `client_mac="{client_mac}"` and `minutes={lookback}`.
2. Review association/disassociation/auth/roam counters and the top APs/SSIDs.
3. If authentication issues dominate, call `get_auth_failures`.
4. If disconnect issues dominate, call `get_disconnect_reasons`.
5. If the client moves across APs, call `get_roaming_issues`.
6. Use `search_wifi_events` with `client_mac="{client_mac}"` for a short list of concrete normalized examples.

Note when the issue is concentrated on a single client, because that raises the probability of an endpoint-specific problem.
""".strip()
    return _prompt_response(text)


def _prompt_response(text: str) -> dict[str, Any]:
    return {
        "description": "Wi-Fi diagnostics workflow prompt",
        "messages": [
            {
                "role": "user",
                "content": {
                    "type": "text",
                    "text": text,
                },
            }
        ],
    }

