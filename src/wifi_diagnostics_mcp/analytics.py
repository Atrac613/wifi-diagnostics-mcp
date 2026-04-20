from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from .config import AppConfig
from .models import EventType, NormalizedEvent, SearchFilters, utc_now
from .storage import Repository


class WiFiAnalytics:
    def __init__(self, repository: Repository, config: AppConfig) -> None:
        self.repository = repository
        self.config = config

    def get_wifi_health(self, minutes: int = 5, now: datetime | None = None) -> dict[str, Any]:
        end = now or utc_now()
        start = end - timedelta(minutes=minutes)
        return self._build_wifi_health(start, end, minutes)

    def compare_wifi_windows(
        self, window_minutes: int = 5, now: datetime | None = None
    ) -> dict[str, Any]:
        end = now or utc_now()
        current_start = end - timedelta(minutes=window_minutes)
        previous_end = current_start
        previous_start = previous_end - timedelta(minutes=window_minutes)

        current = self._build_wifi_health(current_start, end, window_minutes)
        previous = self._build_wifi_health(previous_start, previous_end, window_minutes)
        delta = {
            "auth_failure_change": current["auth_failure_count"] - previous["auth_failure_count"],
            "disassociation_change": current["disassociation_count"] - previous["disassociation_count"],
            "deauthentication_change": current["deauthentication_count"] - previous["deauthentication_count"],
            "roam_failure_change": current["roam_failure_count"] - previous["roam_failure_count"],
            "ap_down_change": current["ap_down_count"] - previous["ap_down_count"],
            "poor_rssi_change": current["poor_rssi_count"] - previous["poor_rssi_count"],
            "wifi_health_score_change": current["wifi_health_score"] - previous["wifi_health_score"],
        }
        return {"current": current, "previous": previous, "delta": delta}

    def get_ap_status(self, ap_name: str, minutes: int = 30) -> dict[str, Any]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        aliases = self._ap_aliases(ap_name)
        events = self._fetch_events(
            start,
            end=end,
            ap_names=aliases["names"],
            ap_mac=aliases["ap_mac"],
            limit=2000,
        )
        issue_events = self._issue_analysis_events(events)
        counts = Counter(event.event_type for event in issue_events)
        top_clients = self._counter_to_ranked(
            Counter(event.client_mac for event in issue_events if event.client_mac), "client_mac"
        )
        top_ssids = self._counter_to_ranked(
            Counter(event.ssid for event in issue_events if event.ssid), "ssid"
        )
        summary = {
            "ap_name": aliases["display_name"],
            "window": self._window(minutes, start, end),
            "total_events": len(events),
            "vendor": self._most_common([event.vendor for event in events]),
        }
        return {
            "ap_summary": summary,
            "event_counts_by_type": dict(counts),
            "top_clients": top_clients[:10],
            "top_ssids": top_ssids[:10],
            "latest_events": [self._event_brief(event) for event in issue_events[:10]],
            "suspected_issues": self._suspected_issues(
                counts,
                total_events=len(issue_events),
                dominant_client=self._dominant_entity_share(top_clients),
                focus="ap",
            ),
        }

    def get_client_instability(self, client_mac: str, minutes: int = 60) -> dict[str, Any]:
        normalized_mac = client_mac.lower()
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = self._fetch_events(start, end=end, client_mac=normalized_mac, limit=2000)
        counts = Counter(event.event_type for event in events)
        issue_events = self._issue_analysis_events(events)
        top_aps = self._counter_to_ranked(
            Counter(self._event_ap_name(event) for event in issue_events if self._event_ap_name(event)),
            "ap_name",
        )
        top_ssids = self._counter_to_ranked(Counter(event.ssid for event in issue_events if event.ssid), "ssid")
        instability_score = min(
            100,
            counts.get(EventType.AUTH_FAILURE.value, 0) * 18
            + counts.get(EventType.CLIENT_DISASSOCIATED.value, 0) * 12
            + counts.get(EventType.CLIENT_DEAUTHENTICATED.value, 0) * 15
            + counts.get(EventType.ROAM_FAILURE.value, 0) * 20
            + counts.get(EventType.POOR_RSSI.value, 0) * 10,
        )
        return {
            "client_mac": normalized_mac,
            "window": self._window(minutes, start, end),
            "association_count": counts.get(EventType.CLIENT_ASSOCIATED.value, 0),
            "disassociation_count": counts.get(EventType.CLIENT_DISASSOCIATED.value, 0),
            "auth_failures": counts.get(EventType.AUTH_FAILURE.value, 0),
            "roam_failures": counts.get(EventType.ROAM_FAILURE.value, 0),
            "top_aps": top_aps[:10],
            "top_ssids": top_ssids[:10],
            "instability_score": instability_score,
            "suspected_issues": self._suspected_issues(
                counts,
                total_events=len(issue_events),
                dominant_client=1.0 if issue_events else 0.0,
                focus="client",
            ),
        }

    def get_auth_failures(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        return self._summarize_single_event_type(EventType.AUTH_FAILURE.value, minutes, top_n)

    def get_disconnect_reasons(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = [
            event
            for event in self._fetch_events(start, end=end, limit=3000)
            if event.event_type
            in {EventType.CLIENT_DISASSOCIATED.value, EventType.CLIENT_DEAUTHENTICATED.value}
        ]
        return {
            "total": len(events),
            "by_event_type": dict(Counter(event.event_type for event in events)),
            "by_reason_code": self._counter_to_ranked(
                Counter(event.reason_code for event in events if event.reason_code),
                "reason_code",
                top_n,
            ),
            "by_ap": self._counter_to_ranked(
                Counter(self._event_ap_name(event) for event in events if self._event_ap_name(event)),
                "ap_name",
                top_n,
            ),
            "by_client": self._counter_to_ranked(
                Counter(event.client_mac for event in events if event.client_mac), "client_mac", top_n
            ),
            "recent_examples": [self._event_brief(event) for event in events[:top_n]],
        }

    def get_roaming_issues(self, minutes: int = 30, top_n: int = 10) -> dict[str, Any]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = [
            event
            for event in self._fetch_events(start, end=end, limit=3000)
            if event.event_type == EventType.ROAM_FAILURE.value
        ]
        return {
            "total": len(events),
            "by_ap": self._counter_to_ranked(
                Counter(self._event_ap_name(event) for event in events if self._event_ap_name(event)),
                "ap_name",
                top_n,
            ),
            "by_client": self._counter_to_ranked(
                Counter(event.client_mac for event in events if event.client_mac), "client_mac", top_n
            ),
            "by_ssid": self._counter_to_ranked(Counter(event.ssid for event in events if event.ssid), "ssid", top_n),
            "recent_examples": [self._event_brief(event) for event in events[:top_n]],
        }

    def search_wifi_events(
        self,
        *,
        query: str = "",
        vendor: str | None = None,
        ap_name: str | None = None,
        client_mac: str | None = None,
        event_type: str | None = None,
        minutes: int = 60,
        limit: int = 50,
        include_raw: bool = False,
    ) -> list[dict[str, Any]]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = self._fetch_events(
            start,
            end=end,
            vendor=vendor,
            ap_name=ap_name,
            client_mac=client_mac.lower() if client_mac else None,
            event_type=event_type,
            query=query,
            limit=limit,
        )
        raw_records = (
            self.repository.get_raw_records([event.raw_event_id for event in events if event.raw_event_id is not None])
            if include_raw
            else {}
        )
        enriched: list[dict[str, Any]] = []
        for event in events[:limit]:
            payload = event.as_dict()
            if include_raw and event.raw_event_id is not None and event.raw_event_id in raw_records:
                payload["raw_message"] = raw_records[event.raw_event_id].raw_message
            enriched.append(payload)
        return enriched

    def explain_network_slowdown_context(self, lookback_minutes: int = 30) -> dict[str, Any]:
        now = utc_now()
        health = self.get_wifi_health(lookback_minutes, now=now)
        compare = self.compare_wifi_windows(lookback_minutes, now=now)
        dominant_categories = self._dominant_categories(
            self._issue_analysis_events(
                self._fetch_events(
                    now - timedelta(minutes=lookback_minutes),
                    end=now,
                    limit=3000,
                )
            )
        )
        facts = [
            f"window_total_events={health['total_events']}",
            f"wifi_health_score={health['wifi_health_score']}",
        ]
        if health["top_noisy_aps"]:
            top_ap = health["top_noisy_aps"][0]
            facts.append(
                f"top_problem_ap={top_ap['ap_name']} events={top_ap['events']} weighted_score={top_ap['score']}"
            )
        if health["top_unstable_clients"]:
            top_client = health["top_unstable_clients"][0]
            facts.append(
                f"top_problem_client={top_client['client_mac']} events={top_client['events']} weighted_score={top_client['score']}"
            )
        if dominant_categories:
            facts.append(
                "dominant_issues="
                + ",".join(f"{item['event_type']}:{item['count']}" for item in dominant_categories[:3])
            )
        return {
            "wifi_health": health,
            "compare_windows": compare,
            "top_problem_aps": health["top_noisy_aps"],
            "top_problem_clients": health["top_unstable_clients"],
            "dominant_issue_categories": dominant_categories,
            "fact_summary": facts,
        }

    def top_unstable_clients(self, minutes: int, top_n: int = 10) -> list[dict[str, Any]]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = self._issue_analysis_events(self._fetch_events(start, end=end, limit=3000))
        return self._rank_entities(events, "client_mac", top_n)

    def _build_wifi_health(self, start: datetime, end: datetime, minutes: int) -> dict[str, Any]:
        events = self._fetch_events(start, end=end, limit=3000)
        issue_events = self._issue_analysis_events(events)
        counts = self._health_score_counts(issue_events)
        top_noisy_aps = self._rank_entities(issue_events, "ap_name", 5)
        top_unstable_clients = self._rank_entities(issue_events, "client_mac", 5)
        score = self._wifi_health_score(counts, len(events))
        return {
            "window": self._window(minutes, start, end),
            "total_events": len(events),
            "auth_failure_count": counts.get(EventType.AUTH_FAILURE.value, 0),
            "disassociation_count": counts.get(EventType.CLIENT_DISASSOCIATED.value, 0),
            "deauthentication_count": counts.get(EventType.CLIENT_DEAUTHENTICATED.value, 0),
            "roam_failure_count": counts.get(EventType.ROAM_FAILURE.value, 0),
            "ap_down_count": counts.get(EventType.AP_DOWN.value, 0),
            "poor_rssi_count": counts.get(EventType.POOR_RSSI.value, 0),
            "channel_interference_count": counts.get(EventType.CHANNEL_INTERFERENCE.value, 0),
            "top_noisy_aps": top_noisy_aps,
            "top_unstable_clients": top_unstable_clients,
            "wifi_health_score": score,
            "interpretation_hint": self._interpretation_hint(
                counts, len(events), score, top_noisy_aps, top_unstable_clients
            ),
        }

    def _fetch_events(
        self,
        start: datetime,
        *,
        end: datetime | None = None,
        vendor: str | None = None,
        ap_name: str | None = None,
        ap_names: tuple[str, ...] | None = None,
        ap_mac: str | None = None,
        client_mac: str | None = None,
        event_type: str | None = None,
        query: str = "",
        limit: int = 1000,
    ) -> list[NormalizedEvent]:
        return self.repository.search_events(
            SearchFilters(
                since=start,
                until=end,
                vendor=vendor,
                ap_name=ap_name,
                ap_names=ap_names,
                ap_mac=ap_mac,
                client_mac=client_mac,
                event_type=event_type,
                query=query,
                limit=limit,
            )
        )

    def _ap_aliases(self, ap_name: str) -> dict[str, Any]:
        metadata = getattr(self.repository, "find_ap_metadata", lambda _: None)(ap_name)
        if metadata is None:
            return {"display_name": ap_name, "names": (ap_name,), "ap_mac": None}
        names = {ap_name, metadata.ap_name}
        if metadata.ap_mac:
            names.add(metadata.ap_mac)
        return {
            "display_name": metadata.ap_name,
            "names": tuple(sorted(name for name in names if name)),
            "ap_mac": metadata.ap_mac,
        }

    def _summarize_single_event_type(self, event_type: str, minutes: int, top_n: int) -> dict[str, Any]:
        end = utc_now()
        start = end - timedelta(minutes=minutes)
        events = self._fetch_events(start, end=end, event_type=event_type, limit=3000)
        return {
            "total": len(events),
            "by_ap": self._counter_to_ranked(
                Counter(self._event_ap_name(event) for event in events if self._event_ap_name(event)),
                "ap_name",
                top_n,
            ),
            "by_ssid": self._counter_to_ranked(Counter(event.ssid for event in events if event.ssid), "ssid", top_n),
            "by_client": self._counter_to_ranked(
                Counter(event.client_mac for event in events if event.client_mac), "client_mac", top_n
            ),
            "by_reason_code": self._counter_to_ranked(
                Counter(event.reason_code for event in events if event.reason_code),
                "reason_code",
                top_n,
            ),
            "recent_examples": [self._event_brief(event) for event in events[:top_n]],
        }

    def _wifi_health_score(self, counts: Counter[str], total_events: int) -> int:
        thresholds = self.config.health_score_thresholds
        weights: dict[str, int] = thresholds.get("weights", {})
        penalty = 0
        for event_type, count in counts.items():
            penalty += int(weights.get(event_type, 0)) * count
        score = max(0, 100 - penalty)
        observation_floor = int(thresholds.get("observation_floor", 5))
        insufficient_cap = int(thresholds.get("insufficient_data_ceiling", 72))
        if total_events < observation_floor:
            score = min(score, insufficient_cap + total_events)
        return max(0, min(100, score))

    def _health_score_counts(self, events: Iterable[NormalizedEvent]) -> Counter[str]:
        return Counter(
            event.event_type
            for event in events
            if not self._exclude_from_health_score(event)
        )

    def _issue_analysis_events(self, events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
        return [event for event in events if not self._exclude_from_health_score(event)]

    @staticmethod
    def _exclude_from_health_score(event: NormalizedEvent) -> bool:
        return (
            event.event_type == EventType.UNKNOWN_WIFI_EVENT.value
            and isinstance(event.reason_code, str)
            and event.reason_code.startswith("noise:")
        )

    def _interpretation_hint(
        self,
        counts: Counter[str],
        total_events: int,
        score: int,
        top_noisy_aps: list[dict[str, Any]],
        top_unstable_clients: list[dict[str, Any]],
    ) -> str:
        if total_events == 0:
            return "No normalized Wi-Fi events were observed in the window; the score is capped because observation volume is low."
        dominant = self._dominant_categories_from_counts(counts)
        parts = [f"Observed {total_events} normalized Wi-Fi events, health score {score}."]
        if dominant:
            parts.append(
                "Top issue counts: "
                + ", ".join(f"{item['event_type']}={item['count']}" for item in dominant[:3])
                + "."
            )
        if top_noisy_aps:
            parts.append(f"Most affected AP: {top_noisy_aps[0]['ap_name']}.")
        if top_unstable_clients:
            parts.append(f"Most affected client: {top_unstable_clients[0]['client_mac']}.")
        return " ".join(parts)

    def _suspected_issues(
        self,
        counts: Counter[str],
        *,
        total_events: int,
        dominant_client: float,
        focus: str,
    ) -> list[str]:
        issues: list[str] = []
        trigger = int(self.config.health_score_thresholds.get("issue_trigger_count", 3))
        if counts.get(EventType.AUTH_FAILURE.value, 0) >= trigger:
            issues.append("Authentication failures are elevated; PSK, RADIUS, certificate, or EAP settings are candidates.")
        if (
            counts.get(EventType.CLIENT_DISASSOCIATED.value, 0)
            + counts.get(EventType.CLIENT_DEAUTHENTICATED.value, 0)
            >= trigger
        ):
            issues.append("Disconnect-related events are elevated; interference, radio quality, AP restart, or client behavior are candidates.")
        if counts.get(EventType.POOR_RSSI.value, 0) >= trigger:
            issues.append("Poor RSSI is recurring; coverage or client placement may be contributing.")
        if counts.get(EventType.ROAM_FAILURE.value, 0) >= trigger:
            issues.append("Roam failures are recurring; roaming thresholds or AP placement may need review.")
        if counts.get(EventType.AP_DOWN.value, 0) > 0:
            issues.append("AP down events were observed; AP stability or upstream power/uplink should be checked.")
        if counts.get(EventType.CHANNEL_INTERFERENCE.value, 0) >= trigger:
            issues.append("Channel interference is elevated; RF noise or channel plan issues are plausible.")
        if counts.get(EventType.DHCP_ISSUE.value, 0) + counts.get(EventType.DNS_ISSUE.value, 0) >= trigger:
            issues.append("DHCP/DNS issues are visible; the slowdown may extend beyond Wi-Fi into upstream services.")
        if focus == "ap" and dominant_client >= 0.6:
            issues.append("A single client dominates the AP's recent issue volume, so the endpoint may be driving part of the instability.")
        if focus == "client" and total_events > 0:
            issues.append("The issue pattern is concentrated on one client, which raises the likelihood of an endpoint-specific problem.")
        if not issues:
            issues.append("No single issue type clearly dominates this window.")
        return issues

    def _rank_entities(
        self, events: Iterable[NormalizedEvent], field_name: str, top_n: int
    ) -> list[dict[str, Any]]:
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            key = self._event_ap_name(event) if field_name == "ap_name" else getattr(event, field_name)
            if key:
                groups[str(key)].append(event)
        weights: dict[str, int] = self.config.health_score_thresholds.get("weights", {})
        ranked: list[dict[str, Any]] = []
        for key, group in groups.items():
            counts = Counter(event.event_type for event in group)
            weighted_score = sum(weights.get(event_type, 0) * count for event_type, count in counts.items())
            ranked.append(
                {
                    field_name: key,
                    "events": len(group),
                    "score": weighted_score,
                    "dominant_event_type": counts.most_common(1)[0][0] if counts else None,
                }
            )
        ranked.sort(key=lambda item: (-item["score"], -item["events"], item[field_name]))
        return ranked[:top_n]

    def _event_ap_name(self, event: NormalizedEvent) -> str | None:
        finder = getattr(self.repository, "find_ap_metadata", None)
        if finder is not None:
            if event.ap_mac:
                metadata = finder(event.ap_mac)
                if metadata is not None:
                    return metadata.ap_name
            if event.ap_name:
                metadata = finder(event.ap_name)
                if metadata is not None:
                    return metadata.ap_name
        return event.ap_name or event.ap_mac

    @staticmethod
    def _counter_to_ranked(
        counter: Counter[str], key_name: str, top_n: int = 10
    ) -> list[dict[str, Any]]:
        return [{key_name: key, "count": count} for key, count in counter.most_common(top_n)]

    def _event_brief(self, event: NormalizedEvent) -> dict[str, Any]:
        return {
            "ts": event.ts.isoformat(),
            "vendor": event.vendor,
            "ap_name": self._event_ap_name(event),
            "client_mac": event.client_mac,
            "ssid": event.ssid,
            "event_type": event.event_type,
            "severity": event.severity,
            "reason_code": event.reason_code,
            "message": event.message,
        }

    @staticmethod
    def _window(minutes: int, start: datetime, end: datetime) -> dict[str, Any]:
        return {"minutes": minutes, "start": start.isoformat(), "end": end.isoformat()}

    @staticmethod
    def _most_common(values: list[str]) -> str | None:
        if not values:
            return None
        return Counter(values).most_common(1)[0][0]

    @staticmethod
    def _dominant_entity_share(ranked: list[dict[str, Any]]) -> float:
        if not ranked:
            return 0.0
        total = sum(item["count"] if "count" in item else item["events"] for item in ranked)
        first = ranked[0]["count"] if "count" in ranked[0] else ranked[0]["events"]
        return first / total if total else 0.0

    def _dominant_categories(self, events: list[NormalizedEvent]) -> list[dict[str, Any]]:
        return self._dominant_categories_from_counts(Counter(event.event_type for event in events))

    @staticmethod
    def _dominant_categories_from_counts(counts: Counter[str]) -> list[dict[str, Any]]:
        noisy_counts = Counter(
            {
                key: value
                for key, value in counts.items()
                if key
                not in {
                    EventType.AUTH_SUCCESS.value,
                    EventType.AP_UP.value,
                    EventType.CLIENT_ASSOCIATED.value,
                    EventType.ROAM_SUCCESS.value,
                }
            }
        )
        return [{"event_type": key, "count": value} for key, value in noisy_counts.most_common(10)]
