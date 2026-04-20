from __future__ import annotations

import re

from .models import Vendor


class VendorDetector:
    _netgear_patterns = (
        re.compile(r"NETGEAR(?:_AP)?", re.IGNORECASE),
        re.compile(r"\b(WAX\d+|wlceventd|hostapd|Insight)\b", re.IGNORECASE),
    )
    _cisco_patterns = (
        re.compile(r"%[A-Z0-9_-]+-\d-"),
        re.compile(r"\b(CAPWAP|DOT1X|APF|RRM|DFS|WLC|EWC)\b", re.IGNORECASE),
    )

    def detect(self, raw_message: str) -> Vendor:
        for pattern in self._netgear_patterns:
            if pattern.search(raw_message):
                return Vendor.NETGEAR
        for pattern in self._cisco_patterns:
            if pattern.search(raw_message):
                return Vendor.CISCO
        return Vendor.UNKNOWN
