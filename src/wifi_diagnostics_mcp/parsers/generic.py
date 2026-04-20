from __future__ import annotations

from ..models import ParseOutcome, RawSyslogRecord, Vendor
from .base import BaseParser


class GenericParser(BaseParser):
    vendor_name = Vendor.UNKNOWN.value
    parser_version = "generic-regex-1.0"

    def parse(self, record: RawSyslogRecord) -> ParseOutcome:
        return self.build_unknown_event(record, vendor=record.vendor_guess or self.vendor_name)

