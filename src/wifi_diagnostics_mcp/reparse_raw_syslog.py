from __future__ import annotations

import json

from .config import AppConfig
from .service import WiFiDiagnosticsService
from .storage import SQLiteRepository


def main() -> None:
    config = AppConfig.from_env()
    repository = SQLiteRepository(config.db_path)
    repository.initialize()
    service = WiFiDiagnosticsService(repository, config)
    try:
        result = service.reparse_saved_raw_syslog()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        repository.close()


if __name__ == "__main__":
    main()
