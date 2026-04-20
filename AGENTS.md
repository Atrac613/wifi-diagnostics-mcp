# AGENTS.md

## Project Summary

`wifi-diagnostics-mcp` is a Python 3.11+ Wi-Fi diagnostics MCP server.

Its job is to ingest Wi-Fi syslog, preserve raw records, normalize
Wi-Fi-relevant events, and expose fact-centered MCP tools for LLM clients.

This repository intentionally does not try to be:

- A full SIEM or log lake
- A packet capture or RF telemetry product
- A controller-specific management plane
- A complete parser for every firmware variant from every vendor

When making changes, prefer a practical diagnostics MVP mindset:

- Keep ingestion resilient
- Keep raw and normalized storage separate
- Preserve unknown events instead of dropping them
- Prefer small, explicit, typed components over framework-heavy abstractions
- Keep MCP transport behavior standard-oriented

## Repository Layout

- `src/wifi_diagnostics_mcp/server.py`: CLI entrypoint and MCP transports
- `src/wifi_diagnostics_mcp/service.py`: orchestration for ingest, parse, store, and analytics
- `src/wifi_diagnostics_mcp/analytics.py`: Wi-Fi health score and diagnostics summaries
- `src/wifi_diagnostics_mcp/storage.py`: SQLite repository and query layer
- `src/wifi_diagnostics_mcp/vendor_detection.py`: vendor classification
- `src/wifi_diagnostics_mcp/receiver.py`: UDP/TCP syslog listeners
- `src/wifi_diagnostics_mcp/parsers/`: vendor parser implementations
- `src/wifi_diagnostics_mcp/mcp/`: tools, resources, and prompts
- `tests/`: parser, analytics, and transport tests
- `tests/fixtures/`: Cisco and Netgear sample logs
- `scripts/deploy_remote.sh`: SSH + `rsync` deployment helper
- `scripts/install_systemd_service.sh`: systemd system-service installer
- `scripts/run_server.sh`: service runtime wrapper
- `deploy/systemd/`: systemd unit template and env example

## Working Agreements

- Keep the project Python 3.11+ and standard-library-first
- Preserve the repository abstraction so storage can move beyond SQLite later
- Do not let parser failures block raw syslog ingestion
- Keep unknown events queryable and visible for future parser work
- When adding parser rules, prefer precise vendor-specific regexes over vague
  generic heuristics
- When adding new event mappings, update tests first or alongside the code
- When parser changes alter user-visible behavior, update `README.md`
- When MCP transport semantics change, update transport tests and examples
- When new benign controller noise is recognized, consider whether it should
  stay visible but be excluded from health-score penalties

## Coding Guidelines

- Use clear type hints and the existing dataclass-based models
- Keep helpers small and focused
- Prefer readable, explicit code over deep abstraction
- Keep comments brief and high signal
- Avoid new dependencies unless they materially simplify the implementation
- Preserve standard JSON-RPC message shapes for MCP clients
- Avoid inventing custom wire envelopes unless a documented MCP behavior
  requires them

## Parser Guidance

- Treat vendor syslog formats as unstable and firmware-specific
- Normalize only when the event meaning is sufficiently clear
- If meaning is ambiguous, keep the event as `unknown_wifi_event`
- Keep the original raw message available for search results and examples
- Use `reason_code` for compact diagnostic context that survives aggregation
- If an event is operationally noisy but still worth preserving, prefer tagging
  it as `unknown_wifi_event` with a `reason_code` prefix such as `noise:`

## Analytics Guidance

- Health score is a heuristic, not a promise of end-user experience
- Low observation volume should not automatically score as perfect
- Noise-tagged events should not dominate the score
- AP/client ranking should remain fact-based and easy for LLM clients to use
- Keep `interpretation_hint` short and observational rather than speculative

## Validation

Run this before finishing a non-trivial change:

```bash
python3 -m unittest discover -s tests -v
```

Useful focused runs:

```bash
python3 -m unittest tests.test_cisco_parser -v
python3 -m unittest tests.test_analytics -v
python3 -m unittest tests.test_tools -v
```

For documentation-only changes, use judgment about which commands are necessary.

## Deployment Notes

- `scripts/deploy_remote.sh` is the supported remote deploy helper
- The supported deploy flow installs a systemd system service, not a user service
- The deploy flow syncs directly into `--target-dir`; do not reintroduce `releases/` or a `current` symlink layout unless there is a strong operational reason
- Keep service installation logic in `scripts/install_systemd_service.sh`, not inline in `scripts/deploy_remote.sh`
- Default the systemd `EnvironmentFile` to `/etc/<service>/<service>.env` for parity with `zeek-mcp`
- Do not preserve or recreate a compatibility `current` symlink during deploy; the supported runtime path is `scripts/run_server.sh` plus the installed systemd unit
- The generated unit runs as the remote SSH user with `Restart=on-failure`
- Root SSH login is rejected in the deploy helper; keep the service on a non-root account
- Shared runtime paths should remain writable by that same remote SSH user
- The deploy helper should fail fast if non-interactive `sudo` is unavailable on the remote host
- Explicit deploy CLI overrides such as transport, ports, and `DB_PATH` should be written back into the remote env file so the service matches the invoked deploy command
- The deploy helper should prepare parent directories for env-driven runtime paths such as `DB_PATH` and `RAW_SYSLOG_ARCHIVE_PATH`
- Read env files as data during deploy; do not `source` them just to inspect runtime paths
- Parser and analytics changes may require a process restart to affect live MCP
  responses
- Existing `normalized_events` are not automatically backfilled after parser
  changes, so be explicit about whether a task needs reparse/backfill behavior

## Commit Messages

Write Git commit messages in English using a modern Conventional Commits style.

Preferred format:

```text
type(scope): short imperative summary
```

Examples:

```text
feat(parser): normalize Cisco Mobility Express disassoc events
fix(analytics): ignore parser-tagged controller noise in health score
test(mcp): assert streamable HTTP wire format
docs(readme): clarify supported MCP transports
chore(repo): add AGENTS and MIT license
```

Guidelines:

- Use English only
- Keep the subject concise and specific
- Use the imperative mood
- Do not end the subject with a period
- Prefer lowercase type names such as `feat`, `fix`, `docs`, `refactor`,
  `test`, and `chore`
- Add a scope when it improves clarity

## Change Checklist

Before wrapping up, quickly confirm:

- Raw syslog ingestion still works even when parsing changes
- Unknown events are preserved where normalization is uncertain
- Tests cover the affected parser, analytics, or transport behavior
- `README.md` still matches the public surface and operational guidance
- MCP responses stay parseable by standard-oriented clients
