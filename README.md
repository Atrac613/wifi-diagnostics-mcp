# Wi-Fi Diagnostics MCP Server

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`wifi-diagnostics-mcp` is a Python 3.11+ MCP server focused on Wi-Fi diagnostics.

It ingests syslog from Wi-Fi APs and controllers, stores raw messages, normalizes
Wi-Fi-relevant events, and exposes fact-centered MCP tools for LLM clients.

The current implementation targets Cisco and Netgear first, while keeping the
parser and storage layers extensible for additional vendors and backends.

## Status

This repository is usable today as a practical Wi-Fi diagnostics MVP.

What it is:

- A Wi-Fi-specific syslog ingestion pipeline with raw and normalized storage
- A plugin-style parser architecture for Cisco, Netgear, and generic fallback
- A diagnostics-oriented MCP server with tools, resources, and prompts
- A lightweight analytics layer for health score, auth failures, disconnects,
  roaming issues, and AP/client instability
- A standard-oriented MCP HTTP transport that behaves like a stateless
  `2025-03-26` Streamable HTTP server on `POST /mcp`

What it is not:

- A general-purpose SIEM or log search platform
- A packet capture or RF telemetry system
- A full controller integration for every Wi-Fi vendor
- A replacement for DHCP, DNS, RADIUS, or upstream network observability

## Highlights

- UDP syslog receiver with optional TCP syslog support
- SQLite storage with separate `raw_syslog` and `normalized_events` tables
- Optional raw syslog JSONL archive mirroring via `RAW_SYSLOG_ARCHIVE_PATH`
- Restricted sample-log ingestion roots via `SAMPLE_LOG_ROOTS`
- Developer-only tooling gated by `ENABLE_DEV_TOOLS`
- MCP transports:
  - stdio
  - HTTP JSON-RPC on `POST /mcp`
  - SSE response mode on `POST /mcp?stream=1`
- Cisco and Netgear regex-based parsers with unknown-event retention
- Wi-Fi analytics for:
  - health score
  - auth failures
  - disconnect summaries
  - roaming issues
  - AP status
  - client instability
- Remote deployment helper via [`scripts/deploy_remote.sh`](scripts/deploy_remote.sh)
  - installs a systemd system service by default

## Getting Started

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This project currently runs on the Python standard library only.

## Quick Start

Run the default stdio MCP server with the syslog receiver:

```bash
python3 -m wifi_diagnostics_mcp
```

Run HTTP only:

```bash
python3 -m wifi_diagnostics_mcp --transport http
```

Run both stdio and HTTP:

```bash
python3 -m wifi_diagnostics_mcp --transport both
```

Example HTTP `initialize` request:

```bash
curl -s http://127.0.0.1:8765/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-03-26",
      "capabilities": {},
      "clientInfo": {
        "name": "example-client",
        "version": "1.0"
      }
    }
  }'
```

Example `tools/list` request:

```bash
curl -s http://127.0.0.1:8765/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
  }'
```

## Supported Vendors

### Cisco

Current Cisco normalization includes practical support for:

- `client_associated`
- `client_disassociated`
- `client_deauthenticated`
- `auth_success`
- `auth_failure`
- `roam_failure`
- `poor_rssi`
- `channel_interference`
- `ap_down`
- `radar_or_dfs_event`

Recent Mobility Express-oriented coverage also includes examples such as:

- `DOT1X-3-INVALID_REPLAY_CTR` as `auth_failure`
- `DOT1X-6-11R_FORCED_AUTH` as `roam_success`
- `APF-3-ASSOC_REQ_FAILED` as `auth_failure`
- `DOT11-5-EXPECTED_RADIO_RESET` as a radio-scoped `ap_down`
- `DOT11-6-DISASSOC` as `client_disassociated` or `client_deauthenticated`
- `LINK-6-UPDOWN`, `LINEPROTO-5-UPDOWN`, and `LINK-5-CHANGED` as radio state changes
- `LOG-4-Q_IND` / `LOG-6-Q_IND` association failures as `auth_failure`

The Cisco parser also recognizes several controller/AP noise patterns and keeps
them as `unknown_wifi_event` records tagged with `reason_code` values prefixed
with `noise:` so they can be de-emphasized in health scoring.

Current noise tagging includes:

- `OSAPI-*`
- `APF-6-RADIUS_OVERRIDE_DISABLED`
- `APF-6-USE_DEFAULT_CIPHER_SUITE`
- `LOG-6-Q_IND` when it mirrors the default-cipher controller message
- `AAA-5-AAA_AUTH_ADMIN_USER`
- `CLEANAIR-6-STATE` when the state is `enabled`

`CLEANAIR-6-STATE` with `down` is preserved as a low-priority unknown signal
instead of being fully suppressed as noise.

`APF-4-MOBILESTATION_NOT_FOUND` is also preserved as a low-priority unknown
signal with `reason_code=mobile_station_not_found`. It stays searchable and
visible in AP drilldowns, but it does not contribute to health-score penalties
or AP/client issue rankings.

`SAFEC-3-SAFEC_ERROR` is preserved in the same way with a compact
`reason_code` such as `safec_error:memcpy_s_n_exceeds_dmax`, so internal
controller instability remains visible without being mistaken for a direct
client Wi-Fi failure signal.

### Netgear

Current Netgear normalization includes:

- `client_associated`
- `client_disassociated`
- `client_deauthenticated`
- `auth_failure`
- `roam_failure`
- `dhcp_issue`
- `dns_issue`
- `poor_rssi`
- `channel_interference`
- `ap_down`
- `radar_or_dfs_event`

### Unknown and Unsupported Events

Unknown events are not dropped.

They are stored in `raw_syslog`, normalized into `unknown_wifi_event`, and kept
available for future parser improvements and for controlled search results.

## MCP Surface

### Tools

- `get_wifi_health`
- `compare_wifi_windows`
- `get_ap_status`
- `get_client_instability`
- `get_auth_failures`
- `get_disconnect_reasons`
- `get_roaming_issues`
- `search_wifi_events`
- `explain_network_slowdown_context`

When `ENABLE_DEV_TOOLS=true`, one extra tool is exposed:

- `ingest_sample_logs`

`ingest_sample_logs` is intended for development workflows only and only reads
files from configured sample roots.

### Resources

- `wifi://health/latest`
- `wifi://config`
- `wifi://aps`
- `wifi://clients/top-unstable`
- `wifi://parsers`

### Prompts

- `diagnose_wifi_issue`
- `investigate_ap_instability`
- `investigate_client_wifi_problem`

## Architecture

- `receiver`
  - UDP syslog is the default ingress path
  - TCP syslog can be enabled with `ENABLE_TCP_SYSLOG=true`
  - Adds receive timestamp and sender IP
- `classifier`
  - Estimates `cisco`, `netgear`, or `unknown`
- `parser`
  - Vendor-specific parser plugins under `src/wifi_diagnostics_mcp/parsers/`
  - Unknown or unsupported events are retained instead of dropped
- `storage`
  - SQLite implementation with a repository abstraction
  - Designed to be replaceable with PostgreSQL or ClickHouse later
- `analytics`
  - Time-window summaries, AP/client ranking, auth failure summaries,
    disconnect summaries, roaming summaries, and health score
- `mcp`
  - Tool, resource, and prompt definitions plus stdio and HTTP transport

## Data Model

Primary tables:

- `raw_syslog`
  - `id`, `received_at`, `sender_ip`, `raw_message`, `vendor_guess`,
    `parse_status`, `parse_error`
- `normalized_events`
  - `id`, `ts`, `vendor`, `device_id`, `ap_name`, `ap_mac`, `client_mac`,
    `client_ip`, `ssid`, `band`, `radio`, `channel`, `event_type`, `severity`,
    `reason_code`, `message`, `raw_event_id`, `parser_version`
- `ap_metadata`
  - `ap_name`, `vendor`, `mgmt_ip`, `location`, `model`, `notes`
- `client_aliases`
  - `client_mac`, `alias`, `notes`

## Configuration

Environment variables:

- `SYSLOG_UDP_PORT`
- `SYSLOG_TCP_PORT`
- `SYSLOG_TIMESTAMP_TIMEZONE`
- `DB_PATH`
- `RAW_SYSLOG_ARCHIVE_PATH`
- `SAMPLE_LOG_ROOTS`
- `ENABLE_DEV_TOOLS`
- `ENABLE_TCP_SYSLOG`
- `ENABLE_HTTP_MCP`
- `MCP_HTTP_HOST`
- `MCP_HTTP_PORT`
- `MCP_HTTP_AUTH_TOKEN`
- `MCP_HTTP_ALLOWED_ORIGINS`
- `DEFAULT_LOOKBACK_MINUTES`
- `HEALTH_SCORE_THRESHOLDS`
- `ENABLE_VENDOR_AUTO_DETECT`

Example:

```bash
export SYSLOG_UDP_PORT=5514
export SYSLOG_TCP_PORT=5515
export SYSLOG_TIMESTAMP_TIMEZONE=UTC
export DB_PATH=./wifi_diagnostics.db
export RAW_SYSLOG_ARCHIVE_PATH=./raw_syslog.jsonl
export SAMPLE_LOG_ROOTS=./tests/fixtures
export ENABLE_DEV_TOOLS=false
export ENABLE_TCP_SYSLOG=false
export ENABLE_HTTP_MCP=true
export MCP_HTTP_HOST=127.0.0.1
export MCP_HTTP_PORT=8765
export MCP_HTTP_AUTH_TOKEN=
export MCP_HTTP_ALLOWED_ORIGINS=
export DEFAULT_LOOKBACK_MINUTES=30
```

This example keeps HTTP MCP on loopback by default. If you want to expose it to
other hosts, explicitly switch `MCP_HTTP_HOST=0.0.0.0` and set a non-empty
`MCP_HTTP_AUTH_TOKEN`.

Remote deploy helper example:

```bash
scripts/deploy_remote.sh \
  --host ops@example.com \
  --target-dir /opt/wifi-diagnostics-mcp \
  --env-file deploy/systemd/wifi-diagnostics-mcp.env.example
```

The bundled env example assumes `/opt/wifi-diagnostics-mcp`. If you deploy to a
different target directory, edit the copied env file or let the deploy helper
write its default env on first install.

By default, the installed systemd unit reads its environment from
`/etc/wifi-diagnostics-mcp/wifi-diagnostics-mcp.env`.

The bundled systemd env example also keeps `MCP_HTTP_HOST=127.0.0.1` by
default. Exposing HTTP MCP on `0.0.0.0` is an explicit opt-in and should be
paired with `MCP_HTTP_AUTH_TOKEN`.

## Syslog Sender Notes

Cisco Mobility Express and related Cisco AP/controller deployments often behave
as if syslog is sent to UDP/514 with limited port customization in the UI.

Netgear devices typically expose remote syslog settings in the web UI with a
server address and logging options.

This server can receive higher, non-privileged ports by default, but it can also
be deployed on UDP/514 when the runtime has permission to bind that port.

When HTTP MCP is exposed beyond loopback, set `MCP_HTTP_AUTH_TOKEN` and send it
as `Authorization: Bearer <token>` from clients. If browser-based clients need
access, explicitly allow their origins with `MCP_HTTP_ALLOWED_ORIGINS` as a
comma-separated list such as `https://ops.example,https://console.example`.

The stdio transport writes newline-delimited JSON-RPC messages to stdout. For
backwards compatibility during migration, it still accepts legacy
`Content-Length` framed input on stdin.

The supported remote deploy flow installs a systemd system service under
`/etc/systemd/system`. It now deploys directly into `--target-dir` rather than
publishing a `current` symlink, and it keeps the systemd setup in
`scripts/install_systemd_service.sh` with `scripts/run_server.sh` as the
service entrypoint.

This repository no longer maintains any compatibility `current` symlink during
deploy. Hosts should run the split systemd setup directly against
`scripts/run_server.sh` and `/etc/wifi-diagnostics-mcp/wifi-diagnostics-mcp.env`.

When you pass deploy-time CLI overrides such as `--transport`, `--http-port`,
or `--db-path`, the deploy helper now writes those values back into the remote
env file as explicit overrides. That keeps the installed service consistent
with the command you just ran, even when the env file already existed.

Unless you override `--env-file`, the deploy helper targets the same default
path as the installer: `/etc/wifi-diagnostics-mcp/wifi-diagnostics-mcp.env`.

The generated unit runs as the remote SSH user and adds
`CAP_NET_BIND_SERVICE`, so privileged syslog ports such as UDP 514 remain
usable without running the process as root.

For a system service, `scripts/deploy_remote.sh` always sets `User=` to the
remote SSH user. Root SSH login is rejected, so use a non-root account such as
`ubuntu` or a dedicated `wifi-diagnostics-mcp` user for deployment.

Runtime paths under `shared/` and the deployment root are re-owned to that same
remote SSH user so the service can write SQLite data and raw syslog archives
without needing a separate service-account configuration path.

The deploy helper is intentionally non-interactive and checks `sudo -n true`
up front. Configure passwordless `sudo` for the remote SSH user before running
the deployment flow.

Before installing or restarting the service, the deploy helper reads the remote
env file and prepares the parent directories for `DB_PATH` and
`RAW_SYSLOG_ARCHIVE_PATH`. This also covers paths outside the target directory,
such as a dedicated mounted data volume. The helper parses `KEY=VALUE` lines
directly instead of shell-sourcing the env file during deploy.

If a sender omits timezone information in the syslog timestamp, this server uses
`SYSLOG_TIMESTAMP_TIMEZONE` to interpret that clock time before converting the
stored normalized event timestamp back to UTC. It also applies a nearest-year
heuristic to avoid year-rollover mistakes around January.

When you change `SYSLOG_TIMESTAMP_TIMEZONE` for an existing deployment, already
saved `normalized_events` will still keep the old interpretation. To rebuild
them from `raw_syslog`, run:

```bash
python3 -m wifi_diagnostics_mcp.reparse_raw_syslog
```

## Health Score

The health score is a practical 0-100 heuristic, not a universal Wi-Fi truth.

It uses weighted penalties for event categories such as:

- `auth_failure`
- `client_disassociated`
- `client_deauthenticated`
- `roam_failure`
- `ap_down`
- `poor_rssi`
- `channel_interference`
- `dhcp_issue`
- `dns_issue`
- `unknown_wifi_event`

Important nuance:

- low observation volume is capped to avoid treating “no data” as perfect health
- parser-tagged noise events with `reason_code` values starting with `noise:`
  are excluded from health score penalties and AP/client issue rankings
- selected low-priority unknown signals such as `mobile_station_not_found`
  and `safec_error:*`
  are also excluded from health score penalties and AP/client issue rankings
  while remaining visible in drilldown views
- `search_wifi_events` returns normalized fields by default and only includes
  `raw_message` when `include_raw=true` is requested

That keeps noisy controller internals from dominating the score while still
preserving the raw and normalized event trail.

## Repository Layout

- `src/wifi_diagnostics_mcp/server.py`: CLI entrypoint and MCP transports
- `src/wifi_diagnostics_mcp/service.py`: orchestration for ingest, parse, store, and analytics
- `src/wifi_diagnostics_mcp/analytics.py`: Wi-Fi health scoring and summaries
- `src/wifi_diagnostics_mcp/storage.py`: SQLite repository and query layer
- `src/wifi_diagnostics_mcp/vendor_detection.py`: vendor classification
- `src/wifi_diagnostics_mcp/parsers/`: vendor parser implementations
- `src/wifi_diagnostics_mcp/mcp/`: MCP tools, resources, and prompts
- `tests/`: parser, analytics, and transport tests
- `tests/fixtures/`: Cisco and Netgear sample logs
- `scripts/deploy_remote.sh`: SSH + `rsync` remote deployment helper
- `scripts/install_systemd_service.sh`: systemd system-service installer
- `scripts/run_server.sh`: systemd-friendly runtime wrapper
- `deploy/systemd/`: systemd unit template and env example

## Development

Run the full verification set:

```bash
python3 -m unittest discover -s tests -v
```

Useful focused test runs:

```bash
python3 -m unittest tests.test_cisco_parser -v
python3 -m unittest tests.test_tools -v
```

## Limitations

- Parsing is regex-based and intentionally conservative
- Not every Cisco or Netgear firmware variant is covered yet
- Existing `normalized_events` are not automatically backfilled when parser
  logic changes
- `ingest_sample_logs` is intentionally restricted to configured sample roots
- `ingest_sample_logs` is disabled unless `ENABLE_DEV_TOOLS=true`
- Syslog sender timestamps do not carry timezone metadata, so correct
  interpretation still depends on a sensible `SYSLOG_TIMESTAMP_TIMEZONE`
- SQLite is appropriate for the MVP but not ideal for large sustained ingest
- Wi-Fi diagnosis here is event-driven; it does not replace RF telemetry,
  controller APIs, or packet inspection

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
