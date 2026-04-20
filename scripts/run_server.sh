#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${WIFI_DIAGNOSTICS_MCP_VENV_DIR:-.venv}"
PYTHON_BIN="${PROJECT_ROOT}/${VENV_DIR}/bin/python"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Python executable not found: ${PYTHON_BIN}" >&2
  echo "Create the virtualenv first or set WIFI_DIAGNOSTICS_MCP_VENV_DIR." >&2
  exit 1
fi

: "${WIFI_DIAGNOSTICS_MCP_TRANSPORT:=http}"

exec "${PYTHON_BIN}" -m wifi_diagnostics_mcp --transport "${WIFI_DIAGNOSTICS_MCP_TRANSPORT}" "$@"
