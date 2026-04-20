#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/install_systemd_service.sh [options]

Options:
  --service NAME          Service name. Default: wifi-diagnostics-mcp
  --target-dir DIR        Deployment directory. Default: repository root
  --venv-dir DIR          Virtualenv directory relative to target-dir. Default: .venv
  --env-file PATH         Override the EnvironmentFile path
  --description TEXT      systemd Description value
  --dry-run               Render and print actions without mutating systemd.
  -h, --help              Show this help.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_PATH="${PROJECT_ROOT}/deploy/systemd/wifi-diagnostics-mcp.service.template"
ENV_TEMPLATE_PATH="${PROJECT_ROOT}/deploy/systemd/wifi-diagnostics-mcp.env.example"
ENV_TEMPLATE_ROOT="/opt/wifi-diagnostics-mcp"

SERVICE_NAME="wifi-diagnostics-mcp"
TARGET_DIR="${PROJECT_ROOT}"
VENV_DIR=".venv"
ENV_FILE=""
DESCRIPTION="Wi-Fi Diagnostics MCP Server"
DRY_RUN="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --target-dir)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --description)
      DESCRIPTION="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "Missing service template: ${TEMPLATE_PATH}" >&2
  exit 1
fi

if [[ ! -f "${ENV_TEMPLATE_PATH}" ]]; then
  echo "Missing environment template: ${ENV_TEMPLATE_PATH}" >&2
  exit 1
fi

if [[ ! -d "${TARGET_DIR}" ]]; then
  echo "Target directory does not exist: ${TARGET_DIR}" >&2
  exit 1
fi

if [[ -z "${ENV_FILE}" ]]; then
  ENV_FILE="/etc/${SERVICE_NAME}/${SERVICE_NAME}.env"
fi

if [[ "${DRY_RUN}" != "1" ]] && ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required but was not found" >&2
  exit 1
fi

UNIT_DIR="/etc/systemd/system"
UNIT_PATH="${UNIT_DIR}/${SERVICE_NAME}.service"
ENV_DIR="$(dirname "${ENV_FILE}")"

if [[ "${EUID}" -eq 0 ]]; then
  INSTALL_PREFIX=()
  SYSTEMCTL_CMD=(systemctl)
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required for system service installation" >&2
    exit 1
  fi
  if [[ "${DRY_RUN}" != "1" ]] && ! sudo -n true >/dev/null 2>&1; then
    echo "system service installation requires root or passwordless sudo for non-interactive execution" >&2
    exit 1
  fi
  INSTALL_PREFIX=(sudo)
  SYSTEMCTL_CMD=(sudo systemctl)
fi

if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" ]]; then
  SERVICE_USER="${SUDO_USER}"
else
  SERVICE_USER="$(id -un)"
fi

if [[ "${SERVICE_USER}" == "root" ]]; then
  echo "root is not allowed as the systemd User= account; run the installer as a non-root SSH user and escalate with sudo only for systemd writes" >&2
  exit 1
fi

if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  echo "Service user does not exist: ${SERVICE_USER}" >&2
  exit 1
fi

SERVICE_GROUP="$(id -gn "${SERVICE_USER}")"

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[&|\\]/\\&/g'
}

rendered_unit="$(mktemp)"
rendered_env="$(mktemp)"
trap 'rm -f "${rendered_unit}" "${rendered_env}"' EXIT

sed \
  -e "s|__DESCRIPTION__|$(escape_sed_replacement "${DESCRIPTION}")|g" \
  -e "s|__SERVICE_USER__|$(escape_sed_replacement "${SERVICE_USER}")|g" \
  -e "s|__SERVICE_GROUP__|$(escape_sed_replacement "${SERVICE_GROUP}")|g" \
  -e "s|__TARGET_DIR__|$(escape_sed_replacement "${TARGET_DIR}")|g" \
  -e "s|__VENV_DIR__|$(escape_sed_replacement "${VENV_DIR}")|g" \
  -e "s|__ENV_FILE__|$(escape_sed_replacement "${ENV_FILE}")|g" \
  "${TEMPLATE_PATH}" > "${rendered_unit}"

sed \
  -e "s|${ENV_TEMPLATE_ROOT}|$(escape_sed_replacement "${TARGET_DIR}")|g" \
  "${ENV_TEMPLATE_PATH}" > "${rendered_env}"

if [[ "${DRY_RUN}" == "1" ]]; then
  echo "Dry run: would install ${UNIT_PATH}"
  echo
  cat "${rendered_unit}"
  if [[ ! -f "${ENV_FILE}" ]]; then
    echo
    echo "Dry run: would create ${ENV_FILE} from ${ENV_TEMPLATE_PATH}"
    cat "${rendered_env}"
  fi
  exit 0
fi

"${INSTALL_PREFIX[@]}" install -d -m 0755 "${UNIT_DIR}"
"${INSTALL_PREFIX[@]}" install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0755 "${ENV_DIR}"
if [[ ! -f "${ENV_FILE}" ]]; then
  "${INSTALL_PREFIX[@]}" install -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0640 "${rendered_env}" "${ENV_FILE}"
fi
"${INSTALL_PREFIX[@]}" install -m 0644 "${rendered_unit}" "${UNIT_PATH}"
"${SYSTEMCTL_CMD[@]}" daemon-reload
"${SYSTEMCTL_CMD[@]}" enable --now "${SERVICE_NAME}.service"
"${SYSTEMCTL_CMD[@]}" restart "${SERVICE_NAME}.service"
"${SYSTEMCTL_CMD[@]}" status "${SERVICE_NAME}.service" --no-pager
