#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/deploy_remote.sh --host user@example.com --target-dir /opt/wifi-diagnostics-mcp [options]

Options:
  --host HOST                  Remote SSH target in ssh-compatible form.
  --target-dir DIR             Remote deployment directory.
  --target TARGET              Backward-compatible alias for --host.
  --app-dir DIR                Backward-compatible alias for --target-dir.
  --ssh-port PORT              SSH port. Default: 22
  --service NAME               systemd service name. Default: wifi-diagnostics-mcp
  --service-name NAME          Alias for --service.
  --env-file PATH              Local env file to upload to the remote EnvironmentFile path.
  --remote-python BIN          Remote Python interpreter. Default: python3
  --python-bin PATH            Alias for --remote-python.
  --venv-dir DIR               Remote virtualenv directory relative to target-dir. Default: .venv
  --transport VALUE            stdio|http|both. Default: both
  --http-host HOST             HTTP bind host. Default: 127.0.0.1
  --http-port PORT             HTTP bind port. Default: 8765
  --syslog-udp-port PORT       Syslog UDP port. Default: 5514
  --syslog-tcp-port PORT       Syslog TCP port. Default: 5515
  --enable-tcp-syslog BOOL     true|false. Default: false
  --enable-http-mcp BOOL       true|false. Default: true
  --default-lookback MINUTES   Default lookback minutes. Default: 30
  --db-path PATH               SQLite path on the remote host. Default: <target-dir>/shared/data/wifi_diagnostics.db
  --no-service                 Deploy files but do not install/restart the systemd service.
  --dry-run                    Print actions without mutating the remote host.
  --skip-tests                 Skip local unit tests before deploy.
  --help                       Show this help.

Examples:
  scripts/deploy_remote.sh \
    --host ops@example.com \
    --target-dir /opt/wifi-diagnostics-mcp \
    --env-file deploy/systemd/wifi-diagnostics-mcp.env.example

  scripts/deploy_remote.sh \
    --host ops@example.com \
    --target-dir /opt/wifi-diagnostics-mcp \
    --transport both \
    --http-port 8765 \
    --syslog-udp-port 5514
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

HOST=""
TARGET_DIR=""
SSH_PORT="22"
SERVICE_NAME="wifi-diagnostics-mcp"
ENV_FILE=""
REMOTE_PYTHON="python3"
VENV_DIR=".venv"
TRANSPORT="both"
TRANSPORT_SET="false"
HTTP_HOST="127.0.0.1"
HTTP_HOST_SET="false"
HTTP_PORT="8765"
HTTP_PORT_SET="false"
SYSLOG_UDP_PORT="5514"
SYSLOG_UDP_PORT_SET="false"
SYSLOG_TCP_PORT="5515"
SYSLOG_TCP_PORT_SET="false"
ENABLE_TCP_SYSLOG="false"
ENABLE_TCP_SYSLOG_SET="false"
ENABLE_HTTP_MCP="true"
ENABLE_HTTP_MCP_SET="false"
DEFAULT_LOOKBACK_MINUTES="30"
DEFAULT_LOOKBACK_MINUTES_SET="false"
DB_PATH=""
DB_PATH_SET="false"
NO_SERVICE="false"
DRY_RUN="false"
SKIP_TESTS="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --target-dir)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --target)
      HOST="${2:-}"
      shift 2
      ;;
    --app-dir)
      TARGET_DIR="${2:-}"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="${2:-}"
      shift 2
      ;;
    --service)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --service-name)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --remote-python)
      REMOTE_PYTHON="${2:-}"
      shift 2
      ;;
    --python-bin)
      REMOTE_PYTHON="${2:-}"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="${2:-}"
      shift 2
      ;;
    --transport)
      TRANSPORT="${2:-}"
      TRANSPORT_SET="true"
      shift 2
      ;;
    --http-host)
      HTTP_HOST="${2:-}"
      HTTP_HOST_SET="true"
      shift 2
      ;;
    --http-port)
      HTTP_PORT="${2:-}"
      HTTP_PORT_SET="true"
      shift 2
      ;;
    --syslog-udp-port)
      SYSLOG_UDP_PORT="${2:-}"
      SYSLOG_UDP_PORT_SET="true"
      shift 2
      ;;
    --syslog-tcp-port)
      SYSLOG_TCP_PORT="${2:-}"
      SYSLOG_TCP_PORT_SET="true"
      shift 2
      ;;
    --enable-tcp-syslog)
      ENABLE_TCP_SYSLOG="${2:-}"
      ENABLE_TCP_SYSLOG_SET="true"
      shift 2
      ;;
    --enable-http-mcp)
      ENABLE_HTTP_MCP="${2:-}"
      ENABLE_HTTP_MCP_SET="true"
      shift 2
      ;;
    --default-lookback)
      DEFAULT_LOOKBACK_MINUTES="${2:-}"
      DEFAULT_LOOKBACK_MINUTES_SET="true"
      shift 2
      ;;
    --db-path)
      DB_PATH="${2:-}"
      DB_PATH_SET="true"
      shift 2
      ;;
    --no-service)
      NO_SERVICE="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    --skip-tests)
      SKIP_TESTS="true"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "${HOST}" ]]; then
  echo "--host is required" >&2
  usage >&2
  exit 1
fi

if [[ -z "${TARGET_DIR}" ]]; then
  echo "--target-dir is required" >&2
  usage >&2
  exit 1
fi

if [[ -n "${ENV_FILE}" && ! -f "${ENV_FILE}" ]]; then
  echo "env file not found: ${ENV_FILE}" >&2
  exit 1
fi

for required_cmd in ssh rsync; do
  if ! command -v "${required_cmd}" >/dev/null 2>&1; then
    echo "Missing required local command: ${required_cmd}" >&2
    exit 1
  fi
done

SSH_CMD=(ssh -p "${SSH_PORT}")
SCP_CMD=(scp -P "${SSH_PORT}")
RSYNC_SSH_CMD="ssh -p ${SSH_PORT}"

REMOTE_HOME="$("${SSH_CMD[@]}" "${HOST}" 'printf %s "$HOME"')"
if [[ -z "${REMOTE_HOME}" ]]; then
  echo "Failed to determine remote home directory for ${HOST}" >&2
  exit 1
fi

REMOTE_LOGIN_USER="$("${SSH_CMD[@]}" "${HOST}" 'id -un')"
REMOTE_LOGIN_GROUP="$("${SSH_CMD[@]}" "${HOST}" 'id -gn')"
if [[ -z "${REMOTE_LOGIN_USER}" || -z "${REMOTE_LOGIN_GROUP}" ]]; then
  echo "Failed to determine remote login user/group for ${HOST}" >&2
  exit 1
fi

if [[ "${REMOTE_LOGIN_USER}" == "root" ]]; then
  echo "root SSH login is not allowed for deploy; use a non-root account such as ubuntu or a dedicated wifi-diagnostics-mcp user" >&2
  exit 1
fi

if [[ "${TARGET_DIR}" == "~" ]]; then
  TARGET_DIR="${REMOTE_HOME}"
elif [[ "${TARGET_DIR}" == ~/* ]]; then
  TARGET_DIR="${REMOTE_HOME}${TARGET_DIR#"~"}"
fi

if [[ -z "${DB_PATH}" ]]; then
  DB_PATH="${TARGET_DIR}/shared/data/wifi_diagnostics.db"
elif [[ "${DB_PATH}" == "~" ]]; then
  DB_PATH="${REMOTE_HOME}"
elif [[ "${DB_PATH}" == ~/* ]]; then
  DB_PATH="${REMOTE_HOME}${DB_PATH#"~"}"
fi

SHARED_DIR="${TARGET_DIR}/shared"
SHARED_DATA_DIR="${SHARED_DIR}/data"
REMOTE_ENV_DIR="/etc/${SERVICE_NAME}"
REMOTE_ENV_PATH="${REMOTE_ENV_DIR}/${SERVICE_NAME}.env"
REMOTE_VENV_PATH="${TARGET_DIR}/${VENV_DIR}"

check_remote_sudo() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: skipping remote sudo preflight"
    return
  fi
  echo "Checking remote passwordless sudo availability"
  if ! "${SSH_CMD[@]}" "${HOST}" "sudo -n true" >/dev/null 2>&1; then
    echo "remote host does not allow non-interactive sudo for ${REMOTE_LOGIN_USER}; configure passwordless sudo before running deploy" >&2
    exit 1
  fi
}

run_local_tests() {
  if [[ "${SKIP_TESTS}" == "true" ]]; then
    echo "Skipping local tests"
    return
  fi
  echo "Running local unit tests before deploy"
  (
    cd "${PROJECT_ROOT}"
    python3 -m unittest discover -s tests -v
  )
}

create_remote_layout() {
  echo "Preparing remote directories on ${HOST}:${TARGET_DIR}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would create ${TARGET_DIR}, ${SHARED_DATA_DIR}, and ${REMOTE_ENV_DIR}"
    return
  fi
  "${SSH_CMD[@]}" "${HOST}" \
    "set -euo pipefail
     sudo mkdir -p '${TARGET_DIR}' '${SHARED_DATA_DIR}'
     sudo install -d -o '${REMOTE_LOGIN_USER}' -g '${REMOTE_LOGIN_GROUP}' -m 0755 '${REMOTE_ENV_DIR}'
     sudo chown '${REMOTE_LOGIN_USER}:${REMOTE_LOGIN_GROUP}' '${TARGET_DIR}'
     sudo chown -R '${REMOTE_LOGIN_USER}:${REMOTE_LOGIN_GROUP}' '${SHARED_DIR}'"
}

upload_project() {
  local rsync_args=(
    -az
    --delete
    --exclude
    ".git/"
    --exclude
    ".venv/"
    --exclude
    "shared/"
    --exclude
    "__pycache__/"
    --exclude
    "*.pyc"
    --exclude
    ".pytest_cache/"
    --exclude
    ".mypy_cache/"
    --exclude
    ".ruff_cache/"
    --exclude
    ".DS_Store"
  )
  if [[ "${DRY_RUN}" == "true" ]]; then
    rsync_args+=(--dry-run)
  fi
  echo "Syncing project to ${HOST}:${TARGET_DIR}"
  rsync "${rsync_args[@]}" -e "${RSYNC_SSH_CMD}" "${PROJECT_ROOT}/" "${HOST}:${TARGET_DIR}/"
}

upload_env_file_if_needed() {
  if [[ -z "${ENV_FILE}" ]]; then
    echo "No --env-file provided; keeping existing remote env if present"
    return
  fi
  echo "Uploading env file to ${REMOTE_ENV_PATH}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would upload ${ENV_FILE} to ${REMOTE_ENV_PATH}"
    return
  fi
  "${SCP_CMD[@]}" "${ENV_FILE}" "${HOST}:/tmp/${SERVICE_NAME}.env"
  "${SSH_CMD[@]}" "${HOST}" \
    "set -euo pipefail
     sudo install -o '${REMOTE_LOGIN_USER}' -g '${REMOTE_LOGIN_GROUP}' -m 0640 /tmp/${SERVICE_NAME}.env '${REMOTE_ENV_PATH}'
     rm -f /tmp/${SERVICE_NAME}.env"
}

write_default_env_if_missing() {
  echo "Ensuring remote env file exists"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would write default env file at ${REMOTE_ENV_PATH} if missing"
    return
  fi
  "${SSH_CMD[@]}" "${HOST}" \
    "if [[ ! -f '${REMOTE_ENV_PATH}' ]]; then cat > /tmp/${SERVICE_NAME}.env.default <<'EOF'
WIFI_DIAGNOSTICS_MCP_TRANSPORT=${TRANSPORT}
SYSLOG_UDP_PORT=${SYSLOG_UDP_PORT}
SYSLOG_TCP_PORT=${SYSLOG_TCP_PORT}
DB_PATH=${DB_PATH}
RAW_SYSLOG_ARCHIVE_PATH=${TARGET_DIR}/shared/data/raw_syslog.jsonl
ENABLE_TCP_SYSLOG=${ENABLE_TCP_SYSLOG}
DEFAULT_LOOKBACK_MINUTES=${DEFAULT_LOOKBACK_MINUTES}
ENABLE_HTTP_MCP=${ENABLE_HTTP_MCP}
MCP_HTTP_HOST=${HTTP_HOST}
MCP_HTTP_PORT=${HTTP_PORT}
ENABLE_VENDOR_AUTO_DETECT=true
EOF
sudo install -o '${REMOTE_LOGIN_USER}' -g '${REMOTE_LOGIN_GROUP}' -m 0640 /tmp/${SERVICE_NAME}.env.default '${REMOTE_ENV_PATH}'
rm -f /tmp/${SERVICE_NAME}.env.default
fi"
}

apply_cli_env_overrides() {
  local -a override_args=()

  if [[ "${TRANSPORT_SET}" == "true" ]]; then
    override_args+=("WIFI_DIAGNOSTICS_MCP_TRANSPORT=${TRANSPORT}")
  fi
  if [[ "${SYSLOG_UDP_PORT_SET}" == "true" ]]; then
    override_args+=("SYSLOG_UDP_PORT=${SYSLOG_UDP_PORT}")
  fi
  if [[ "${SYSLOG_TCP_PORT_SET}" == "true" ]]; then
    override_args+=("SYSLOG_TCP_PORT=${SYSLOG_TCP_PORT}")
  fi
  if [[ "${DB_PATH_SET}" == "true" ]]; then
    override_args+=("DB_PATH=${DB_PATH}")
  fi
  if [[ "${ENABLE_TCP_SYSLOG_SET}" == "true" ]]; then
    override_args+=("ENABLE_TCP_SYSLOG=${ENABLE_TCP_SYSLOG}")
  fi
  if [[ "${DEFAULT_LOOKBACK_MINUTES_SET}" == "true" ]]; then
    override_args+=("DEFAULT_LOOKBACK_MINUTES=${DEFAULT_LOOKBACK_MINUTES}")
  fi
  if [[ "${ENABLE_HTTP_MCP_SET}" == "true" ]]; then
    override_args+=("ENABLE_HTTP_MCP=${ENABLE_HTTP_MCP}")
  fi
  if [[ "${HTTP_HOST_SET}" == "true" ]]; then
    override_args+=("MCP_HTTP_HOST=${HTTP_HOST}")
  fi
  if [[ "${HTTP_PORT_SET}" == "true" ]]; then
    override_args+=("MCP_HTTP_PORT=${HTTP_PORT}")
  fi

  if [[ "${#override_args[@]}" -eq 0 ]]; then
    echo "No CLI env overrides requested"
    return
  fi

  echo "Applying CLI overrides to remote env"
  if [[ "${DRY_RUN}" == "true" ]]; then
    printf 'Dry run: would update %s with overrides:\n' "${REMOTE_ENV_PATH}"
    printf '  %s\n' "${override_args[@]}"
    return
  fi

  "${SSH_CMD[@]}" "${HOST}" bash -s -- "${REMOTE_ENV_PATH}" "${REMOTE_LOGIN_USER}" "${REMOTE_LOGIN_GROUP}" "${override_args[@]}" <<'EOF'
set -euo pipefail

env_path="$1"
service_user="$2"
service_group="$3"
shift 3

set_env_key() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  local tmp_file

  tmp_file="$(mktemp)"
  awk -v key="${key}" -v value="${value}" '
    BEGIN { updated = 0 }
    {
      if ($0 ~ "^[[:space:]]*(export[[:space:]]+)?" key "=") {
        if (!updated) {
          print key "=" value
          updated = 1
        }
        next
      }
      print
    }
    END {
      if (!updated) {
        print key "=" value
      }
    }
  ' "${env_file}" > "${tmp_file}"
  mv "${tmp_file}" "${env_file}"
}

if [[ ! -f "${env_path}" ]]; then
  echo "missing remote env file: ${env_path}" >&2
  exit 1
fi

for assignment in "$@"; do
  key="${assignment%%=*}"
  value="${assignment#*=}"
  set_env_key "${env_path}" "${key}" "${value}"
done

sudo chown "${service_user}:${service_group}" "${env_path}"
EOF
}

prepare_runtime_paths_from_env() {
  echo "Preparing runtime data paths from remote env"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would prepare parent directories for DB_PATH and RAW_SYSLOG_ARCHIVE_PATH from ${REMOTE_ENV_PATH}"
    return
  fi
  "${SSH_CMD[@]}" "${HOST}" bash -s -- "${REMOTE_ENV_PATH}" "${REMOTE_LOGIN_USER}" "${REMOTE_LOGIN_GROUP}" <<'EOF'
set -euo pipefail

env_path="$1"
service_user="$2"
service_group="$3"

strip_wrapping_quotes() {
  local value="$1"
  local first_char=""
  local last_char=""
  if [[ ${#value} -ge 2 ]]; then
    first_char="${value:0:1}"
    last_char="${value: -1}"
    if [[ "${first_char}" == "${last_char}" && ( "${first_char}" == '"' || "${first_char}" == "'" ) ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "${value}"
}

read_env_value() {
  local target_key="$1"
  local line=""
  local raw_key=""
  local raw_value=""

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "${line}" =~ ^[[:space:]]*# ]] && continue
    line="${line#export }"
    if [[ "${line}" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      raw_key="${BASH_REMATCH[1]}"
      raw_value="${BASH_REMATCH[2]}"
      if [[ "${raw_key}" == "${target_key}" ]]; then
        strip_wrapping_quotes "${raw_value}"
        return
      fi
    fi
  done < "${env_path}"
}

if [[ ! -f "${env_path}" ]]; then
  echo "missing remote env file: ${env_path}" >&2
  exit 1
fi

db_path="$(read_env_value DB_PATH)"
archive_path="$(read_env_value RAW_SYSLOG_ARCHIVE_PATH)"

if [[ -z "${db_path}" ]]; then
  echo "DB_PATH is not set in ${env_path}" >&2
  exit 1
fi

db_dir="$(dirname -- "${db_path}")"
sudo mkdir -p "${db_dir}"
sudo chown "${service_user}:${service_group}" "${db_dir}"
if [[ -e "${db_path}" ]]; then
  sudo chown "${service_user}:${service_group}" "${db_path}"
fi

if [[ -n "${archive_path}" ]]; then
  archive_dir="$(dirname -- "${archive_path}")"
  sudo mkdir -p "${archive_dir}"
  sudo chown "${service_user}:${service_group}" "${archive_dir}"
  if [[ -e "${archive_path}" ]]; then
    sudo chown "${service_user}:${service_group}" "${archive_path}"
  fi
fi
EOF
}

bootstrap_remote() {
  echo "Bootstrapping Python environment on remote host"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would create ${REMOTE_VENV_PATH} and install the package in ${TARGET_DIR}"
    return
  fi
  "${SSH_CMD[@]}" "${HOST}" bash -s -- "${TARGET_DIR}" "${REMOTE_PYTHON}" "${VENV_DIR}" <<'EOF'
set -euo pipefail

target_dir="$1"
remote_python="$2"
venv_dir="$3"

cd "${target_dir}"

if ! command -v "${remote_python}" >/dev/null 2>&1; then
  echo "Remote Python interpreter not found: ${remote_python}" >&2
  exit 1
fi

if [[ ! -d "${venv_dir}" ]]; then
  "${remote_python}" -m venv "${venv_dir}"
fi

"${venv_dir}/bin/python" -m pip install --upgrade pip
"${venv_dir}/bin/pip" install .
"${venv_dir}/bin/python" -m wifi_diagnostics_mcp --help >/dev/null
EOF
}

install_service() {
  if [[ "${NO_SERVICE}" == "true" ]]; then
    echo "--no-service specified; skipping systemd installation"
    return
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "Dry run: would install or restart ${SERVICE_NAME} (system)"
    return
  fi

  echo "Installing or refreshing systemd unit ${SERVICE_NAME}"
  "${SSH_CMD[@]}" "${HOST}" bash -s -- "${TARGET_DIR}" "${SERVICE_NAME}" "${VENV_DIR}" "${REMOTE_ENV_PATH}" <<'EOF'
set -euo pipefail

target_dir="$1"
service_name="$2"
venv_dir="$3"
env_file="$4"

cd "${target_dir}"
"${target_dir}/scripts/install_systemd_service.sh" \
  --service "${service_name}" \
  --target-dir "${target_dir}" \
  --venv-dir "${venv_dir}" \
  --env-file "${env_file}"
EOF
}

print_summary() {
  echo
  echo "Deploy completed"
  echo "  target: ${HOST}"
  echo "  target_dir: ${TARGET_DIR}"
  echo "  venv: ${REMOTE_VENV_PATH}"
  echo "  env: ${REMOTE_ENV_PATH}"
  echo "  service_user: ${REMOTE_LOGIN_USER}"
  echo "  service_group: ${REMOTE_LOGIN_GROUP}"
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "  mode: dry-run"
  fi
  if [[ "${NO_SERVICE}" == "true" ]]; then
    echo "  service: skipped"
    echo "  manual start:"
    echo "    install the system service later with:"
    echo "    ssh -p ${SSH_PORT} ${HOST} 'cd ${TARGET_DIR} && scripts/install_systemd_service.sh --service ${SERVICE_NAME} --target-dir ${TARGET_DIR} --venv-dir ${VENV_DIR} --env-file ${REMOTE_ENV_PATH}'"
  else
    echo "  service: ${SERVICE_NAME} (system)"
  fi
}

run_local_tests
check_remote_sudo
create_remote_layout
upload_project
upload_env_file_if_needed
write_default_env_if_missing
apply_cli_env_overrides
prepare_runtime_paths_from_env
bootstrap_remote
install_service
print_summary
