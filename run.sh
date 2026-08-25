#!/usr/bin/env bash
# ===========================================================================
#  AETHRA-SEC launcher (Linux / macOS) - the counterpart of run.bat.
#
#    ./run.sh                start the desktop console
#    ./run.sh --check        run diagnostics and exit
#    ./run.sh --headless     run the services without the interface
#    ./run.sh --setup        create the virtual environment and install deps
#
#  Any other argument is passed straight through to "python -m aethra_sec.main".
#
#  Live capture needs raw-socket privileges. Rather than running the whole
#  console as root, grant them to dumpcap once:
#      sudo setcap cap_net_raw,cap_net_admin+eip "$(which dumpcap)"
# ===========================================================================
set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PYTHON="${VENV}/bin/python"

setup() {
    echo "Creating the virtual environment and installing dependencies..."
    python3 -m venv "${VENV}"
    "${PYTHON}" -m pip install --upgrade pip >/dev/null
    "${PYTHON}" -m pip install -r requirements.txt
    if [ ! -f .env ]; then
        cp .env.example .env
        echo
        echo ".env created from .env.example. Set at least:"
        echo "    AETHRA_DB_PASSWORD          your MySQL account password"
        echo "    AETHRA_AUTHORIZED_NETWORKS  the networks you may scan/monitor"
    fi
    echo
    echo "Next:  ./run.sh --check   then   ./run.sh"
}

if [ "${1:-}" = "--setup" ]; then
    setup
    exit 0
fi

if [ ! -x "${PYTHON}" ]; then
    echo "The virtual environment is missing. Run './run.sh --setup' first." >&2
    exit 2
fi

if [ ! -f .env ]; then
    echo "WARNING: no .env found; the built-in defaults will be used." >&2
    echo "         Copy .env.example to .env and set your database password" >&2
    echo "         and your authorised networks before assessing anything." >&2
fi

exec "${PYTHON}" -m aethra_sec.main "$@"
