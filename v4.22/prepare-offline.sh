#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/config/versions.sh"
export OCP_RELEASE OCP_MINOR OCP_ARCH
exec python3 "$SCRIPT_DIR/lib/offline.py" "$@"
