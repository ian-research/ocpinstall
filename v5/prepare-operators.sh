#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} == delivery ]]; then
    shift
    exec python3 "$SCRIPT_DIR/lib/delivery.py" "$@"
fi
if [[ $# == 0 && -t 0 ]]; then
    printf '1. 准备完整离线包（OpenShift 本体、工具、Helper 软件及 Operator）\n2. 仅准备/导入 Operator 离线包\n'
    read -r -p '请选择 [1]: ' mode
    case ${mode:-1} in
        1) exec python3 "$SCRIPT_DIR/lib/delivery.py" ;;
        2) ;;
        *) echo '无效操作' >&2; exit 1 ;;
    esac
fi
exec python3 "$SCRIPT_DIR/lib/operators.py" "$@"
