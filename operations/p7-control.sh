#!/usr/bin/env bash
set -euo pipefail
operations_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$operations_directory/workstation_control.py" "$@"
