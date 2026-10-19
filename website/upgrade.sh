#!/usr/bin/env bash
set -Eeuo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "${BASH:-bash}" "$here/deploy/upgrade.sh" "$@"
