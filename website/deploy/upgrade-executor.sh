#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --once ) ]]; then
    echo '用法：bash upgrade-executor.sh --once' >&2
    exit 2
fi

if [[ ${EUID} -ne 0 ]]; then
    echo '升级执行器必须由 root 运行。' >&2
    exit 1
fi

state=${NOVAPROTECT_STATE_DIR:-/www/server/novaprotect}
updates=${NOVAPROTECT_UPDATES_DIR:-$state/updates}
lock_file="$state/upgrade-executor.lock"
mkdir -p "$state" "$updates"
exec 9>"$lock_file"
flock -n 9 || exit 0

command -v bash >/dev/null 2>&1 || { echo '缺少 bash。' >&2; exit 1; }
command -v find >/dev/null 2>&1 || { echo '缺少 find。' >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { echo '缺少 flock。' >&2; exit 1; }

write_result() {
    local package=$1 id=$2 started=$3 exit_code=$4 message=$5 completed tmp
    completed=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    tmp="$package/execution.json.$$.tmp"
    printf '{"id":"%s","startedAt":"%s","completedAt":"%s","exitCode":%s,"message":"%s"}\n' \
        "$id" "$started" "$completed" "$exit_code" "$message" > "$tmp"
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$package/execution.json"
    rm -f -- "$package/execution-running.json"
}

while IFS= read -r -d '' request; do
    package=$(dirname -- "$request")
    [[ -f "$package/upgrade.sh" && -f "$package/SHA256SUMS" ]] || { rm -f -- "$request"; continue; }
    [[ $(realpath -m -- "$package") == "$updates"/* ]] || { rm -f -- "$request"; continue; }
    running="$package/execution-running.json"
    if ! mv -f -- "$request" "$running"; then continue; fi

    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    id=$(basename "$(dirname "$package")")
    log="$package/execution.log"
    check_log="$package/execution-check.log"
    rc=0
    if (cd -- "$package" && bash ./upgrade.sh --check-package > "$check_log" 2>&1); then
        if (cd -- "$package" && bash ./upgrade.sh > "$log" 2>&1); then
            rc=0
        else
            rc=$?
        fi
    else
        rc=$?
    fi

    if [[ $rc -eq 0 ]]; then
        write_result "$package" "$id" "$started" 0 '升级完成。'
    else
        write_result "$package" "$id" "$started" "$rc" '升级失败，请查看 execution.log。'
    fi
done < <(find "$updates" -mindepth 4 -maxdepth 4 -type f -name execution-request.json -print0 2>/dev/null | sort -z)

