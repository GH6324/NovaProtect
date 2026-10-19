#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
    echo '用法：bash health-check.sh <website-version> <diagnostic-directory>' >&2
    exit 2
fi

version=$1
diagnostics=$2
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid website version: $version" >&2; exit 2; }
mkdir -p -- "$diagnostics"

health_response_ok() {
    local status=$1 headers=$2 body=$3
    [[ $status == 200 ]] || return 1
    grep -Eq '"status"[[:space:]]*:[[:space:]]*"Healthy"' "$body" || return 1
    grep -Eq "\"websiteVersion\"[[:space:]]*:[[:space:]]*\"$version\"" "$body" || return 1
    grep -Eiq '^Cache-Control:.*no-store' "$headers" || return 1
    grep -Eiq '^CDN-Cache-Control:.*no-store' "$headers" || return 1
}

request_health() {
    local scheme=$1 url=$2 headers="$diagnostics/health-$1.headers" body="$diagnostics/health-$1.json"
    local code=000

    if [[ $scheme == http ]]; then
        code=$(curl --noproxy '*' --silent --show-error --max-time 10 \
            -D "$headers" -o "$body" -w '%{http_code}' \
            -H 'Host: nova.fbi.plus' "$url" 2>/dev/null) || code=000
    else
        code=$(curl --noproxy '*' --silent --show-error --insecure \
            --resolve nova.fbi.plus:443:127.0.0.1 --max-time 10 \
            -D "$headers" -o "$body" -w '%{http_code}' "$url" 2>/dev/null) || code=000
    fi

    [[ $code =~ ^[0-9]{3}$ ]] || code=000
    printf '%s\n' "$code" > "$diagnostics/health-$scheme.status"
    health_response_ok "$code" "$headers" "$body"
}

# HTTP may redirect to HTTPS. A successful curl process only means that the
# request completed, so check the HTTP status and payload before accepting it.
request_health http http://127.0.0.1/health && exit 0
request_health https https://nova.fbi.plus/health && exit 0
exit 1
