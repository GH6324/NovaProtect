#!/usr/bin/env bash
set -Eeuo pipefail

site_url=${1:-${NOVAPROTECT_SITE_URL:-https://nova.fbi.plus}}
site_url=${site_url%/}
case "$site_url" in
    https://*) ;;
    *) echo "Usage: bash deploy/cdnfly-check.sh https://nova.fbi.plus" >&2; exit 2 ;;
esac

timeout_seconds=${NOVAPROTECT_PREFLIGHT_TIMEOUT:-15}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/novaprotect-cdnfly.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT

failures=0
warnings=0
site_installed=unknown

contains_status() {
    local allowed=$1 actual=$2
    case " $allowed " in
        *" $actual "*) return 0 ;;
        *) return 1 ;;
    esac
}

check_response() {
    local name=$1 path=$2 method=$3 allowed=$4 body_payload=${5:-} mode=${6:-normal}
    local headers="$tmp/$name.headers" body="$tmp/$name.body" status curl_rc
    local url="$site_url$path"
    local -a curl_args=(
        --silent --show-error --compressed --http1.1
        --connect-timeout 8 --max-time "$timeout_seconds"
        --dump-header "$headers" --output "$body" --write-out '%{http_code}'
        -H 'Accept: application/json, text/html;q=0.9, */*;q=0.1'
        -H 'Cache-Control: no-cache'
        -H 'X-NovaProtect-Client: 1'
    )
    if [[ $method == POST ]]; then
        curl_args+=(
            -X POST
            -H 'Content-Type: application/json'
            -H "Origin: $site_url"
            -H 'Sec-Fetch-Site: same-origin'
            --data "$body_payload"
        )
    fi

    if ! status=$(curl "${curl_args[@]}" "$url"); then
        echo "[FAIL] $method $path: curl could not connect" >&2
        failures=$((failures + 1))
        return
    fi

    if [[ $mode != locked ]]; then
        if [[ $status == 444 ]] || grep -Eiq '^HTTP/[0-9.]+[[:space:]]+444([[:space:]]|$)' "$headers"; then
            echo "[FAIL] $method $path: CDNfly returned HTTP 444" >&2
            failures=$((failures + 1))
            return
        fi
    fi
    if [[ $mode != locked ]] && grep -Eiq '(^|/)_guard/auto\.js|cdnfly|human[[:space:]-]*verification|javascript[[:space:]-]*challenge' "$body"; then
        echo "[FAIL] $method $path: CDNfly guard content reached the client" >&2
        failures=$((failures + 1))
        return
    fi
    if ! contains_status "$allowed" "$status"; then
        echo "[FAIL] $method $path: unexpected HTTP $status (allowed: $allowed)" >&2
        failures=$((failures + 1))
        return
    fi

    if [[ $name == health ]]; then
        if ! grep -q '"status"[[:space:]]*:[[:space:]]*"Healthy"' "$body"; then
            echo "[FAIL] $method $path: health payload is not Healthy" >&2
            failures=$((failures + 1))
            return
        fi
        if grep -Eiq '"installed"[[:space:]]*:[[:space:]]*true' "$body"; then
            site_installed=true
        elif grep -Eiq '"installed"[[:space:]]*:[[:space:]]*false' "$body"; then
            site_installed=false
        else
            echo "[FAIL] $method $path: health payload has no installed state" >&2
            failures=$((failures + 1))
            return
        fi
    fi
    echo "[ OK ] $method $path -> HTTP $status"
}

check_install_route() {
    if [[ $site_installed == true ]]; then
        check_response install_page /install GET '302 403 404 444' '' locked
        check_response install_php /install.php GET '302 403 404 444' '' locked
        return
    fi
    if [[ $site_installed == false ]]; then
        check_response install_page /install GET '200'
        check_response install_php /install.php GET '200'
        return
    fi
    echo '[FAIL] install route: cannot determine installation state from /health' >&2
    failures=$((failures + 1))
}

check_response health /health GET '200'
check_response admin_login /admin/login GET '200 302'
# The admin installer upload uses this JSON endpoint for every request. A 401
# here means the edge passed the POST through to PHP; a 403/444/HTML challenge
# would mean the WAF still intercepts the upload path.
check_response upload_begin /api/admin/release/begin POST '401 400 422' '{"size":1}'
check_install_route
check_response stylesheet /css/site.css GET '200'
check_response favicon /favicon.ico GET '200'

if (( failures > 0 )); then
    echo "CDNFLY-PREFLIGHT-FAILED ($failures failure(s), $warnings warning(s))" >&2
    echo "Apply deploy/cdnfly-edge-policy.json in CDNfly, purge the site cache, then rerun this script." >&2
    exit 1
fi
if (( warnings > 0 )); then
    echo "CDNFLY-PREFLIGHT-OK-WITH-WARNINGS ($warnings warning(s))"
else
    echo "CDNFLY-PREFLIGHT-OK"
fi
