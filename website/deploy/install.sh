#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check-package ) ]]; then
    echo '用法：bash install.sh [--check-package]' >&2
    exit 2
fi

# This file lives in deploy/; the root entry script only forwards here.
# Resolve every package path from the parent, independently of the caller's cwd.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bundle=$(cd -- "$script_dir/.." && pwd)
for required in VERSION SHA256SUMS release.json app/bootstrap.php app/version.json app/view.php public/index.php public/.user.ini deploy/configure_nginx.py deploy/nginx-location.conf deploy/reset-admin-password.php deploy/cdnfly-edge-policy.json deploy/cdnfly-check.sh deploy/CDNFLY.md; do
    [[ -f $bundle/$required ]] || { echo "安装包不完整，缺少：$bundle/$required；请重新解压完整 ZIP。" >&2; exit 1; }
done
[[ -d $bundle/downloads ]] || { echo "安装包不完整，缺少：$bundle/downloads；请重新解压完整 ZIP。" >&2; exit 1; }

version=$(tr -d '\r\n' < "$bundle/VERSION")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid website VERSION: $version" >&2; exit 1; }

verify_bundle() {
    command -v sha256sum >/dev/null 2>&1 || { echo '缺少系统命令：sha256sum' >&2; return 1; }
    (cd -- "$bundle" && sha256sum --check SHA256SUMS --quiet)
}

# Package checks are read-only and require neither root nor PHP/Nginx.
if [[ ${1:-} == --check-package ]]; then
    verify_bundle
    printf 'PACKAGE-CHECK-OK (website %s; root: %s)\n' "$version" "$bundle"
    exit 0
fi

[[ ${EUID} -eq 0 ]] || { echo '请在宝塔终端使用 root 执行：bash install.sh' >&2; exit 1; }
verify_bundle

base=/www/wwwroot/nova.fbi.plus
state=/www/server/novaprotect
release="$base/releases/$version"
vhost=/www/server/panel/vhost/nginx/nova.fbi.plus.conf
nginx=/www/server/nginx/sbin/nginx
service=/etc/systemd/system/novaprotect.service
executor_service=/etc/systemd/system/novaprotect-upgrade-executor.service
executor_timer=/etc/systemd/system/novaprotect-upgrade-executor.timer
php84_root=/www/server/php/84
php84_include=/www/server/nginx/conf/enable-php-84.conf

select_python() {
    local candidate
    local candidates=(
        "$(command -v python3 2>/dev/null || true)"
        /www/server/panel/pyenv/bin/python3
        /www/server/panel/pyenv/bin/python
        /usr/bin/python3
    )
    for candidate in "${candidates[@]}"; do
        [[ -x $candidate ]] || continue
        "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1 || continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

install_php84_if_missing() {
    [[ -x $php84_root/bin/php ]] && return 0
    local installer=/www/server/panel/install/install_soft.sh
    if [[ -x $installer ]]; then
        echo '未找到宝塔 PHP 8.4，尝试通过宝塔安装脚本安装 PHP 8.4。' >&2
        bash "$installer" 0 install php 84 || true
    fi
}

select_php() {
    local candidate
    local candidates=(
        "$php84_root/bin/php"
        "$php84_root/sbin/php"
        "$(command -v php 2>/dev/null || true)"
        /usr/bin/php
    )
    for candidate in "${candidates[@]}"; do
        [[ -x $candidate ]] || continue
        "$candidate" -r 'exit(PHP_MAJOR_VERSION === 8 && PHP_MINOR_VERSION === 4 && function_exists("json_encode") && function_exists("session_start") && function_exists("hash_pbkdf2") && function_exists("random_bytes") && extension_loaded("openssl") && extension_loaded("zip") ? 0 : 1);' >/dev/null 2>&1 || continue
        printf '%s\n' "$candidate"
        return 0
    done
    return 1
}

python=$(select_python || true)
[[ -n $python ]] || { echo '未找到 Python 3.8+；宝塔通常自带 /www/server/panel/pyenv/bin/python3。' >&2; exit 1; }

if [[ ! -x $nginx ]]; then nginx=$(command -v nginx 2>/dev/null || true); fi
[[ -n $nginx && -x $nginx ]] || { echo '未找到宝塔 Nginx。' >&2; exit 1; }
id www >/dev/null 2>&1 || { echo '未找到宝塔 www 账户。' >&2; exit 1; }
install_php84_if_missing
php=$(select_php || true)
[[ -n $php ]] || { echo '未找到可用的 PHP 8.4 CLI。请在宝塔安装 PHP 8.4（/www/server/php/84），并启用 JSON、session、OpenSSL、Zip 后重试。' >&2; exit 1; }
php_version=$("$php" -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')
[[ $php_version == 8.4 ]] || { echo "PHP CLI 版本不是 8.4：$php_version" >&2; exit 1; }
[[ -f $php84_include ]] || { echo "宝塔 PHP 8.4 Nginx 配置不存在：$php84_include；请先安装并启动 PHP 8.4。" >&2; exit 1; }

for tool in curl sha256sum awk flock install find grep sed mv ln readlink tr head date chown; do
    command -v "$tool" >/dev/null 2>&1 || { echo "缺少系统命令：$tool" >&2; exit 1; }
done

normalise_socket() {
    local value=${1:-}
    value=$(printf '%s' "$value" | sed -E 's/[[:space:]]*[;#].*$//; s/^[[:space:]]+//; s/[[:space:]]+$//')
    if [[ $value == unix:* ]]; then
        printf '%s\n' "$value"
    elif [[ $value == /* ]]; then
        printf 'unix:%s\n' "$value"
    elif [[ $value =~ ^[A-Za-z0-9_.-]+:[0-9]{1,5}$ ]]; then
        printf '%s\n' "$value"
    fi
}

socket_is_usable() {
    local value=${1:-}
    if [[ $value == unix:* ]]; then
        [[ -S ${value#unix:} ]]
        return
    fi
    if command -v ss >/dev/null 2>&1; then
        local port=${value##*:}
        ss -ltn 2>/dev/null | awk -v port=":$port" '$0 ~ port {found=1} END {exit(found ? 0 : 1)}'
        return
    fi
    return 0
}

start_php_fpm84() {
    if [[ -S /tmp/php-cgi-84.sock || -S /run/php/php-cgi-84.sock ]]; then return 0; fi
    if command -v systemctl >/dev/null 2>&1; then
        for service_name in php-fpm-84 php84 php84-fpm php-fpm84; do
            systemctl start "$service_name" >/dev/null 2>&1 || true
            [[ -S /tmp/php-cgi-84.sock || -S /run/php/php-cgi-84.sock ]] && return 0
        done
    fi
    if command -v service >/dev/null 2>&1; then
        service php-fpm-84 start >/dev/null 2>&1 || true
        service php84-fpm start >/dev/null 2>&1 || true
    fi
}

detect_php_socket() {
    local candidate value config
    if [[ -n ${NOVAPROTECT_PHP_SOCKET:-} ]]; then
        value=$(normalise_socket "$NOVAPROTECT_PHP_SOCKET")
        [[ -n $value && $value == *84* ]] && socket_is_usable "$value" && { printf '%s\n' "$value"; return 0; }
        echo "NOVAPROTECT_PHP_SOCKET 不可用或不是 PHP 8.4 socket：$NOVAPROTECT_PHP_SOCKET" >&2
        return 1
    fi
    for config in "$php84_root"/etc/php-fpm.conf "$php84_root"/etc/php-fpm.d/*.conf; do
        [[ -f $config ]] || continue
        while IFS= read -r candidate; do
            value=$(normalise_socket "$candidate")
            [[ -n $value ]] && socket_is_usable "$value" && { printf '%s\n' "$value"; return 0; }
        done < <(sed -n -E 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$config")
    done
    while IFS= read -r candidate; do
        value=$(normalise_socket "$candidate")
        [[ -n $value ]] && socket_is_usable "$value" && { printf '%s\n' "$value"; return 0; }
    done < <(find /tmp /run /var/run "$php84_root" -maxdepth 7 -type s -iname '*php*84*.sock' -print 2>/dev/null)
    if [[ -f "$php84_root/etc/php-fpm.conf" ]] && command -v ss >/dev/null 2>&1; then
        while IFS= read -r candidate; do
            value=$(normalise_socket "$candidate")
            [[ -n $value ]] && socket_is_usable "$value" && { printf '%s\n' "$value"; return 0; }
        done < <(awk '$1 == "listen" && $2 ~ /^(127[.]0[.]0[.]1|0[.]0[.]0[.]0):[0-9]+$/ { print $2 }' "$php84_root/etc/php-fpm.conf")
    fi
    return 1
}

start_php_fpm84
php_socket=$(detect_php_socket || true)
if [[ -z $php_socket ]]; then
    echo '未找到正在监听的 PHP 8.4 PHP-FPM socket。请在宝塔启动 PHP 8.4，或显式指定 8.4 socket：' >&2
    echo '  NOVAPROTECT_PHP_SOCKET=/tmp/php-cgi-84.sock bash install.sh' >&2
    exit 1
fi

cd -- "$bundle"

release_json=$bundle/release.json
release_name=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); if (!is_array($v)) exit(2); echo (string)($v["fileName"] ?? "");' "$release_json")
release_hash=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); if (!is_array($v)) exit(2); echo strtolower((string)($v["sha256"] ?? ""));' "$release_json")
release_site_version=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); echo (string)($v["websiteVersion"] ?? "");' "$release_json")
[[ $release_site_version == "$version" ]] || { echo "release.json websiteVersion 与 VERSION 不一致：$release_site_version / $version" >&2; exit 1; }
[[ $release_name =~ ^NovaProtect-Setup-[0-9]+\.[0-9]+\.[0-9]+\.exe$ ]] || { echo 'release.json 的安装包文件名无效。' >&2; exit 1; }
[[ $release_hash =~ ^[a-f0-9]{64}$ ]] || { echo 'release.json 的安装包 SHA-256 无效。' >&2; exit 1; }
installer="$bundle/downloads/$release_name"
[[ -f $installer ]] || { echo "缺少客户端安装包：$installer" >&2; exit 1; }
[[ $(sha256sum "$installer" | awk '{print tolower($1)}') == "$release_hash" ]] || { echo '客户端安装包 SHA-256 与 release.json 不一致。' >&2; exit 1; }

mkdir -p "$base/releases" "$state/backups" "$state/downloads" "$state/updates" "$state/empty" "$state/bin" /www/wwwlogs "$(dirname "$vhost")"
# The site tree (<base>/current -> releases/<version>) lives outside the state
# directory; record the site root so bin/reset-admin-password.php can find app/.
printf '%s\n' "$base" > "$state/site-root"
chmod 0644 "$state/site-root"
chmod 0755 "$base" "$base/releases" "$state" "$state/downloads" "$state/empty"
chmod 0750 "$state/bin"
install -d -m 0700 -o www -g www "$state/data" "$state/updates"

repair_data_permissions() {
    chown -R www:www "$state/data"
    find "$state/data" -type d -exec chmod 0700 {} +
    find "$state/data" -type f -exec chmod 0600 {} +
}
repair_data_permissions

exec 9>"$state/deploy.lock"
flock -n 9 || { echo '另一安装/回滚进程正在运行。' >&2; exit 1; }

slot_target() { local slot=$1; [[ -L $slot ]] && readlink -f -- "$slot" 2>/dev/null || true; }
validate_slot() {
    local slot=$1 target
    if [[ -e $slot && ! -L $slot ]]; then
        echo "$slot 不是软链接，已停止以避免覆盖。" >&2
        return 1
    fi
    target=$(slot_target "$slot")
    if [[ -n $target && $target != "$base/releases/"* ]]; then
        echo "$slot 指向发布目录之外：$target" >&2
        return 1
    fi
}
validate_slot "$base/current"
validate_slot "$base/previous"
old_current=$(slot_target "$base/current")
old_previous=$(slot_target "$base/previous")

backup="$state/backups/$(date -u +%Y%m%dT%H%M%SZ)-$version-$$"
mkdir -p "$backup"
printf '%s\n' "$old_current" > "$backup/old-current"
printf '%s\n' "$old_previous" > "$backup/old-previous"
if [[ -f $vhost ]]; then cp -a -- "$vhost" "$backup/vhost.conf"; else : > "$backup/vhost-missing"; fi
if [[ -f $state/data/setup.json ]]; then cp -a -- "$state/data/setup.json" "$backup/setup.json"; else : > "$backup/setup-missing"; fi
if [[ -d $state/data ]]; then cp -a -- "$state/data" "$backup/data"; fi

systemctl_available=0
command -v systemctl >/dev/null 2>&1 && systemctl_available=1
legacy_unit=0
was_active=0
was_enabled=0
if [[ -f $service || -L $service ]]; then
    legacy_unit=1
    cp -a -- "$service" "$backup/service"
    if [[ $systemctl_available == 1 ]] && systemctl is-active --quiet novaprotect.service; then was_active=1; fi
    if [[ $systemctl_available == 1 ]] && systemctl is-enabled --quiet novaprotect.service 2>/dev/null; then was_enabled=1; fi
fi
printf '%s\n' "$legacy_unit" > "$backup/legacy-unit"
printf '%s\n' "$was_active" > "$backup/was-active"
printf '%s\n' "$was_enabled" > "$backup/was-enabled"

"$nginx" -t >/dev/null
changed=0
recover() {
    local rc=$?
    trap - ERR
    set +e
    if [[ $changed == 1 ]]; then
        if [[ -f "$backup/existing-release-$version" || -d "$backup/existing-release-$version" ]]; then
            rm -rf -- "$release"
            mv -- "$backup/existing-release-$version" "$release"
        fi
        if [[ -n $old_current ]]; then ln -sfn -- "$old_current" "$base/current.rollback"; mv -Tf -- "$base/current.rollback" "$base/current"; else rm -f -- "$base/current"; fi
        if [[ -n $old_previous ]]; then ln -sfn -- "$old_previous" "$base/previous.rollback"; mv -Tf -- "$base/previous.rollback" "$base/previous"; else rm -f -- "$base/previous"; fi
        if [[ -f "$backup/vhost.conf" ]]; then cp -a -- "$backup/vhost.conf" "$vhost"; else rm -f -- "$vhost"; fi
        if [[ -f "$backup/setup.json" ]]; then cp -a -- "$backup/setup.json" "$state/data/setup.json"; else rm -f -- "$state/data/setup.json"; fi
        if [[ $legacy_unit == 1 && -f "$backup/service" ]]; then cp -a -- "$backup/service" "$service"; else rm -f -- "$service"; fi
        if [[ $systemctl_available == 1 ]]; then
            systemctl daemon-reload >/dev/null 2>&1 || true
            if [[ $was_enabled == 1 ]]; then systemctl enable novaprotect.service >/dev/null 2>&1 || true; else systemctl disable novaprotect.service >/dev/null 2>&1 || true; fi
            if [[ $was_active == 1 ]]; then systemctl restart novaprotect.service >/dev/null 2>&1 || true; else systemctl stop novaprotect.service >/dev/null 2>&1 || true; fi
        fi
        "$nginx" -t >/dev/null 2>&1 && "$nginx" -s reload >/dev/null 2>&1 || true
    fi
    echo "安装失败，已尝试恢复原站点/服务。备份：$backup；失败候选保留在 $release" >&2
    echo '查看：journalctl -u nginx -n 80 --no-pager；PHP-FPM 日志请在宝塔对应 PHP 版本中查看。' >&2
    exit "$rc"
}
trap recover ERR

if [[ -e $release || -L $release ]]; then
    if [[ $old_current == "$release" ]]; then
        echo "版本目录已作为 current 使用：$release；为避免覆盖，安装停止。" >&2
        false
    fi
    mv -- "$release" "$backup/existing-release-$version"
fi

stage="$base/releases/.${version}.install-$$"
mkdir "$stage"
cp -a -- "$bundle/app" "$stage/app"
cp -a -- "$bundle/public" "$stage/public"
cp -a -- "$bundle/release.json" "$stage/release.json"
cp -a -- "$bundle/VERSION" "$stage/VERSION"
mv -- "$stage" "$release"
chown -R root:root "$release"
find "$release" -type d -exec chmod 0755 {} +
find "$release" -type f -exec chmod 0644 {} +

install -m 0644 "$installer" "$state/downloads/$release_name"
chown www:www "$state/downloads/$release_name"

new_vhost="$backup/new-vhost.conf"
"$python" "$bundle/deploy/configure_nginx.py" \
    --input "$vhost" \
    --output "$new_vhost" \
    --php-socket "$php_socket" \
    --document-root "$base/current/public" \
    --template "$bundle/deploy/nginx-location.conf"
grep -q 'fastcgi_pass ' "$new_vhost"
! grep -q 'proxy_pass ' "$new_vhost"
grep -q "root $base/current/public;" "$new_vhost"

if [[ $systemctl_available == 1 ]]; then
    systemctl stop novaprotect.service >/dev/null 2>&1 || true
    systemctl disable novaprotect.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f -- "$service"

install -m 0750 -o root -g root "$bundle/deploy/upgrade-executor.sh" "$state/bin/upgrade-executor.sh"
install -m 0644 -o root -g root "$bundle/deploy/novaprotect-upgrade-executor.service" "$executor_service"
install -m 0644 -o root -g root "$bundle/deploy/novaprotect-upgrade-executor.timer" "$executor_timer"
install -m 0750 -o root -g root "$bundle/deploy/reset-admin-password.php" "$state/bin/reset-admin-password.php"
if [[ $systemctl_available == 1 ]]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now novaprotect-upgrade-executor.timer >/dev/null 2>&1 || true
fi

installed_before=$("$php" -r '$p=$argv[1]."/installation.json"; $v=is_file($p)?json_decode(file_get_contents($p),true):[]; echo (($v["installed"]??false)===true?"1":"0");' "$state/data" 2>/dev/null || echo 0)
if [[ $installed_before != 1 ]]; then
    token=$(openssl rand -hex 32 2>/dev/null || true)
    [[ -n $token ]] || token=$("$php" -r 'echo bin2hex(random_bytes(32));')
    token_hash=$(printf '%s' "$token" | sha256sum | awk '{print tolower($1)}')
    expires_at=$(date -u -d '+24 hours' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || "$python" -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc)+timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
    setup_tmp="$state/data/setup.json.$$.tmp"
    printf '{"tokenHash":"%s","expiresAt":"%s","websiteVersion":"%s"}\n' "$token_hash" "$expires_at" "$version" > "$setup_tmp"
    chown www:www "$setup_tmp"
    chmod 0600 "$setup_tmp"
    mv -f -- "$setup_tmp" "$state/data/setup.json"
    setup_message="安装口令（仅显示一次，24 小时内有效）：$token"
else
    setup_message='已有安装记录，未覆盖管理员口令或安装状态；升级后可直接登录后台。'
fi
repair_data_permissions

changed=1
if [[ -n $old_current ]]; then
    ln -sfn -- "$old_current" "$base/previous.next"
    mv -Tf -- "$base/previous.next" "$base/previous"
elif [[ -n $old_previous ]]; then
    ln -sfn -- "$old_previous" "$base/previous.next"
    mv -Tf -- "$base/previous.next" "$base/previous"
else
    rm -f -- "$base/previous"
fi
ln -sfn -- "$release" "$base/current.next"
mv -Tf -- "$base/current.next" "$base/current"
install -m 0644 "$new_vhost" "$vhost"
"$nginx" -t >/dev/null
"$nginx" -s reload >/dev/null

health_request() {
    local scheme=$1 headers=$2 body=$3
    if [[ $scheme == http ]]; then
        curl --noproxy '*' --silent --show-error --max-time 10 -D "$headers" -o "$body" -H 'Host: nova.fbi.plus' http://127.0.0.1/health
    else
        curl --noproxy '*' --silent --show-error --insecure --resolve nova.fbi.plus:443:127.0.0.1 --max-time 10 -D "$headers" -o "$body" https://nova.fbi.plus/health
    fi
}
health_ok() { grep -q '"status":"Healthy"' "$1" && grep -q '"websiteVersion":"' "$1"; }
health_scheme=''
for ((i=0; i<30; i++)); do
    if health_request http "$backup/response-headers" "$backup/health.json" 2>/dev/null && health_ok "$backup/health.json"; then health_scheme=http; break; fi
    if health_request https "$backup/response-headers" "$backup/health.json" 2>/dev/null && health_ok "$backup/health.json"; then health_scheme=https; break; fi
    sleep 1
done
[[ -n $health_scheme ]]
grep -Eiq '^Cache-Control:.*no-store' "$backup/response-headers"
grep -Eiq '^CDN-Cache-Control:.*no-store' "$backup/response-headers"
grep -Eiq '^Surrogate-Control:.*no-store' "$backup/response-headers"
if [[ $installed_before != 1 ]]; then
    if [[ $health_scheme == http ]]; then
        curl --noproxy '*' --fail --silent --show-error --max-time 15 -H 'Host: nova.fbi.plus' http://127.0.0.1/install | grep -q '安装向导'
    else
        curl --noproxy '*' --fail --silent --show-error --insecure --resolve nova.fbi.plus:443:127.0.0.1 --max-time 15 https://nova.fbi.plus/install | grep -q '安装向导'
    fi
fi

ln -sfn -- "$backup" "$state/last-backup"
trap - ERR
echo "NovaProtect 网站 $version 安装完成：https://nova.fbi.plus"
echo "$setup_message"
echo "PHP-FPM：$php_socket"
echo "当前版本：$base/current；previous：$base/previous；客户端安装包：$state/downloads/$release_name"
echo "备份：$backup；回滚：bash $bundle/deploy/rollback.sh"
echo 'CDNfly 规则模板：deploy/cdnfly-edge-policy.json；控制台步骤：deploy/CDNFLY.md。'
echo '应用规则并清理全站缓存后运行：bash deploy/cdnfly-check.sh https://nova.fbi.plus'
echo '忘记管理员口令时，用 root 在 SSH 执行：php /www/server/novaprotect/bin/reset-admin-password.php'
