#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $# -gt 1 || ( $# -eq 1 && $1 != --check-package ) ]]; then
    echo '用法：bash upgrade.sh [--check-package]' >&2
    exit 2
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bundle=$(cd -- "$script_dir/.." && pwd)
for required in VERSION SHA256SUMS release.json app/bootstrap.php app/features.php app/version.json public/index.php public/.user.ini deploy/migrate.php deploy/reset-admin-password.php deploy/health-check.sh deploy/upgrade-executor.sh deploy/novaprotect-upgrade-executor.service deploy/novaprotect-upgrade-executor.timer deploy/configure_nginx.py deploy/nginx-location.conf deploy/cdnfly-edge-policy.json deploy/cdnfly-check.sh deploy/CDNFLY.md; do
    [[ -f $bundle/$required ]] || { echo "升级包不完整，缺少：$bundle/$required" >&2; exit 1; }
done
[[ -d $bundle/downloads ]] || { echo "升级包不完整，缺少：$bundle/downloads" >&2; exit 1; }

version=$(tr -d '\r\n' < "$bundle/VERSION")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid website VERSION: $version" >&2; exit 1; }

verify_bundle() {
    command -v sha256sum >/dev/null 2>&1 || { echo '缺少系统命令：sha256sum' >&2; return 1; }
    (cd -- "$bundle" && sha256sum --check SHA256SUMS --quiet)
}

if [[ ${1:-} == --check-package ]]; then
    verify_bundle
    printf 'UPGRADE-PACKAGE-CHECK-OK (website %s; root: %s)\n' "$version" "$bundle"
    exit 0
fi

[[ ${EUID} -eq 0 ]] || { echo '请在宝塔终端使用 root 执行：bash upgrade.sh' >&2; exit 1; }
verify_bundle

base=/www/wwwroot/nova.fbi.plus
state=/www/server/novaprotect
vhost=/www/server/panel/vhost/nginx/nova.fbi.plus.conf
nginx=/www/server/nginx/sbin/nginx
current="$base/current"
previous="$base/previous"
release="$base/releases/$version"
data="$state/data"
downloads="$state/downloads"
updates="$state/updates"
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

install_php84_if_missing
php=$(select_php || true)
[[ -n $php ]] || { echo '未找到 PHP 8.4 CLI，无法执行升级迁移。请在宝塔安装 PHP 8.4 并启用 JSON、session、OpenSSL、Zip。' >&2; exit 1; }
php_version=$("$php" -r 'echo PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION;')
[[ $php_version == 8.4 ]] || { echo "PHP CLI 版本不是 8.4：$php_version" >&2; exit 1; }
python=$(select_python || true)
[[ -n $python ]] || { echo '未找到 Python 3.8+，无法修复宝塔 Nginx PHP 站点配置。' >&2; exit 1; }
if [[ ! -x $nginx ]]; then nginx=$(command -v nginx 2>/dev/null || true); fi
[[ -n $nginx && -x $nginx ]] || { echo '未找到宝塔 Nginx。' >&2; exit 1; }
[[ -f $php84_include ]] || { echo "宝塔 PHP 8.4 Nginx 配置不存在：$php84_include。" >&2; exit 1; }
for tool in curl sha256sum awk flock install find grep sed mv ln readlink tr head sort xargs date chown cp; do
    command -v "$tool" >/dev/null 2>&1 || { echo "缺少系统命令：$tool" >&2; exit 1; }
done

[[ -d $base/releases && -L $current ]] || { echo '没有可升级的 current 发布槽位。' >&2; exit 1; }
old_current=$(readlink -f -- "$current" 2>/dev/null || true)
old_previous=$(readlink -f -- "$previous" 2>/dev/null || true)
[[ $old_current == "$base/releases/"* && -f $old_current/public/index.php ]] || { echo 'current 发布槽位不在受控目录或不是 PHP 站点。' >&2; exit 1; }
[[ -f $vhost ]] || { echo "未找到宝塔站点配置：$vhost" >&2; exit 1; }
php_socket=$(awk '$1 == "fastcgi_pass" { gsub(";", "", $2); print $2; exit }' "$php84_include")
[[ -n $php_socket && $php_socket == *84* ]] || { echo "宝塔 PHP 8.4 配置没有可用的 8.4 fastcgi_pass：$php84_include" >&2; exit 1; }
php_socket_usable() {
    if [[ $php_socket == unix:* ]]; then
        [[ -S ${php_socket#unix:} ]]
        return
    fi
    command -v ss >/dev/null 2>&1 || return 0
    local port=${php_socket##*:}
    ss -ltn 2>/dev/null | awk -v port=":$port" '$0 ~ port {found=1} END {exit(found ? 0 : 1)}'
}
if ! php_socket_usable && command -v systemctl >/dev/null 2>&1; then
    for service_name in php-fpm-84 php84 php84-fpm php-fpm84; do
        systemctl start "$service_name" >/dev/null 2>&1 || true
        php_socket_usable && break
    done
fi
php_socket_usable || { echo "PHP 8.4 FPM 未在 $php_socket 监听，请在宝塔启动 PHP 8.4。" >&2; exit 1; }
[[ -d $data && -f $data/installation.json ]] || { echo '网站尚未完成安装，升级已停止。' >&2; exit 1; }
[[ ! -e $release && ! -L $release ]] || { echo "目标版本目录已存在：$release；请上传新的版本号升级包。" >&2; exit 1; }

version_gt() {
    local left=$1 right=$2 lmajor lminor lpatch rmajor rminor rpatch
    IFS=. read -r lmajor lminor lpatch <<< "$left"
    IFS=. read -r rmajor rminor rpatch <<< "$right"
    (( lmajor > rmajor || (lmajor == rmajor && lminor > rminor) || (lmajor == rmajor && lminor == rminor && lpatch > rpatch) ))
}

old_version=$(tr -d '\r\n' < "$old_current/VERSION" 2>/dev/null || true)
[[ $old_version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || old_version=0.0.0
version_gt "$version" "$old_version" || { echo "升级版本必须高于当前版本：$old_version -> $version" >&2; exit 1; }

release_json=$bundle/release.json
release_name=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); echo (string)($v["fileName"] ?? "");' "$release_json")
release_hash=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); echo strtolower((string)($v["sha256"] ?? ""));' "$release_json")
release_site_version=$("$php" -r '$v=json_decode(file_get_contents($argv[1]), true, 32, JSON_THROW_ON_ERROR); echo (string)($v["websiteVersion"] ?? "");' "$release_json")
[[ $release_site_version == "$version" ]] || { echo "release.json websiteVersion 与 VERSION 不一致：$release_site_version / $version" >&2; exit 1; }
[[ $release_name =~ ^NovaProtect-Setup-[0-9]+\.[0-9]+\.[0-9]+\.exe$ ]] || { echo 'release.json 的安装包文件名无效。' >&2; exit 1; }
[[ $release_hash =~ ^[a-f0-9]{64}$ ]] || { echo 'release.json 的安装包 SHA-256 无效。' >&2; exit 1; }
installer="$bundle/downloads/$release_name"
[[ -f $installer ]] || { echo "缺少客户端安装包：$installer" >&2; exit 1; }
[[ $(sha256sum "$installer" | awk '{print tolower($1)}') == "$release_hash" ]] || { echo '客户端安装包 SHA-256 与 release.json 不一致。' >&2; exit 1; }

mkdir -p "$base/releases" "$state/backups" "$downloads" "$updates" "$state/bin"
# The site tree (<base>/current -> releases/<version>) lives outside the state
# directory; record the site root so bin/reset-admin-password.php can find app/.
printf '%s\n' "$base" > "$state/site-root"
chmod 0644 "$state/site-root"
chmod 0755 "$base/releases" "$state" "$downloads"
chmod 0750 "$state/bin"
chown www:www "$updates"
chmod 0700 "$updates"
repair_data_permissions() {
    chown -R www:www "$data"
    find "$data" -type d -exec chmod 0700 {} +
    find "$data" -type f -exec chmod 0600 {} +
}
repair_data_permissions
exec 9>"$state/deploy.lock"
flock -n 9 || { echo '另一安装/升级/回滚进程正在运行。' >&2; exit 1; }

backup="$state/backups/$(date -u +%Y%m%dT%H%M%SZ)-upgrade-$version-$$"
mkdir -p "$backup"
printf '%s\n' "$old_current" > "$backup/old-current"
printf '%s\n' "$old_previous" > "$backup/old-previous"
printf '%s\n' "$old_version" > "$backup/old-version"
printf '%s\n' "$version" > "$backup/new-version"
printf '%s\n' "$data" > "$backup/shared-data"
cp -a -- "$vhost" "$backup/vhost.conf"
if [[ -f "$state/data/schema.json" ]]; then cp -a -- "$state/data/schema.json" "$backup/schema-before.json"; fi
if [[ -f "$state/data/installation.json" ]]; then cp -a -- "$state/data/installation.json" "$backup/installation-before.json"; fi
(
    cd -- "$data"
    find . -maxdepth 1 -type f -print0 | sort -z | xargs -0 -r sha256sum
) > "$backup/data-files-before.sha256"

maintenance="$data/maintenance.json"
maintenance_tmp="$maintenance.$$.tmp"
printf '{"version":"%s","startedAt":"%s","reason":"offline-upgrade"}\n' "$version" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$maintenance_tmp"
chown www:www "$maintenance_tmp" 2>/dev/null || true
chmod 0600 "$maintenance_tmp"
mv -f -- "$maintenance_tmp" "$maintenance"

new_vhost="$backup/new-vhost.conf"
"$python" "$bundle/deploy/configure_nginx.py" \
    --input "$vhost" \
    --output "$new_vhost" \
    --php-socket "$php_socket" \
    --document-root "$base/current/public" \
    --template "$bundle/deploy/nginx-location.conf"
grep -q 'fastcgi_pass ' "$new_vhost"
grep -q 'include enable-php-84.conf;' "$new_vhost"
! grep -q 'proxy_pass ' "$new_vhost"
grep -q "root $base/current/public;" "$new_vhost"

changed=0
vhost_changed=0
cleanup() {
    local rc=$?
    trap - ERR
    set +e
    if [[ $rc -ne 0 && $changed == 1 ]]; then
        if [[ -n $old_current ]]; then ln -sfn -- "$old_current" "$base/current.rollback"; mv -Tf -- "$base/current.rollback" "$current"; fi
        if [[ -n $old_previous ]]; then ln -sfn -- "$old_previous" "$base/previous.rollback"; mv -Tf -- "$base/previous.rollback" "$previous"; else rm -f -- "$previous"; fi
        echo "升级失败，代码槽位已恢复为 $old_version；共享数据未回滚。备份：$backup" >&2
    fi
    if [[ $rc -ne 0 && $vhost_changed == 1 && -f $backup/vhost.conf ]]; then
        install -m 0644 "$backup/vhost.conf" "$vhost"
        "$nginx" -t >/dev/null 2>&1 && "$nginx" -s reload >/dev/null 2>&1 || true
    fi
    rm -f -- "$maintenance"
    if [[ $rc -ne 0 ]]; then echo "失败候选保留在 $release；可查看：$backup" >&2; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit $?' ERR

stage="$base/releases/.${version}.upgrade-$$"
mkdir "$stage"
cp -a -- "$bundle/app" "$stage/app"
cp -a -- "$bundle/public" "$stage/public"
cp -a -- "$bundle/release.json" "$stage/release.json"
cp -a -- "$bundle/VERSION" "$stage/VERSION"
mv -- "$stage" "$release"
chown -R root:root "$release"
find "$release" -type d -exec chmod 0755 {} +
find "$release" -type f -exec chmod 0644 {} +
install -m 0644 "$installer" "$downloads/$release_name"
chown www:www "$downloads/$release_name" 2>/dev/null || true
install -m 0750 -o root -g root "$bundle/deploy/upgrade-executor.sh" "$state/bin/upgrade-executor.sh"
install -m 0644 -o root -g root "$bundle/deploy/novaprotect-upgrade-executor.service" "$executor_service"
install -m 0644 -o root -g root "$bundle/deploy/novaprotect-upgrade-executor.timer" "$executor_timer"
install -m 0750 -o root -g root "$bundle/deploy/reset-admin-password.php" "$state/bin/reset-admin-password.php"
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now novaprotect-upgrade-executor.timer >/dev/null 2>&1 || true
fi

# Run migrations from the candidate release against shared data before the
# public slot changes. The migration does not alter installation.json ownership.
NOVAPROTECT_DATA_DIR="$data" NOVAPROTECT_RELEASE_DIR="$downloads" "$php" "$bundle/deploy/migrate.php" > "$backup/migration.log"
repair_data_permissions

install -m 0644 "$new_vhost" "$vhost"
vhost_changed=1
"$nginx" -t >/dev/null
"$nginx" -s reload >/dev/null

if [[ -n $old_current ]]; then
    ln -sfn -- "$old_current" "$base/previous.next"
    mv -Tf -- "$base/previous.next" "$previous"
fi
ln -sfn -- "$release" "$base/current.next"
mv -Tf -- "$base/current.next" "$current"
changed=1

rm -f -- "$maintenance"
healthy=0
for ((i=0; i<30; i++)); do
    if bash "$bundle/deploy/health-check.sh" "$version" "$backup"; then
        healthy=1
        break
    fi
    sleep 1
done
if [[ $healthy != 1 ]]; then
    http_status=$(<"$backup/health-http.status")
    https_status=$(<"$backup/health-https.status")
    echo "新版本健康检查失败（HTTP=$http_status，HTTPS=$https_status）。响应详情：$backup/health-http.json、$backup/health-http.headers、$backup/health-https.json、$backup/health-https.headers" >&2
    exit 1
fi

printf '{"completedAt":"%s","version":"%s","previous":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$version" "$old_version" > "$backup/upgrade.json"
ln -sfn -- "$backup" "$state/last-backup"
trap - EXIT
echo "NovaProtect 网站升级完成：$old_version -> $version"
echo "当前：$current；previous：$previous；客户端安装包：$downloads/$release_name"
echo "备份：$backup；回滚代码槽位可使用 deploy/rollback.sh（不会回写共享数据）"
echo '忘记管理员口令时，用 root 在 SSH 执行：php /www/server/novaprotect/bin/reset-admin-password.php'
