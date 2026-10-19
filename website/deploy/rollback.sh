#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 运行 bash deploy/rollback.sh' >&2; exit 1; }

base=/www/wwwroot/nova.fbi.plus
state=/www/server/novaprotect
nginx=/www/server/nginx/sbin/nginx
vhost=/www/server/panel/vhost/nginx/nova.fbi.plus.conf
service=/etc/systemd/system/novaprotect.service

[[ -d $state/backups ]] || { echo '没有可用的安装备份目录。' >&2; exit 1; }
[[ -x $nginx ]] || nginx=$(command -v nginx 2>/dev/null || true)
[[ -n $nginx && -x $nginx ]] || { echo '未找到宝塔 Nginx。' >&2; exit 1; }

exec 9>"$state/deploy.lock"
flock -n 9 || { echo '另一安装/回滚进程正在运行。' >&2; exit 1; }

backup=$(readlink -f "$state/last-backup" 2>/dev/null || true)
[[ $backup == "$state/backups/"* && -f $backup/old-current ]] || { echo '没有可用的安装备份。' >&2; exit 1; }

read_slot() { tr -d '\r\n' < "$1"; }
old_current=$(read_slot "$backup/old-current")
old_previous=$(read_slot "$backup/old-previous")
validate_target() {
    local target=$1
    [[ -z $target ]] && return 0
    [[ $target == "$base/releases/"* ]] || { echo "备份中的发布目标不在允许目录：$target" >&2; exit 1; }
    [[ -d $target ]] || { echo "备份中的发布目录不存在：$target" >&2; exit 1; }
    if [[ ! -f $target/public/index.php && ! -f $target/app/bootstrap.php && ! -f $target/NovaProtect.Web ]]; then
        echo "备份中的发布目录不是可识别的 NovaProtect 发布物：$target" >&2
        exit 1
    fi
}
validate_target "$old_current"
validate_target "$old_previous"

restore_link() {
    local slot=$1 target=$2
    if [[ -n $target ]]; then
        ln -sfn -- "$target" "$slot.rollback"
        mv -Tf -- "$slot.rollback" "$slot"
    else
        rm -f -- "$slot"
    fi
}

restore_link "$base/current" "$old_current"
restore_link "$base/previous" "$old_previous"
if [[ -f $backup/vhost.conf ]]; then
    install -m 0644 "$backup/vhost.conf" "$vhost"
elif [[ -f $backup/vhost-missing ]]; then
    rm -f -- "$vhost"
else
    echo '备份缺少原站点 Nginx 配置，拒绝继续。' >&2
    exit 1
fi

systemctl_available=0
command -v systemctl >/dev/null 2>&1 && systemctl_available=1
legacy_unit=$(read_slot "$backup/legacy-unit" 2>/dev/null || echo 0)
was_enabled=$(read_slot "$backup/was-enabled" 2>/dev/null || echo 0)
was_active=$(read_slot "$backup/was-active" 2>/dev/null || echo 0)
if [[ $legacy_unit == 1 && -f $backup/service ]]; then
    install -m 0644 "$backup/service" "$service"
elif [[ $legacy_unit == 0 ]]; then
    rm -f -- "$service"
fi

if [[ $systemctl_available == 1 ]]; then
    systemctl daemon-reload
    if [[ $was_enabled == 1 ]]; then systemctl enable novaprotect.service >/dev/null; else systemctl disable novaprotect.service >/dev/null 2>&1 || true; fi
    if [[ $was_active == 1 ]]; then
        systemctl restart novaprotect.service
        ready=0
        for ((i=0; i<30; i++)); do
            if curl --noproxy '*' --fail --silent --show-error --max-time 3 http://127.0.0.1:5080/health | grep -q Healthy; then ready=1; break; fi
            sleep 1
        done
        [[ $ready == 1 ]] || { echo '旧 ASP.NET 服务未就绪，请检查 journalctl -u novaprotect。' >&2; exit 1; }
    else
        systemctl stop novaprotect.service >/dev/null 2>&1 || true
    fi
fi

"$nginx" -t
"$nginx" -s reload
# rollback only restores the application/vhost; the shared admin/data state is intentionally preserved.
echo "已恢复原站点/服务配置。管理员口令和数据保持不变。备份：$backup"