# 宝塔 PHP 部署说明

这是 NovaProtect 官网的 Linux x64 宝塔部署包，固定使用 PHP 8.4、PHP-FPM 和 Nginx。ZIP 根目录的 `install.sh` 是唯一安装入口；它不依赖 dotnet，也不会创建新的 ASP.NET systemd 应用服务。

## 安装

```bash
unzip NovaProtect-Website-<website-version>-Linux-x64-BaoTa-Full.zip -d /www/server/novaprotect-upload
cd /www/server/novaprotect-upload
bash install.sh --check-package
bash install.sh
```

ZIP 根目录的 `install.sh` 会转交给 `deploy/install.sh`；两者都依据自身位置解析包根目录，不受当前工作目录影响。`--check-package` 只读校验文件布局和包内 SHA-256，不修改服务器状态。正式安装脚本会：

- 校验包内 `SHA256SUMS`、客户端安装包和 `release.json`；
- 检查 Python 3.8+、PHP 8.4、JSON/session/hash_pbkdf2/random_bytes/OpenSSL/Zip、宝塔 Nginx 和 PHP 8.4 PHP-FPM；
- 备份当前 Nginx 配置、发布槽位、安装状态和旧的 `novaprotect.service`；
- 把 PHP 网站发布到 `/www/wwwroot/nova.fbi.plus/releases/<version>`，并原子切换 `current` / `previous`；
- 写入 `/www/server/novaprotect/data`、`downloads` 和备份目录；
- 生成 PHP-FPM Nginx 规则，保留现有 listen、server_name、TLS 证书和日志；
- 重载 Nginx，检查 `/health`、不缓存响应头和首次安装页面。

安装成功后打开：

```text
https://nova.fbi.plus/install
```

终端输出的一次性安装口令有效 24 小时。向导完成后安装入口自动锁定；升级不会覆盖管理员口令、session keys 或安装状态。

## 回滚

```bash
bash deploy/rollback.sh
```

回滚使用 `/www/server/novaprotect/last-backup`，只恢复网站发布槽位、Nginx 配置和安装前旧服务状态，不删除管理员口令等共享数据。

## 离线升级

发布系统会同时生成两个 ZIP，并保存到不同目录：

```text
artifacts/website-full/<version>/NovaProtect-Website-<version>-Linux-x64-BaoTa-Full.zip
artifacts/website-upgrade/<version>/NovaProtect-Website-<version>-Linux-x64-BaoTa-Upgrade.zip
```

已有网站只上传 `website-upgrade` 下的精简升级 ZIP。它只包含升级所需的 PHP、资源、迁移脚本、清单和客户端下载文件，不含 `install.sh`、`deploy/install.sh` 或 Nginx 初始配置，不能用于首次安装：

```bash
bash upgrade.sh --check-package
bash upgrade.sh
```

首次安装或完整恢复才使用 `website-full` 下的完整安装 ZIP；不要把完整包当作离线升级包使用。

升级要求包内 `VERSION` 高于当前 `current/VERSION`。脚本会校验包清单和客户端安装包哈希，写入短暂的维护状态，执行 PHP 数据迁移，然后原子切换 `current` 和 `previous`。管理员口令、后台会话、安装状态和下载目录均保留；失败只恢复代码槽位，不覆盖升级后的共享数据。升级会备份现有 Nginx 配置，并重新生成保留 listen、TLS 证书、日志和 `include enable-php-84.conf;` 的 PHP 8.4 配置；生成或重载失败会自动恢复原配置。

升级完成后可在管理后台“版本与升级”查看当前版本。升级失败时保留候选目录和备份目录，先查看备份中的 `migration.log`、`health.json` 与 `response-headers`，再使用 `bash deploy/rollback.sh` 恢复代码槽位。

## 管理后台上传升级包

管理员可以在“管理后台 → 版本与升级”上传精简升级 ZIP。上传流程只在 PHP-FPM 内做安全校验和暂存，不直接执行 root 命令。服务器首次安装或升级后会启用 `novaprotect-upgrade-executor.timer`；校验通过后，在已上传包的记录中点击“一键升级”，由 root 执行器自动复核、备份、迁移、健康检查并回滚。后台会持续显示排队、执行中、完成或失败状态，不需要手动复制命令。

包会保存到 `/www/server/novaprotect/updates/<version>/<upload-id>/`，不在网站公开目录。管理员上传客户端或升级 ZIP 时，网站会为 PHP-FPM 设置 `upload_max_filesize=256M`、`post_max_size=260M`；Nginx 只在 `/admin` 上传路由放宽到 `260M`。`.user.ini` 默认最多 5 分钟生效。如果仍提示限制过小，请检查 PHP 8.4 的 `user_ini.filename` 没有被禁用，并确认 Nginx 与 PHP-FPM 已加载新网站包配置。

## 管理后台手动发布客户端

在“管理后台 → 客户端发布”选择 `.exe` 文件即可，不要求原文件使用特定名字。服务器会验证 PE 格式和 NovaProtect 产品描述，从 PE 版本资源读取客户端版本，再自动保存为 `NovaProtect-Setup-x.y.z.exe`；更新说明留空时会读取 PE 文件描述。客户端 EXE 上限为 256 MB，版本必须高于当前发布版本。若 Nginx/CDN 返回 HTTP 413，请检查对应请求体限制；PHP 已丢弃超限表单时，后台会显示实际 `post_max_size` 并提示修复。

## 重置管理员口令（SSH）

网站只有一个管理员口令，没有用户账户。忘记口令时不需要重装：用 root 在 SSH 执行安装或升级脚本部署好的工具，按提示输入两次新口令（10 到 128 字节）即可。

```bash
php /www/server/novaprotect/bin/reset-admin-password.php
```

也支持非交互用法，便于自动化或远程脚本：

```bash
php /www/server/novaprotect/bin/reset-admin-password.php --password '新的管理员口令'
printf '%s' '新的管理员口令' | php /www/server/novaprotect/bin/reset-admin-password.php --stdin
php /www/server/novaprotect/bin/reset-admin-password.php --generate
```

重置通过网站共用的写入逻辑更新 `data/admin.json`（Argon2id，不可用时退化为 PBKDF2-SHA256 60 万次），完成后自动失效全部后台会话并清除登录失败限速记录，随后即可用新口令登录 `https://nova.fbi.plus/admin/login`。工具不询问原口令——SSH 权限即授权边界，请只开放给可信运维人员；`--keep-sessions` 可保留已登录会话。

app 目录按以下顺序自动探测：`--app` 指定值 → 环境变量 `NOVAPROTECT_APP_DIR` → 解压包内的 `app` → `<state>/site-root` 记录的站点根下的 `current` → `<state>/current`、`/www/wwwroot/nova.fbi.plus/current` → `/www/wwwroot/*/current`、`/www/wwwroot/*/app`。安装脚本会把站点根写入 `/www/server/novaprotect/site-root`，因此已安装站点无需任何参数即可定位（站点在 `/www/wwwroot/nova.fbi.plus/current/app`，与 state 目录是两棵不同的树）。不确定位置时先诊断：

```bash
php /www/server/novaprotect/bin/reset-admin-password.php --locate
```

数据目录不在默认位置时用 `--data-dir` 指定；自动探测全部失败时（例如自定义站点根）用 `--app` 指定 app 目录：

```bash
php deploy/reset-admin-password.php --data-dir /www/server/novaprotect/data
php /www/server/novaprotect/bin/reset-admin-password.php --app=/www/wwwroot/nova.fbi.plus/current/app
php deploy/reset-admin-password.php --help
```

## PHP 8.4 PHP-FPM socket

脚本只从宝塔 PHP 8.4 配置和带 `84` 标识的 socket 自动探测，避免误连 PHP 8.2/8.3。探测不到时可以显式指定：

```bash
NOVAPROTECT_PHP_SOCKET=/tmp/php-cgi-84.sock bash install.sh
```

脚本会先尝试启动 `php-fpm-84`、`php84` 等常见服务名；PHP 8.4 未安装时会尝试调用宝塔安装脚本。PHP-FPM 必须由宝塔或系统服务启动，脚本不会把其他 PHP 版本绑定到站点。

生成的 Nginx 配置保留 `include enable-php-84.conf;`，因此宝塔会把站点识别为 PHP 8.4，而不是“静态 PHP”。如果面板仍显示静态，请先在宝塔安装并启动 PHP 8.4，再重新执行安装或升级包。

## CDNfly 与缓存

源站和 PHP 同时返回：

```text
Cache-Control: no-store, private, max-age=0, no-cache, must-revalidate
CDN-Cache-Control: no-store
Surrogate-Control: no-store
Vary: Cookie
```

不要只修改源站 Nginx：HTTP `444` 或 `/_guard/auto.js` 说明请求在 CDNfly 边缘层被拦截。将 `deploy/cdnfly-edge-policy.json` 中的 `application-dynamic` 规则放在最高优先级，覆盖 `/api/`、`/admin/login`、`/admin`、`/install`、`/download`、`/client-updates`、`/health` 等路径；关闭这些路径的 JS/CC/Bot 验证，旁路边缘和浏览器缓存，并保留 Cookie、Set-Cookie、Origin、Range 和 `Content-Range`。静态资源 `/css/`、`/assets/`、`/favicon.ico` 使用较低优先级的 `application-static` 规则，同样关闭挑战，避免 CSS 或图标被替换为验证页。

规则应用后清理 CDNfly 全站缓存，再运行：

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

预检会测试健康检查、管理员登录页、安装页和静态资源；遇到 HTTP `444`、`Server: cdn` 的验证页或 `/_guard/auto.js` 会失败。完整控制台步骤见 `deploy/CDNFLY.md`。公网 HTTPS 可以由 CDNfly 终止，源站会把 `X-Forwarded-Proto` 固定为 `https`，避免回源 HTTP 造成重定向循环。

## 目录约定

```text
/www/wwwroot/nova.fbi.plus/current       当前 PHP 发布（app/ 与 public/）
/www/wwwroot/nova.fbi.plus/previous      上一个发布
/www/wwwroot/nova.fbi.plus/releases      所有发布
/www/server/novaprotect/data             管理员口令哈希、后台会话、安装状态
/www/server/novaprotect/site-root        站点根目录记录（供重置工具定位 app/）
/www/server/novaprotect/bin              root 升级执行器与管理员口令重置工具
/www/server/novaprotect/downloads        客户端下载文件
/www/server/novaprotect/backups          自动备份
```

不要把 `data`、管理员口令 JSON、session 文件或生产 Nginx 证书打回 ZIP。网站没有用户账户系统，`data` 下只有管理员与发布相关数据。
