# NovaProtect PHP 官网

当前网站版本：`2.2.16`。运行时固定为 PHP 8.4、PHP-FPM 和宝塔 Nginx，不再依赖 ASP.NET Core、dotnet 或 systemd 应用服务。网站没有用户账户或会员系统，只提供客户端下载、更新日志和一个管理员口令保护的后台发布入口。

## 宝塔安装

1. 将 `artifacts/website-full/2.2.16/` 下的完整网站 ZIP 上传到服务器并解压。
2. 进入解压目录，以 root 执行：

   ```bash
   bash install.sh --check-package
   bash install.sh
   ```

3. 可先使用 `--check-package` 只读验证包文件和 SHA-256。安装入口会以 ZIP 根目录解析文件，不受当前工作目录影响；正式安装会检查 PHP CLI、JSON/session/OpenSSL、PHP-FPM socket、宝塔 Nginx、客户端安装包 SHA-256，并备份原站点配置。
4. 安装完成后，在浏览器打开 `https://nova.fbi.plus/install`，输入终端只显示一次的安装口令，设置管理员口令并锁定安装入口。

安装过程维护 `/www/wwwroot/nova.fbi.plus/current` 和 `previous` 两个发布槽位；管理员口令哈希、后台会话、安装状态和客户端下载文件保存在 `/www/server/novaprotect`，升级不会覆盖。

## 回滚

在当前解压目录执行：

```bash
bash deploy/rollback.sh
```

回滚只恢复发布槽位和 Nginx 配置，不删除管理员口令等共享数据。

## 离线升级

已有网站使用 `artifacts/website-upgrade/2.2.16/` 下的精简升级 ZIP。该包不包含 `install.sh`、`deploy/install.sh` 或首次安装 Nginx 配置，只能在已安装站点上执行：

```bash
bash upgrade.sh --check-package
bash upgrade.sh
```

每次发布同时保留完整包和升级包，分别位于 `artifacts/website-full/<version>/` 与 `artifacts/website-upgrade/<version>/`；旧的单包输出路径不再生成。

## 管理后台上传离线升级包

管理员在 `/admin/login` 输入口令后打开“管理后台 → 版本与升级”，上传 `website-upgrade/<version>/` 下的精简 ZIP。上传表单会显示实时进度，文件发送完成后继续显示服务器校验状态。网站会校验 `packageType=upgrade`、版本递增、ZIP 路径安全、`SHA256SUMS` 全量覆盖、客户端安装包哈希，以及完整安装入口是否被错误带入。通过后包保存在 `/www/server/novaprotect/updates/<version>/<upload-id>/`，不进入 Web 根目录；后台显示 root 执行命令，PHP-FPM 不直接执行 root 升级。

客户端发布页可直接选取 EXE 文件。服务器会从 PE 版本资源读取客户端版本、自动规范化存储文件名，并从 PE 描述生成更新说明；新文件的版本必须高于当前发布版本。PHP-FPM 的每站点上传上限为 256 MB，部署包会自动写入 Nginx/PHP 上传配置；PHP-FPM 默认最多 5 分钟刷新 `.user.ini`。

服务器首次安装或升级后会启用 `novaprotect-upgrade-executor.timer`。上传校验通过后，点击已上传记录中的“一键升级”；root 执行器会自动复核、备份、迁移、健康检查并在失败时回滚，后台会显示排队、执行中、完成或失败状态。

## 管理员登录行为

- `GET /admin/login` 显示管理员口令登录页；POST 校验口令成功后跳转 `/admin`。
- 未登录访问 `/admin` 会 302 跳转到 `/admin/login`；登录后台有会话过期和写入频率限制。
- 安装向导设置的管理员口令以 Argon2id（不可用时退化为 PBKDF2-SHA256 60 万次）哈希保存。
- 忘记管理员口令时，用 root 在 SSH 执行 `php /www/server/novaprotect/bin/reset-admin-password.php` 重置（详见 `deploy/README.md`）；工具会自动定位已安装站点的 app 目录（`/www/wwwroot/nova.fbi.plus/current/app`），也可用 `--locate` 先诊断位置；重置会失效全部后台会话并清除登录限速，不需要原口令。
- 客户端下载、`/api/releases/current` 和 `/client-updates` 全部匿名可读，不需要会话。

## CDNfly / Nginx

- Nginx 使用 `try_files ... /index.php` 和 PHP-FPM；原有 `listen`、TLS 证书、日志设置会被保留。
- HTML、API、后台会话、下载、CSS、图片和图标都返回 `no-store`、`CDN-Cache-Control: no-store`、`Surrogate-Control: no-store` 和 `Vary: Cookie`。
- CDNfly 规则文件为 `deploy/cdnfly-edge-policy.json`，控制台步骤为 `deploy/CDNFLY.md`；动态路径必须放在最高优先级，关闭 JS/CC/Bot 验证、旁路缓存并保留 Cookie/Set-Cookie/Origin/Range。`/css/`、`/js/`、`/assets/` 和图标也必须关闭挑战，避免站点资源被替换成验证页。应用后清理全站缓存，再运行 `bash deploy/cdnfly-check.sh https://nova.fbi.plus`；脚本会检测管理员登录页、API、健康检查和静态资源的 HTTP `444`、`Server: cdn` 验证页及 `/_guard/auto.js`。已完成安装的网站会把 `/install` 和 `/install.php` 视为锁定路径，返回 `302/403/404/444` 均可通过该项检查。
- 安装脚本不会创建新的 `novaprotect.service`。旧 ASP.NET 服务只在回滚时按备份恢复。

## 包内容

- `public/`：唯一 Web 根目录和 PHP 入口；
- `app/`：管理员会话、安装向导和发布目录逻辑；
- `deploy/`：宝塔 Nginx 配置器、安装和回滚脚本、SSH 管理员口令重置工具（`deploy/reset-admin-password.php`）；
- `deploy/cdnfly-edge-policy.json`、`deploy/cdnfly-check.sh`、`deploy/CDNFLY.md`：CDNfly 规则映射、边缘预检和控制台步骤；
- `downloads/`：经过 SHA-256 校验的 `NovaProtect-Setup-2.3.1.exe`；
- 源客户端安装包独立保存于 `artifacts/client-installer/2.3.1/`，网站 ZIP 只携带部署所需的 `downloads/` 副本；
- `SHA256SUMS`：包内文件清单。

生产环境不要把 `data/`、管理员口令文件、会话目录或生产 Nginx 证书放入网站 ZIP；安装脚本会在 `/www/server/novaprotect/data` 创建持久目录。
