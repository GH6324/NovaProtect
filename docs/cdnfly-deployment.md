# CDNfly 部署说明

NovaProtect 官网使用 PHP 8.4、PHP-FPM 和宝塔 Nginx，不再依赖 ASP.NET Core，也没有用户账户系统。当前网站版本为 `2.2.12`，发布时同时生成完整安装包和精简升级包：完整包位于 `artifacts/website-full/2.2.12/`，已有网站升级包位于 `artifacts/website-upgrade/2.2.12/`。已有站点只上传 `NovaProtect-Website-2.2.12-Linux-x64-BaoTa-Upgrade.zip`，以 root 执行包内的 `bash upgrade.sh`；可先运行 `bash upgrade.sh --check-package` 验证文件布局和 SHA-256。完整包仅用于首次安装或恢复。

安装脚本从自身位置解析 ZIP 根目录，因此可以从其他当前工作目录调用，不会把 `deploy/` 误判为包根目录或查找不存在的 `deploy/VERSION`。脚本自动检查 PHP-FPM、替换目标站点的 NovaProtect server block、保留现有 listen/TLS/日志、备份并可回滚。网站入口、API、管理员登录、安装向导和客户端下载均由 `public/index.php` 处理。

## CDNfly 规则

- 源站回源可使用 HTTP，Nginx/PHP 会接收固定的 canonical HTTPS scheme；
- 使用 `website/deploy/cdnfly-edge-policy.json` 作为控制台映射，先创建最高优先级的动态规则，覆盖 `/api/`、`/admin/login`、`/admin`、`/install`、`/download`、`/client-updates` 和 `/health`；
- 动态规则关闭 JS/CC/Bot 验证和边缘/浏览器缓存，保留 Cookie、Set-Cookie、Origin、Range 和 `Content-Range`；CSS、图片和图标使用次高优先级静态规则并关闭挑战；
- 修改规则后清理全站旧缓存，包括 HTML 和人机验证对象；
- 不要缓存带 Cookie 的 HTML/API/下载响应，也不要缓存安装向导；
- 源站会返回 `Cache-Control: no-store`、`CDN-Cache-Control: no-store`、`Surrogate-Control: no-store` 和 `Vary: Cookie`，用于阻止误缓存，但不能替代 CDNfly 控制台规则。

## 管理员与数据

网站只有一个管理员口令，哈希、PHP 后台会话和安装状态保存在 `/www/server/novaprotect/data`；客户端安装包存放于 `/www/server/novaprotect/downloads`。升级只替换发布目录，不覆盖这些共享数据。

## 验收

```bash
curl -sS -D - -H 'Host: nova.fbi.plus' http://127.0.0.1/health
curl -sk -D - --resolve nova.fbi.plus:443:127.0.0.1 https://nova.fbi.plus/health
```

确认状态为 `Healthy`，响应包含四个 `no-store` 相关头，然后浏览器打开 `/install` 完成初始化。生产验收应再从 CDN 公网入口验证 `/admin/login`、`/api/releases/current` 和客户端下载。

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

预检会请求管理员登录页、发布 API、健康检查和静态资源；如果这些请求返回 HTTP `444`、`Server: cdn` 的验证内容或 `/_guard/auto.js`，说明请求仍在 CDNfly 边缘层被拦截。已安装网站的 `/install` 和 `/install.php` 是锁定路径，返回 `302/403/404/444` 属于预期。完整操作步骤见 `website/deploy/CDNFLY.md`。
