# CDNfly deployment for NovaProtect

`cdnfly-edge-policy.json` is a declarative rule map for the CDNfly console. It is intentionally not presented as an official CDNfly import payload because CDNfly installations can expose different console labels and API schemas.

## Apply the rules

1. Create the `application-dynamic` rule at the highest priority for `nova.fbi.plus`.
2. Match the exact web paths and the `/api/` prefix listed in the JSON file.
3. Set edge cache and browser cache to bypass. Disable JavaScript, CC and bot challenges for this rule.
4. Preserve request `Cookie`, `Origin`, `Range`, `Host`, `X-Forwarded-For` and `X-Forwarded-Proto` headers.
5. Preserve `Set-Cookie`, `Cache-Control`, `CDN-Cache-Control`, `Surrogate-Control`, `Vary` and `Content-Range` response headers.
6. Create the lower-priority `application-static` rule for `/css/`, `/js/`, `/assets/` and `/favicon.ico`, also with challenge off and cache bypass.
7. Keep the fallback rule below both application rules. Do not rewrite `/api/` to a static page or convert POST requests to GET.
8. Purge the full site cache, including HTML and challenge objects. A partial asset purge can leave the old guard response cached.

The `X-NovaProtect-Client` header is only a diagnostic/routing hint. Do not use it as an authentication or security allow-list signal.

## Why the admin installer upload does not trip the WAF

The "发布客户端新版本" panel no longer submits a multipart form. The browser slices the installer into 512 KB pieces, base64-encodes each piece and POSTs it as `text/plain` to `/api/admin/release/chunk`. A single request therefore carries no `Content-Disposition`, no `filename`, no `.exe` suffix and no `MZ`/`PE` binary header, so file-upload rules and oversized-body rules have nothing to match.

| Request | Method | Purpose |
| --- | --- | --- |
| `/api/admin/release/begin` | POST | opens a session, body is only `{"size":<bytes>,"kind":"client\|upgrade"}` |
| `/api/admin/release/chunk?sid=&index=` | POST | one base64 slice, about 683 KB |
| `/api/admin/release/finish?sid=` | POST | validates the installer or upgrade archive, then publishes it |
| `/api/admin/release/abort?sid=` | POST | drops the staging session |

Both the client installer and the offline upgrade ZIP use this channel, so neither ever appears to the edge as a file upload.

Three things must hold:

1. The `application-dynamic` CDNfly rule covers the `/api/` prefix (it already does) and never rewrites or challenges POST requests.
2. The origin Nginx allows `client_max_body_size 4m` on `/api/` (`nginx-location.conf` already contains it).
3. If the WAF has a separate "file upload protection" switch, add `/api/admin/release/` to its allow list. A conforming chunk request has no file characteristics anyway.

After the website is installed, `/install` and `/install.php` are locked by the application. The preflight therefore accepts `302`, `403`, `404` or `444` for those two paths when `/health` reports `"installed":true`. It continues to reject `444` and guard content for `/admin/login`, `/api/`, the health endpoint and static resources.

## Verify the edge

From the uploaded package directory, run:

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

The check fails on HTTP `444`, a `Server: cdn` guard response, or a body containing `/_guard/auto.js`. It probes the anonymous admin login page, the release API, the chunked upload endpoint and static resources through the same CDN routes used by the desktop client.

## Diagnose a failing admin upload

With an admin session, open `https://nova.fbi.plus/api/admin/release/ping` in the browser:

```json
{"ok":true,"websiteVersion":"2.2.21","method":"GET","path":"/api/admin/release/ping","scheme":"https","admin":true,"chunkBytes":524288}
```

- JSON like the above: the chunked transport is deployed and reachable, so the failure is further down the request chain.
- An HTML error page or a 404: the site is still running an older website package without `app/upload.php`.
- `"scheme":"http"`: the request is not on HTTPS. An http→https 301 rewrites POST into GET, which is exactly what produces the "请求方法不支持" page.

Expected result:

```text
CDNFLY-PREFLIGHT-OK
```

If the output still reports `444`, the request is being rejected before PHP and Nginx. Recheck rule priority and purge the CDN again; changing PHP login code cannot bypass an edge rejection.
