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

After the website is installed, `/install` and `/install.php` are locked by the application. The preflight therefore accepts `302`, `403`, `404` or `444` for those two paths when `/health` reports `"installed":true`. It continues to reject `444` and guard content for `/admin/login`, `/api/`, the health endpoint and static resources.

## Verify the edge

From the uploaded package directory, run:

```bash
bash deploy/cdnfly-check.sh https://nova.fbi.plus
```

The check fails on HTTP `444`, a `Server: cdn` guard response, or a body containing `/_guard/auto.js`. It probes the anonymous admin login page, the release API and static resources through the same CDN routes used by the desktop client.

Expected result:

```text
CDNFLY-PREFLIGHT-OK
```

If the output still reports `444`, the request is being rejected before PHP and Nginx. Recheck rule priority and purge the CDN again; changing PHP login code cannot bypass an edge rejection.
