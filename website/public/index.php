<?php
declare(strict_types=1);
require dirname(__DIR__) . '/app/bootstrap.php';
require dirname(__DIR__) . '/app/view.php';
require dirname(__DIR__) . '/app/site.php';
require dirname(__DIR__) . '/app/portal.php';

$path = rtrim(parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/', '/') ?: '/';
$method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
np_set_common_headers();
set_exception_handler(static function (Throwable $exception) use ($path): void {
    error_log('NovaProtect request failed: ' . get_class($exception));
    if (str_starts_with($path, '/api/') || $path === '/health') np_problem('服务器暂时无法处理请求，请稍后重试。', 500, 'internal_error');
    np_error('服务器暂时无法处理请求，请稍后重试。', 500);
});
if (!in_array($method, ['GET', 'HEAD', 'POST'], true)) { header('Allow: GET, HEAD, POST'); np_problem('请求方法不支持。', 405); }
$assets = ['/css/site.css' => ['css/site.css', 'text/css; charset=utf-8'], '/js/upload-progress.js' => ['js/upload-progress.js', 'text/javascript; charset=utf-8'], '/assets/novaprotect.png' => ['assets/novaprotect.png', 'image/png'], '/favicon.ico' => ['favicon.ico', 'image/x-icon']];
if (isset($assets[$path]) && in_array($method, ['GET','HEAD'], true)) {
    [$file, $type] = $assets[$path]; header('Content-Type: ' . $type); header('Content-Length: ' . filesize(__DIR__ . '/' . $file));
    if ($method !== 'HEAD') readfile(__DIR__ . '/' . $file); exit;
}
if (is_file(np_data_dir() . '/maintenance.json')) { header('Retry-After: 30'); np_problem('网站正在升级，请稍后重试。', 503, 'maintenance'); }
np_migrate();
if ($path === '/health' && in_array($method, ['GET','HEAD'], true)) np_json_response(['status' => 'Healthy', 'websiteVersion' => np_website_version(), 'installed' => np_installed()]);
if (!np_installed() && !in_array($path, ['/install','/install.php'], true)) {
    if (str_starts_with($path, '/api/')) np_problem('网站尚未完成安装。', 503);
    np_redirect('/install');
}
$release = np_client_release();

if (str_starts_with($path, '/api/')) {
    // Public read-only release metadata and download; no account system exists.
    $reads = ['/api/releases/current', '/api/releases/current/download'];
    if (!in_array($path, $reads, true)) np_problem('接口不存在。', 404, 'not_found');
    if (!in_array($method, ['GET','HEAD'], true)) { header('Allow: GET, HEAD'); np_problem('请求方法不支持。', 405); }
    if ($path === '/api/releases/current') {
        $file = np_release_file(true);
        if (!$file) np_problem('当前版本暂不可下载。', 404, 'release_unavailable');
        np_json_response([
            'clientVersion' => $release['clientVersion'],
            'websiteVersion' => np_website_version(),
            'fileName' => $release['fileName'],
            'size' => filesize($file),
            'sha256' => strtolower((string) $release['sha256']),
            'minimumClientVersion' => is_string($release['minimumClientVersion'] ?? null) ? $release['minimumClientVersion'] : $release['clientVersion'],
            'forceUpdate' => ($release['forceUpdate'] ?? false) === true,
            'releaseNotes' => is_string($release['releaseNotes'] ?? null) ? $release['releaseNotes'] : '',
            'publishedAt' => is_string($release['publishedAt'] ?? null) ? $release['publishedAt'] : null,
            'downloadPath' => '/api/releases/current/download?version=' . rawurlencode($release['clientVersion']) . '&sha256=' . rawurlencode(strtolower((string) $release['sha256'])),
        ]);
    }
}
if ($path === '/api/releases/current/download') {
    $metadata = np_client_release(); if (isset($_GET['version']) && $_GET['version'] !== ($metadata['clientVersion'] ?? '')) np_problem('发布版本已变化，请重新检查更新。',409,'release_changed'); if (isset($_GET['sha256']) && strtolower((string)$_GET['sha256']) !== strtolower((string)($metadata['sha256'] ?? ''))) np_problem('发布文件已变化，请重新检查更新。',409,'release_changed'); $full = np_release_file(true);
    if ($full === null) np_problem('当前版本暂不可下载。',404);
    $file = basename($full); $size = filesize($full); $start = 0; $end = $size-1;
    $range = $_SERVER['HTTP_RANGE'] ?? '';
    if ($range !== '') {
        if (!preg_match('/^bytes=(\d*)-(\d*)$/D',$range,$m) || ($m[1]==='' && $m[2]==='')) { header('Content-Range: bytes */'.$size); np_problem('Range 无效。',416); }
        if ($m[1]==='') { $start=max(0,$size-(int)$m[2]); } else { $start=(int)$m[1]; if($m[2]!=='')$end=min($end,(int)$m[2]); }
        if($start>$end || $start>=$size){ header('Content-Range: bytes */'.$size); np_problem('Range 无效。',416); }
        http_response_code(206); header('Content-Range: bytes '.$start.'-'.$end.'/'.$size);
    }
    header('Content-Type: application/octet-stream'); header('Accept-Ranges: bytes'); header('Content-Length: '.($end-$start+1));
    header('Content-Disposition: attachment; filename="'.$file.'"; filename*=UTF-8\'\''.$file);
    session_write_close();
    if($method!=='HEAD'){ $f=fopen($full,'rb');fseek($f,$start);$left=$end-$start+1;while($left>0 && !feof($f)){ $chunk=fread($f,min(1048576,$left));if($chunk===false)break;echo $chunk;$left-=strlen($chunk);}fclose($f); } exit;
}

if ($path === '/install' || $path === '/install.php') { if ($method === 'POST') np_handle_install(); if (np_installed()) np_redirect('/admin'); np_install_page(); }
if ($path === '/admin/login') {
    if ($method === 'POST') {
        if (np_admin_session()) np_redirect('/admin');
        np_handle_admin_login();
    }
    if (np_admin_session()) np_redirect('/admin');
    np_admin_login_page();
}
if ($path === '/admin') {
    if (!np_admin_session()) np_redirect('/admin/login');
    if ($method === 'POST') {
        $tab = is_string($_GET['tab'] ?? null) && in_array($_GET['tab'], ['client-releases','upgrades'], true) ? $_GET['tab'] : 'client-releases';
        np_admin_post($tab);
    }
    $tab = is_string($_GET['tab'] ?? null) && in_array($_GET['tab'], ['client-releases','upgrades'], true) ? $_GET['tab'] : 'client-releases';
    np_admin_page($tab, max(1, min(10000, (int) ($_GET['page'] ?? 1))));
}
if ($path === '/logout' && $method === 'POST') { if (!np_check_csrf()) np_error('表单已过期，请刷新后重试。', 400); np_admin_sign_out(); np_redirect('/'); }
if ($method === 'POST') { header('Allow: GET, HEAD'); np_error('请求方法不支持。', 405); }
if ($path === '/download') { $available = np_release_file() !== null; $action = $available ? '<a class="button button-small" href="/api/releases/current/download">下载安装包</a>' : '<span class="status status-muted">待配置</span>'; np_page('下载', '<main class="content-shell"><div class="eyebrow">NovaProtect releases</div><h1>下载 NovaProtect</h1><p class="lede">Windows x64 客户端，无需账户即可下载。</p><section class="release-table surface"><div class="release-row release-head"><span>版本</span><span>平台</span><span>状态</span><span></span></div><div class="release-row"><span><strong>NovaProtect ' . np_e($release['clientVersion'] ?? '2.2.3') . '</strong><small>Windows 安装包</small></span><span>Windows x64</span><span>' . ($available ? '<span class="status status-ok">可下载</span>' : '<span class="status status-muted">准备发布</span>') . '</span><span>' . $action . '</span></div></section>' . ($available ? '<section class="surface release-integrity"><h2>文件校验</h2><p>' . np_e((string) $release['fileName']) . '</p><p>SHA-256 <code>' . np_e((string) ($release['sha256'] ?? '')) . '</code></p><p class="notice">安装包未附带 Authenticode 签名；SHA-256 用于下载完整性校验。</p></section>' : '<p class="notice">安装包尚未配置，请联系管理员。</p>') . '</main>'); }

if ($path === '/privacy') np_page('隐私说明', '<main class="content-shell prose"><h1>隐私说明</h1><p>NovaProtect 不提供用户账户、会员或邮件验证服务。网站仅保存管理员口令哈希、客户端发布记录与必要的会话数据，用于分发客户端和后台发布。</p><p>密码以不可逆哈希保存。桌面客户端通过 HTTPS 检查更新并下载安装包。</p></main>');
if ($path === '/sdk') np_sdk_page();
if ($path === '/client-updates') np_client_updates_page(np_client_release_history());
if ($path === '/') np_home($release);
np_error('页面不存在。', 404);
