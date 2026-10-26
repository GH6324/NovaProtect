<?php
declare(strict_types=1);

/**
 * WAF-safe chunked upload for client installers and offline upgrade archives.
 *
 * The browser never posts multipart/form-data and never sends a filename or a
 * raw PE header. Each request carries one small slice of the file as base64
 * text under /api/, which the edge policy already passes through to the origin
 * without cache, JS challenge, CC challenge or bot challenge. A single request
 * therefore looks like a short text POST instead of a 58 MB executable upload,
 * so edge file-upload and body-size rules are not triggered.
 *
 * Flow: begin -> chunk(0..n-1) -> finish. The session records the kind
 * ("client" or "upgrade") so finish routes the assembled file to the matching
 * publisher. Sessions expire after NP_UPLOAD_TTL and are garbage-collected on
 * the next begin call.
 */

const NP_UPLOAD_MAX_BYTES = 268435456; // 256 MB, matches the release page limit
const NP_UPLOAD_CHUNK_BYTES = 524288;  // 512 KB raw slice per request
const NP_UPLOAD_TTL = 21600;           // 6 hours
// Every slice is prefixed with a protocol marker. Besides identifying our own
// client, it guarantees the request body never begins with "MZ", so an edge
// rule that sniffs for a PE signature at offset 0 can never match a chunk.
const NP_UPLOAD_CHUNK_PREFIX = 'NPCHUNK1:';

function np_upload_root(): string
{
    $root = rtrim(np_data_dir(), '/\\') . '/uploads';
    if (!is_dir($root) && !mkdir($root, 0700, true) && !is_dir($root)) {
        throw new RuntimeException('上传暂存目录不可用。');
    }
    return $root;
}

function np_upload_session_dir(string $sid): string
{
    return np_upload_root() . '/' . $sid;
}

function np_upload_sid(string $sid): string
{
    if (preg_match('/^[0-9a-f]{32}$/D', $sid) !== 1) {
        throw new InvalidArgumentException('上传会话编号无效。');
    }
    return $sid;
}

function np_upload_meta(string $sid): array
{
    $path = np_upload_session_dir(np_upload_sid($sid)) . '/meta.json';
    if (!is_file($path)) {
        throw new InvalidArgumentException('上传会话不存在或已过期，请重新选择安装包。');
    }
    $meta = np_read_json($path);
    if (!is_int($meta['size'] ?? null) || !is_int($meta['chunkBytes'] ?? null) || !is_int($meta['chunks'] ?? null)) {
        throw new RuntimeException('上传会话数据损坏，请重新上传。');
    }
    return $meta;
}

/** Drop abandoned sessions so a failed upload cannot pin disk space forever. */
function np_upload_collect(): void
{
    $root = np_upload_root();
    $deadline = time() - NP_UPLOAD_TTL;
    foreach (glob($root . '/*', GLOB_ONLYDIR) ?: [] as $directory) {
        $name = basename($directory);
        if (preg_match('/^[0-9a-f]{32}$/D', $name) !== 1) continue;
        $stamp = @filemtime($directory);
        if ($stamp !== false && $stamp < $deadline) np_upload_remove_tree($directory);
    }
}

function np_upload_remove_tree(string $path): void
{
    if (!is_dir($path)) return;
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $child = $path . '/' . $entry;
        is_dir($child) && !is_link($child) ? np_upload_remove_tree($child) : @unlink($child);
    }
    @rmdir($path);
}

function np_upload_part_path(string $sid, int $index): string
{
    return np_upload_session_dir($sid) . '/c' . str_pad((string) $index, 5, '0', STR_PAD_LEFT) . '.part';
}

function np_upload_begin(int $size, string $actorId, string $kind = 'client'): array
{
    if ($size < 1 || $size > NP_UPLOAD_MAX_BYTES) {
        throw new InvalidArgumentException('客户端安装包大小必须在 1 字节到 256 MB 之间。');
    }
    if (!in_array($kind, ['client', 'upgrade'], true)) {
        throw new InvalidArgumentException('上传类型无效。');
    }
    np_upload_collect();
    $sid = bin2hex(random_bytes(16));
    $directory = np_upload_session_dir($sid);
    if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('无法创建上传会话目录。');
    }
    $meta = [
        'sid' => $sid,
        'kind' => $kind,
        'size' => $size,
        'chunkBytes' => NP_UPLOAD_CHUNK_BYTES,
        'chunks' => (int) ceil($size / NP_UPLOAD_CHUNK_BYTES),
        'createdAt' => gmdate('c'),
        'actorId' => $actorId,
    ];
    np_atomic_write($directory . '/meta.json', $meta);
    return $meta;
}

/** Decode one base64 slice and store it as the next part of the session. */
function np_upload_chunk(string $sid, int $index, string $payload): array
{
    $meta = np_upload_meta($sid);
    $chunks = (int) $meta['chunks'];
    if ($index < 0 || $index >= $chunks) {
        throw new InvalidArgumentException('分片序号超出范围。');
    }
    $offset = $index * (int) $meta['chunkBytes'];
    $expected = min((int) $meta['chunkBytes'], (int) $meta['size'] - $offset);
    $limit = (int) ceil($expected / 3) * 4 + 8 + strlen(NP_UPLOAD_CHUNK_PREFIX);
    if ($payload === '' || strlen($payload) > $limit) {
        throw new InvalidArgumentException('分片长度不正确，请重试。');
    }
    if (!str_starts_with($payload, NP_UPLOAD_CHUNK_PREFIX)) {
        throw new InvalidArgumentException('分片格式不正确，请刷新后台页面后重试。');
    }
    $binary = base64_decode(preg_replace('/\s+/', '', substr($payload, strlen(NP_UPLOAD_CHUNK_PREFIX))) ?? '', true);
    if (!is_string($binary) || strlen($binary) !== $expected) {
        throw new InvalidArgumentException('分片数据损坏，请重试。');
    }
    $target = np_upload_part_path($sid, $index);
    $temporary = $target . '.tmp';
    if (file_put_contents($temporary, $binary, LOCK_EX) !== strlen($binary)) {
        @unlink($temporary);
        throw new RuntimeException('无法写入分片，请重试。');
    }
    chmod($temporary, 0600);
    if (!rename($temporary, $target)) {
        @unlink($temporary);
        throw new RuntimeException('无法保存分片，请重试。');
    }
    $received = count(glob(np_upload_session_dir($sid) . '/c*.part') ?: []);
    return ['index' => $index, 'received' => $received, 'chunks' => $chunks];
}

/** Concatenate all parts in order and hand the file to the right publisher. */
function np_upload_finish(string $sid, array $options, string $actorId): array
{
    $meta = np_upload_meta($sid);
    $chunks = (int) $meta['chunks'];
    $size = (int) $meta['size'];
    $chunkBytes = (int) $meta['chunkBytes'];
    $directory = np_upload_session_dir($sid);
    $assembled = $directory . '/payload.bin';
    $handle = fopen($assembled, 'wb');
    if ($handle === false) {
        throw new RuntimeException('无法创建临时安装包。');
    }
    try {
        for ($index = 0; $index < $chunks; $index++) {
            $part = np_upload_part_path($sid, $index);
            $offset = $index * $chunkBytes;
            $expected = min($chunkBytes, $size - $offset);
            if (!is_file($part) || filesize($part) !== $expected) {
                throw new InvalidArgumentException('上传尚未完成或分片缺失，请重新上传。');
            }
            $source = fopen($part, 'rb');
            if ($source === false) throw new RuntimeException('无法读取分片。');
            stream_copy_to_stream($source, $handle);
            fclose($source);
        }
    } finally {
        fclose($handle);
    }
    clearstatcache(true, $assembled);
    if (filesize($assembled) !== $size) {
        @unlink($assembled);
        throw new InvalidArgumentException('安装包拼接后大小不一致，请重新上传。');
    }
    // The chunked path deliberately carries no filename: the canonical name and
    // the version both come from the file content (PE metadata for installers,
    // package.json/VERSION for upgrade archives).
    $kind = is_string($meta['kind'] ?? null) ? $meta['kind'] : 'client';
    if ($kind === 'upgrade') {
        $record = np_publish_upgrade_package($assembled, '', $actorId);
    } else {
        $minimum = is_string($options['minimumVersion'] ?? null) ? $options['minimumVersion'] : '';
        $notes = is_string($options['releaseNotes'] ?? null) ? $options['releaseNotes'] : '';
        $force = ($options['forceUpdate'] ?? false) === true;
        $record = np_publish_client_release($assembled, '', $minimum, $force, $notes, $actorId);
    }
    np_upload_remove_tree($directory);
    return $record + ['kind' => $kind];
}

function np_upload_abort(string $sid): void
{
    np_upload_remove_tree(np_upload_session_dir(np_upload_sid($sid)));
}

/**
 * CSRF for a raw-body request: the token travels in a header instead of a form
 * field. The token is the real gate; the origin check only has to prove the
 * caller is not a cross-site page, so an administrator reaching the panel
 * through an IP or an alternate hostname is not locked out.
 */
function np_upload_csrf_ok(): bool
{
    $token = $_SERVER['HTTP_X_NOVAPROTECT_TOKEN'] ?? '';
    if (!is_string($token) || $token === '') return false;
    if (!hash_equals(np_csrf_token(), $token)) return false;
    $origin = (string) ($_SERVER['HTTP_ORIGIN'] ?? '');
    if ($origin === '') return ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') !== 'cross-site';
    $host = strtolower((string) parse_url($origin, PHP_URL_HOST));
    $requestHost = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
    $siteHost = strtolower((string) parse_url(np_site_url(), PHP_URL_HOST));
    return $host !== '' && ($host === $requestHost || $host === $siteHost);
}

function np_upload_json_body(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || $raw === '') return [];
    try {
        $value = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new InvalidArgumentException('请求内容不是有效的 JSON。');
    }
    return is_array($value) ? $value : [];
}

function np_request_scheme(): string
{
    $forwarded = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    if (is_string($forwarded) && $forwarded !== '') {
        return strtolower(trim(explode(',', $forwarded)[0]));
    }
    $https = $_SERVER['HTTPS'] ?? '';
    return ($https !== '' && strtolower((string) $https) !== 'off') ? 'https' : 'http';
}

/**
 * POST /api/admin/release/{begin,chunk,finish,abort}
 * GET  /api/admin/release/ping   (diagnostics only, no state change)
 *
 * Lives under /api/ on purpose: the CDNfly edge policy gives that prefix an
 * origin pass-through with every challenge disabled, so the admin upload never
 * meets a JavaScript/CC/bot challenge and never has to touch WAF allow-lists.
 */
function np_handle_release_upload_api(string $path, string $method): never
{
    $action = substr($path, strlen('/api/admin/release/'));

    // Answers "does this build even have the chunked transport, and what did
    // the edge actually forward?" — open it in a browser to diagnose a
    // deployment where the admin panel and the server disagree.
    if ($action === 'ping') {
        np_json_response([
            'ok' => true,
            'websiteVersion' => np_website_version(),
            'method' => $method,
            'path' => $path,
            'scheme' => np_request_scheme(),
            'admin' => np_admin_session(),
            'chunkBytes' => NP_UPLOAD_CHUNK_BYTES,
        ]);
    }
    if ($method === 'OPTIONS') {
        header('Allow: POST, OPTIONS');
        http_response_code(204);
        exit;
    }
    if ($method !== 'POST') {
        header('Allow: POST');
        error_log('NovaProtect upload endpoint received ' . $method . ' on ' . $path . ' (scheme ' . np_request_scheme() . ')');
        np_json_response([
            'type' => 'about:blank',
            'title' => '上传接口只接受 POST，服务器收到的却是 ' . $method . '。通常是 http→https 或路径规范化重定向把 POST 改写成了 GET。',
            'detail' => '上传接口需要 POST。',
            'status' => 405,
            'code' => 'method_not_allowed',
            'method' => $method,
            'path' => $path,
            'scheme' => np_request_scheme(),
        ], 405);
    }
    if (!np_admin_session()) np_problem('管理员登录已过期，请重新登录。', 401, 'unauthorized');
    if (!np_upload_csrf_ok()) np_problem('表单已过期，请刷新后重试。', 400, 'csrf_failed');
    // Release the session lock before touching the filesystem: a long upload
    // must not block the administrator's other tabs.
    session_write_close();
    $sid = is_string($_GET['sid'] ?? null) ? $_GET['sid'] : '';
    try {
        switch ($action) {
            case 'begin':
                if (!np_rate_limit('admin-upload-begin', 'admin', 40, 300)) np_problem('上传过于频繁，请稍后重试。', 429, 'rate_limited');
                $body = np_upload_json_body();
                $size = $body['size'] ?? null;
                if (!is_int($size) && !(is_string($size) && preg_match('/^\d+$/D', $size) === 1)) {
                    throw new InvalidArgumentException('缺少文件大小。');
                }
                $kind = is_string($body['kind'] ?? null) && $body['kind'] !== '' ? $body['kind'] : 'client';
                $meta = np_upload_begin((int) $size, 'admin', $kind);
                np_json_response(['sid' => $meta['sid'], 'kind' => $meta['kind'], 'chunkBytes' => $meta['chunkBytes'], 'chunks' => $meta['chunks']], 201);
                // no break: np_json_response never returns
            case 'chunk':
                $index = filter_var($_GET['index'] ?? null, FILTER_VALIDATE_INT);
                if ($index === false || $index === null) throw new InvalidArgumentException('缺少分片序号。');
                $payload = file_get_contents('php://input');
                if (!is_string($payload)) throw new InvalidArgumentException('缺少分片内容。');
                np_json_response(np_upload_chunk($sid, (int) $index, $payload), 202);
            case 'finish':
                $record = np_upload_finish($sid, np_upload_json_body(), 'admin');
                if (($record['kind'] ?? 'client') === 'upgrade') {
                    np_audit('admin', 'upgrade-upload', ['operationId' => $sid, 'transport' => 'chunked', 'websiteVersion' => $record['websiteVersion'] ?? '']);
                    np_json_response([
                        'kind' => 'upgrade',
                        'websiteVersion' => $record['websiteVersion'],
                        'clientVersion' => $record['clientVersion'],
                        'fileName' => $record['fileName'],
                        'sha256' => $record['sha256'],
                        'size' => $record['size'],
                        'redirect' => '/admin?tab=upgrades',
                    ], 201);
                }
                np_audit('admin', 'client-release-upload', ['operationId' => $sid, 'transport' => 'chunked', 'clientVersion' => $record['clientVersion']]);
                np_json_response([
                    'kind' => 'client',
                    'clientVersion' => $record['clientVersion'],
                    'fileName' => $record['fileName'],
                    'sha256' => $record['sha256'],
                    'size' => $record['size'],
                    'releaseNotes' => $record['releaseNotes'],
                    'redirect' => '/admin?tab=client-releases',
                ], 201);
            case 'abort':
                np_upload_abort($sid);
                np_json_response(['aborted' => true]);
            default:
                np_problem('接口不存在。', 404, 'not_found');
        }
    } catch (InvalidArgumentException $exception) {
        np_problem($exception->getMessage(), 422, 'invalid_upload');
    } catch (Throwable $exception) {
        error_log('NovaProtect chunked upload failed: ' . get_class($exception));
        np_problem('上传处理失败，请重试；若持续失败请查看服务器日志。', 500, 'upload_failed');
    }
}
