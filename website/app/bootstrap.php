<?php
declare(strict_types=1);

const NP_ROOT = __DIR__ . '/..';
const NP_SESSION_TTL = 1209600; // 14 days absolute; idle expiry is shorter.

function np_env(string $key, string $default): string
{
    $value = $_SERVER[$key] ?? getenv($key);
    return is_string($value) && $value !== '' ? $value : $default;
}

function np_development(): bool
{
    return np_env('NOVAPROTECT_DEV', '0') === '1';
}

function np_data_dir(): string
{
    // Keep the production default compatible with the previous deployment.
    return np_env('NOVAPROTECT_DATA_DIR', '/www/server/novaprotect/data');
}

function np_release_dir(): string
{
    return np_env('NOVAPROTECT_RELEASE_DIR', '/www/server/novaprotect/downloads');
}

function np_site_url(): string
{
    return np_env('NOVAPROTECT_SITE_URL', np_development() ? 'http://127.0.0.1:5081' : 'https://nova.fbi.plus');
}

function np_read_json(string $path, array $default = []): array
{
    if (!is_file($path)) {
        return $default;
    }

    $size = filesize($path);
    if ($size === false || $size > 16777216) {
        throw new RuntimeException('Data size limit');
    }

    $raw = file_get_contents($path);
    if ($raw === false || trim($raw) === '') {
        return $default;
    }

    $value = json_decode($raw, true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($value)) {
        throw new RuntimeException('Invalid data shape');
    }

    return $value;
}

function np_atomic_write(string $path, array $value): void
{
    $directory = dirname($path);
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Unable to create data directory');
    }

    $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
    $encoded = json_encode(
        $value,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR
    ) . "\n";

    try {
        if (file_put_contents($temporary, $encoded, LOCK_EX) !== strlen($encoded)) {
            throw new RuntimeException('Write failed');
        }
        chmod($temporary, 0600);
        if (!rename($temporary, $path)) {
            throw new RuntimeException('Commit failed');
        }
    } finally {
        if (is_file($temporary)) {
            unlink($temporary);
        }
    }
}

/** Serialize a JSON-file mutation with a stable sidecar lock. */
function np_transaction(string $name, callable $operation): mixed
{
    $directory = np_data_dir();
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Data directory unavailable');
    }
    if (!is_writable($directory)) {
        throw new RuntimeException('Data directory is not writable');
    }

    $lock = fopen($directory . '/' . $name . '.lock', 'c');
    if ($lock === false) {
        throw new RuntimeException('Lock unavailable');
    }

    try {
        if (!flock($lock, LOCK_EX)) {
            throw new RuntimeException('Lock failed');
        }
        return $operation($directory . '/' . $name . '.json');
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function np_website_version(): string
{
    $version = np_read_json(__DIR__ . '/version.json')['websiteVersion'] ?? '0.0.0';
    return is_string($version) && preg_match('/^\d+\.\d+\.\d+$/D', $version) ? $version : '0.0.0';
}

function np_client_release(): array
{
    $fallback = np_read_json(NP_ROOT . '/release.json');
    $runtimePath = np_data_dir() . '/client_release.json';
    if (!is_file($runtimePath)) {
        return $fallback;
    }

    try {
        $runtime = np_read_json($runtimePath);
        return array_merge($fallback, $runtime);
    } catch (Throwable $exception) {
        // A damaged runtime override must never make the whole site return a
        // PHP fatal. Keep the package release as a safe, read-only fallback and
        // leave an operator-visible log entry for repair.
        error_log('NovaProtect client release override ignored: ' . get_class($exception));
        return $fallback;
    }
}

function np_client_release_history(): array
{
    $rows = [];
    $path = np_data_dir() . '/client_releases.json';
    if (is_file($path)) {
        try {
            $saved = np_read_json($path);
            foreach ($saved as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $version = $row['clientVersion'] ?? null;
                $fileName = $row['fileName'] ?? null;
                if (!is_string($version) || !preg_match('/^\d+\.\d+\.\d+$/D', $version) ||
                    !is_string($fileName) || !preg_match('/^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$/D', $fileName)) {
                    continue;
                }
                $rows[] = [
                    'clientVersion' => $version,
                    'websiteVersion' => is_string($row['websiteVersion'] ?? null) ? $row['websiteVersion'] : np_website_version(),
                    'fileName' => $fileName,
                    'size' => max(0, (int) ($row['size'] ?? 0)),
                    'sha256' => strtolower((string) ($row['sha256'] ?? '')),
                    'minimumClientVersion' => is_string($row['minimumClientVersion'] ?? null) ? $row['minimumClientVersion'] : $version,
                    'forceUpdate' => ($row['forceUpdate'] ?? false) === true,
                    'releaseNotes' => is_string($row['releaseNotes'] ?? null) ? $row['releaseNotes'] : '',
                    'publishedAt' => is_string($row['publishedAt'] ?? null) ? $row['publishedAt'] : null,
                ];
            }
        } catch (Throwable $exception) {
            error_log('NovaProtect client release history ignored: ' . get_class($exception));
        }
    }

    $appendRelease = static function (array $release) use (&$rows): void {
        $clientVersion = $release['clientVersion'] ?? null;
        $fileName = $release['fileName'] ?? null;
        if (!is_string($clientVersion) || !preg_match('/^\d+\.\d+\.\d+$/D', $clientVersion) ||
            !is_string($fileName) || !preg_match('/^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$/D', $fileName)) {
            return;
        }
        $candidate = [
            'clientVersion' => $clientVersion,
            'websiteVersion' => is_string($release['websiteVersion'] ?? null) ? $release['websiteVersion'] : np_website_version(),
            'fileName' => $fileName,
            'size' => max(0, (int) ($release['size'] ?? 0)),
            'sha256' => strtolower((string) ($release['sha256'] ?? '')),
            'minimumClientVersion' => is_string($release['minimumClientVersion'] ?? null) ? $release['minimumClientVersion'] : $clientVersion,
            'forceUpdate' => ($release['forceUpdate'] ?? false) === true,
            'releaseNotes' => is_string($release['releaseNotes'] ?? null) ? $release['releaseNotes'] : '',
            'publishedAt' => is_string($release['publishedAt'] ?? null) ? $release['publishedAt'] : null,
        ];
        $exists = array_filter($rows, static fn(array $row): bool =>
            (string) ($row['clientVersion'] ?? '') === $candidate['clientVersion'] &&
            strtolower((string) ($row['sha256'] ?? '')) === $candidate['sha256']);
        if (!$exists) $rows[] = $candidate;
    };

    // Keep the package release visible even after a newer runtime release is published.
    $appendRelease(np_read_json(NP_ROOT . '/release.json'));
    $appendRelease(np_client_release());

    usort($rows, static fn(array $left, array $right): int =>
        version_compare((string) $right['clientVersion'], (string) $left['clientVersion']) ?: strcmp((string) ($right['publishedAt'] ?? ''), (string) ($left['publishedAt'] ?? '')));
    return $rows;
}

function np_uuid(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
}

function np_installed(): bool
{
    return (np_read_json(np_data_dir() . '/installation.json')['installed'] ?? false) === true;
}

function np_hash_password(string $password): string
{
    if (defined('PASSWORD_ARGON2ID')) {
        $hash = password_hash($password, PASSWORD_ARGON2ID);
        if (is_string($hash)) {
            return $hash;
        }
    }

    // Portable fallback for BaoTa PHP builds without Argon2. Never use a fast hash alone.
    $salt = random_bytes(16);
    return 'v1$600000$' . base64_encode($salt) . '$' . base64_encode(hash_pbkdf2('sha256', $password, $salt, 600000, 32, true));
}

function np_verify_password(string $password, string $encoded): bool
{
    if (strlen($encoded) > 1024 || strlen($password) > 128) {
        return false;
    }
    if (str_starts_with($encoded, '$')) {
        return password_verify($password, $encoded);
    }

    if (str_starts_with($encoded, 'v1$')) {
        $parts = explode('$', $encoded);
        if (count($parts) !== 4 || !ctype_digit($parts[1])) {
            return false;
        }
        $iterations = (int) $parts[1];
        $salt = base64_decode($parts[2], true);
        $key = base64_decode($parts[3], true);
        $algorithm = 'sha256';
    } else {
        return false;
    }

    if (!is_string($salt) || !is_string($key) || $algorithm === '' ||
        $iterations < 1 || $iterations > 1000000 || strlen($salt) < 16 || strlen($salt) > 128 ||
        strlen($key) < 16 || strlen($key) > 128) {
        return false;
    }

    return hash_equals($key, hash_pbkdf2($algorithm, $password, $salt, $iterations, strlen($key), true));
}

/**
 * The website no longer has user accounts. A single administrator password in
 * data/admin.json protects the update-upload backend.
 */
function np_admin_password_hash(): ?string
{
    $admin = np_read_json(np_data_dir() . '/admin.json');
    $hash = $admin['passwordHash'] ?? null;
    return is_string($hash) && $hash !== '' ? $hash : null;
}

function np_admin_password_exists(): bool
{
    return np_admin_password_hash() !== null;
}

function np_set_admin_password(string $password): void
{
    if (strlen($password) < 10 || strlen($password) > 128) {
        throw new InvalidArgumentException('管理员口令需要 10 到 128 字节。');
    }
    np_transaction('admin', static function (string $path) use ($password): void {
        $existing = np_read_json($path);
        np_atomic_write($path, [
            'passwordHash' => np_hash_password($password),
            'createdAt' => is_string($existing['createdAt'] ?? null) ? $existing['createdAt'] : gmdate('c'),
            'updatedAt' => gmdate('c'),
        ]);
    });
}

function np_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $directory = np_data_dir();
    if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
        throw new RuntimeException('Data directory unavailable');
    }
    $sessions = $directory . '/sessions';
    if (!is_dir($sessions) && !mkdir($sessions, 0700, true) && !is_dir($sessions)) {
        throw new RuntimeException('Session directory unavailable');
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string) NP_SESSION_TTL);
    session_name('novaprotect_sid');
    session_save_path($sessions);
    session_set_cookie_params([
        'lifetime' => NP_SESSION_TTL,
        'path' => '/',
        'secure' => !np_development(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    if (!session_start()) {
        throw new RuntimeException('Session unavailable');
    }

    $now = time();
    if (isset($_SESSION['np_admin']) &&
        ($now - (int) ($_SESSION['issued'] ?? 0) > NP_SESSION_TTL ||
         $now - (int) ($_SESSION['last_seen'] ?? 0) > 86400)) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    if (isset($_SESSION['np_admin'])) {
        $_SESSION['last_seen'] = $now;
    }
}

function np_admin_session(): bool
{
    np_start_session();
    return ($_SESSION['np_admin'] ?? false) === true;
}

function np_admin_sign_in(): void
{
    np_start_session();
    session_regenerate_id(true);
    $_SESSION = ['np_admin' => true, 'issued' => time(), 'last_seen' => time()];
}

function np_admin_sign_out(): void
{
    np_start_session();
    $_SESSION = [];
    session_destroy();
    setcookie('novaprotect_sid', '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => !np_development(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function np_csrf_token(): string
{
    np_start_session();
    if (!isset($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function np_same_origin(): bool
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '') !== 'cross-site';
    }
    return strcasecmp(rtrim($origin, '/'), rtrim(np_site_url(), '/')) === 0;
}

function np_check_csrf(): bool
{
    np_start_session();
    $token = $_POST['csrf'] ?? null;
    return np_same_origin() && is_string($token) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $token);
}

function np_rate_limit(string $scope, string $key, int $limit, int $window): bool
{
    return np_transaction('limits', static function (string $path) use ($scope, $key, $limit, $window): bool {
        $rows = np_read_json($path);
        $now = time();
        $active = [];
        foreach ($rows as $id => $row) {
            if (is_array($row) && (int) ($row['until'] ?? 0) > $now) {
                $active[$id] = $row;
            }
        }
        $id = hash('sha256', $scope . ':' . $key);
        // scope is stored so the SSH password-reset tool can clear admin-login
        // throttles precisely; records written before this field existed are
        // simply never matched by that filter.
        $record = $active[$id] ?? ['scope' => $scope, 'until' => $now + $window, 'count' => 0];
        $record['count'] = (int) ($record['count'] ?? 0) + 1;
        $record['scope'] = $scope;
        $active[$id] = $record;
        np_atomic_write($path, $active);
        return $record['count'] <= $limit;
    });
}

function np_admin_login_allowed(): bool
{
    $ip = is_string($_SERVER['REMOTE_ADDR'] ?? null) ? $_SERVER['REMOTE_ADDR'] : 'local';
    return np_rate_limit('admin-login-ip', $ip, 10, 300);
}

require_once __DIR__ . '/features.php';

/** Detect PHP-FPM's post_max_size rejection, which empties both form arrays. */
function np_request_exceeds_post_max_size(): bool
{
    $contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));
    if (!str_starts_with($contentType, 'multipart/form-data') || $_POST !== [] || $_FILES !== []) return false;
    $contentLength = filter_var($_SERVER['CONTENT_LENGTH'] ?? null, FILTER_VALIDATE_INT);
    $limit = np_ini_size_bytes((string) ini_get('post_max_size'));
    return $contentLength !== false && $contentLength > 0 && $limit > 0 && $contentLength > $limit;
}

function np_set_common_headers(): void
{
    header('Cache-Control: no-store, private, max-age=0, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('CDN-Cache-Control: no-store');
    header('Surrogate-Control: no-store');
    header('Vary: Cookie');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header("Content-Security-Policy: default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-src 'none'; font-src 'self' data:; worker-src 'self' blob:");
    if (!np_development()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function np_json_response(array $value, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function np_problem(string $message, int $status, string $code = 'request_failed'): never
{
    np_json_response(['type' => 'about:blank', 'title' => $message, 'detail' => $message, 'status' => $status, 'code' => $code], $status);
}

function np_redirect(string $location): never
{
    header('Location: ' . $location, true, 302);
    exit;
}

function np_release_file(bool $verify = false): ?string
{
    $metadata = np_client_release();
    $name = $metadata['fileName'] ?? '';
    $hash = strtolower((string) ($metadata['sha256'] ?? ''));
    if (!is_string($name) || !preg_match('/^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$/D', $name) ||
        !preg_match('/^[a-f0-9]{64}$/D', $hash)) {
        return null;
    }
    $path = np_release_dir() . '/' . $name;
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    if ($verify) {
        $actual = hash_file('sha256', $path);
        if (!is_string($actual) || !hash_equals($hash, strtolower($actual))) {
            return null;
        }
    }
    return $path;
}

function np_setup_token_hash(): ?string
{
    $setup = np_read_json(np_data_dir() . '/setup.json');
    $hash = $setup['tokenHash'] ?? null;
    return is_string($hash) && preg_match('/^[a-f0-9]{64}$/D', strtolower($hash)) ? strtolower($hash) : null;
}

function np_remove_setup_token(): void
{
    $path = np_data_dir() . '/setup.json';
    if (is_file($path)) {
        unlink($path);
    }
}
