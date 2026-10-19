<?php
declare(strict_types=1);

/**
 * Reset the single administrator password over SSH.
 *
 * The website has no user accounts: one administrator password in
 * data/admin.json protects the update-upload backend. This tool is the
 * recovery path when that password is lost, so it never asks for the old
 * password - filesystem (SSH) access is the authorization boundary.
 *
 *   php /www/server/novaprotect/bin/reset-admin-password.php
 *   php deploy/reset-admin-password.php --data-dir /www/server/novaprotect/data
 *   php deploy/reset-admin-password.php --generate
 *   php /www/server/novaprotect/bin/reset-admin-password.php --locate
 *
 * install.sh deploys the site to /www/wwwroot/<domain>/releases/<version>
 * and points /www/wwwroot/<domain>/current at it, while state (data, bin,
 * downloads) lives under /www/server/novaprotect - the two trees are
 * separate, so app/ is located through the site root, not the state dir.
 */

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "reset-admin-password is CLI-only\n");
    exit(2);
}

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;

function reset_fail(string $message): never
{
    fwrite(STDERR, 'RESET-FAILED ' . $message . PHP_EOL);
    exit(EXIT_FAILED);
}

function reset_usage(): never
{
    $text = <<<'TEXT'
用法：php reset-admin-password.php [选项]

在 SSH 终端重置 NovaProtect 网站后台的管理员口令。网站只有一个管理员口令，
没有用户账户；忘记口令时用本工具重置，无需知道原口令（SSH 权限即授权边界）。

选项：
  --password=VALUE   直接指定新口令（非交互，10 到 128 字节）
  --stdin            从标准输入读取新口令（第一行）
  --generate[=LEN]   随机生成口令并打印（默认 20 位，最短 12）
  --data-dir=PATH    网站数据目录（默认 /www/server/novaprotect/data，
                     或环境变量 NOVAPROTECT_DATA_DIR）
  --app=PATH         网站 app 目录（含 bootstrap.php；默认按下面的顺序自动探测）
  --locate           只探测并打印 app 目录位置，不重置口令
  --force            网站未完成安装向导也允许重置
  --keep-sessions    保留已登录的后台会话（默认全部失效）
  -h, --help         显示本帮助

app 目录自动探测顺序（先匹配先返回）：
  1. --app 指定值；2. 环境变量 NOVAPROTECT_APP_DIR；
  3. 解压包布局 <包>/app；4. <state>/site-root 记录的站点根下的 current；
  5. <state>/current、/www/wwwroot/nova.fbi.plus/current；
  6. /www/wwwroot/*/current、/www/wwwroot/*/app 等宝塔站点根。
  安装版站点位于 /www/wwwroot/<域名>/current/app（软链接），state 目录
  /www/server/novaprotect 下只有 data/bin/downloads，没有 app。

示例：
  php /www/server/novaprotect/bin/reset-admin-password.php
  php /www/server/novaprotect/bin/reset-admin-password.php --locate
  php /www/server/novaprotect/bin/reset-admin-password.php --app=/www/wwwroot/nova.fbi.plus/current/app
  php deploy/reset-admin-password.php --data-dir /www/server/novaprotect/data
  php deploy/reset-admin-password.php --generate

TEXT;
    fwrite(STDOUT, $text);
    exit(EXIT_USAGE);
}

/** Follow a "current"-style slot (symlink or plain dir) to the release holding app/. */
function app_dir_from_slot(string $slot): ?string
{
    $target = realpath($slot);
    if ($target === false || !is_dir($target)) {
        return null;
    }
    foreach ([$target . '/app', $target] as $dir) {
        if (is_file($dir . '/bootstrap.php')) {
            // Forward slashes everywhere: PHP accepts them on Windows too, and
            // the printed path stays identical across platforms.
            return str_replace('\\', '/', rtrim($dir, '/\\'));
        }
    }
    return null;
}

/** Resolve the website app directory (the one holding bootstrap.php). */
function resolve_app_dir(?string $explicit): string
{
    $candidates = [];
    if ($explicit !== null && $explicit !== '') {
        $candidates[] = $explicit;
    }
    $fromEnv = getenv('NOVAPROTECT_APP_DIR');
    if (is_string($fromEnv) && $fromEnv !== '') {
        $candidates[] = $fromEnv;
    }
    // Extracted package layout: <package>/deploy/reset-admin-password.php
    $candidates[] = dirname(__DIR__) . '/app';
    // Installed layout: <state>/bin/reset-admin-password.php. install.sh
    // records the site root in <state>/site-root; the site itself lives in
    // <site-root>/releases/<version> with <site-root>/current pointing at it.
    $stateDir = dirname(__DIR__);
    $siteRootFile = $stateDir . '/site-root';
    if (is_file($siteRootFile)) {
        $siteRoot = rtrim(trim((string) file_get_contents($siteRootFile)), "/\\\r\n \t");
        if ($siteRoot !== '') {
            $candidates[] = $siteRoot . '/current';
        }
    }
    // Site root next to the state directory, and the documented default.
    $candidates[] = $stateDir . '/current';
    $candidates[] = '/www/wwwroot/nova.fbi.plus/current';
    // Any other BaoTa site root that follows the same releases/current shape.
    foreach (glob('/www/wwwroot/*/current') ?: [] as $slot) {
        $candidates[] = $slot;
    }
    // Legacy direct layouts.
    $candidates[] = $stateDir . '/current/app';
    $candidates[] = $stateDir . '/app';
    $candidates[] = '/www/server/novaprotect/current/app';
    foreach (glob('/www/wwwroot/*/app') ?: [] as $dir) {
        $candidates[] = $dir;
    }

    $tried = [];
    foreach ($candidates as $candidate) {
        $normalized = rtrim($candidate, '/\\');
        if ($normalized === '') {
            continue;
        }
        $tried[] = $normalized;
        if (is_file($normalized . '/bootstrap.php')) {
            return str_replace('\\', '/', $normalized);
        }
        $fromSlot = app_dir_from_slot($normalized);
        if ($fromSlot !== null) {
            return $fromSlot;
        }
    }

    $tried = array_values(array_unique($tried));
    $listing = implode("\n  ", array_map(
        static fn(string $path): string => str_replace('\\', '/', $path) . '/bootstrap.php',
        $tried
    ));
    reset_fail(
        "找不到网站 app 目录（bootstrap.php）。已尝试：\n  $listing\n"
        . "install.sh 安装的站点在 /www/wwwroot/<域名>/current/app（current 是指向 releases/<版本> 的软链接）。\n"
        . "可用以下命令查找真实位置：\n"
        . "  ls -la /www/wwwroot/*/current\n"
        . "  find /www/wwwroot -maxdepth 3 -name bootstrap.php 2>/dev/null\n"
        . "找到后用 --app 指定，例如：\n"
        . "  php /www/server/novaprotect/bin/reset-admin-password.php --app=/www/wwwroot/nova.fbi.plus/current/app"
    );
}

/** Resolve the shared data directory that holds admin.json. */
function resolve_data_dir(?string $explicit): string
{
    if ($explicit !== null && $explicit !== '') {
        return rtrim($explicit, '/\\');
    }
    $fromEnv = getenv('NOVAPROTECT_DATA_DIR');
    if (is_string($fromEnv) && $fromEnv !== '') {
        return rtrim($fromEnv, '/\\');
    }
    return '/www/server/novaprotect/data';
}

function read_hidden(string $prompt): string
{
    fwrite(STDOUT, $prompt);
    $restore = null;
    if (function_exists('stream_isatty') && stream_isatty(STDIN)) {
        $saved = trim((string) shell_exec('stty -g 2>/dev/null'));
        if ($saved !== '') {
            shell_exec('stty -echo 2>/dev/null');
            $restore = $saved;
        }
    } else {
        fwrite(STDOUT, "（非终端输入，内容将可见）\n");
    }

    try {
        $line = fgets(STDIN);
    } finally {
        if ($restore !== null) {
            shell_exec('stty ' . escapeshellarg($restore) . ' 2>/dev/null');
        }
        fwrite(STDOUT, PHP_EOL);
    }

    if ($line === false) {
        reset_fail('没有读到输入（EOF）。');
    }
    return rtrim($line, "\r\n");
}

function generate_password(int $length): string
{
    // No visually ambiguous characters: 0/O, 1/l/I are excluded.
    $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+';
    $alphabetLength = strlen($alphabet);
    $boundary = 256 - (256 % $alphabetLength);
    $password = '';
    while (strlen($password) < $length) {
        $bytes = random_bytes($length - strlen($password) + 16);
        for ($i = 0; $i < strlen($bytes); $i++) {
            $value = ord($bytes[$i]);
            if ($value >= $boundary) {
                continue;
            }
            $password .= $alphabet[$value % $alphabetLength];
            if (strlen($password) === $length) {
                break;
            }
        }
    }
    return $password;
}

/** Keep admin.json owned like the data directory so PHP-FPM can still read it. */
function repair_owner(string $path, string $reference): bool
{
    if (!is_file($path)) {
        return true;
    }
    $uid = @fileowner($reference);
    $gid = @filegroup($reference);
    if ($uid === false || $gid === false) {
        return true;
    }
    if (@fileowner($path) === $uid && @filegroup($path) === $gid) {
        return true;
    }
    $ok = @chown($path, $uid);
    $ok = @chgrp($path, $gid) && $ok;
    @chmod($path, 0600);
    return $ok;
}

function drop_admin_login_limits(string $dataDir): int
{
    $path = $dataDir . '/limits.json';
    if (!is_file($path)) {
        return 0;
    }
    try {
        return np_transaction('limits', static function (string $locked): int {
            $rows = np_read_json($locked);
            $kept = [];
            $dropped = 0;
            foreach ($rows as $id => $row) {
                if (is_array($row) && ($row['scope'] ?? '') === 'admin-login-ip') {
                    $dropped++;
                    continue;
                }
                $kept[$id] = $row;
            }
            if ($dropped > 0) {
                np_atomic_write($locked, $kept);
            }
            return $dropped;
        });
    } catch (Throwable $exception) {
        fwrite(STDERR, '警告：无法清除登录限速记录（' . $exception->getMessage() . "），可稍后手动删除 $path\n");
        return 0;
    }
}

function invalidate_sessions(string $dataDir): int
{
    $directory = $dataDir . '/sessions';
    if (!is_dir($directory)) {
        return 0;
    }
    $removed = 0;
    foreach (scandir($directory) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..' || !str_starts_with($entry, 'sess_')) {
            continue;
        }
        $path = $directory . '/' . $entry;
        if (is_file($path) && @unlink($path)) {
            $removed++;
        }
    }
    return $removed;
}

// ---------------------------------------------------------------- arguments
$password = null;
$fromStdin = false;
$generateLength = null;
$dataDirOption = null;
$appOption = null;
$force = false;
$keepSessions = false;
$locateOnly = false;

$arguments = array_slice($_SERVER['argv'] ?? [], 1);

/** Value of "--flag value" or "--flag=value"; fails when the value is missing. */
function option_value(array $arguments, int $index, string $flag): string
{
    $prefix = $flag . '=';
    if (str_starts_with($arguments[$index], $prefix)) {
        return substr($arguments[$index], strlen($prefix));
    }
    $next = $arguments[$index + 1] ?? null;
    if (!is_string($next) || $next === '' || str_starts_with($next, '--')) {
        reset_fail("选项 $flag 缺少取值。");
    }
    return $next;
}

for ($i = 0; $i < count($arguments); $i++) {
    $argument = $arguments[$i];
    $consumesValue = false;
    if ($argument === '-h' || $argument === '--help') {
        reset_usage();
    } elseif ($argument === '--force') {
        $force = true;
    } elseif ($argument === '--keep-sessions') {
        $keepSessions = true;
    } elseif ($argument === '--locate') {
        $locateOnly = true;
    } elseif ($argument === '--stdin') {
        $fromStdin = true;
    } elseif ($argument === '--generate') {
        $generateLength = 20;
    } elseif (str_starts_with($argument, '--generate=')) {
        $generateLength = (int) substr($argument, strlen('--generate='));
        if ($generateLength < 12 || $generateLength > 128) {
            reset_fail('--generate 长度需在 12 到 128 之间。');
        }
    } elseif ($argument === '--password' || str_starts_with($argument, '--password=')) {
        $password = option_value($arguments, $i, '--password');
        $consumesValue = !str_starts_with($argument, '--password=');
    } elseif ($argument === '--data-dir' || str_starts_with($argument, '--data-dir=')) {
        $dataDirOption = option_value($arguments, $i, '--data-dir');
        $consumesValue = !str_starts_with($argument, '--data-dir=');
    } elseif ($argument === '--app' || str_starts_with($argument, '--app=')) {
        $appOption = option_value($arguments, $i, '--app');
        $consumesValue = !str_starts_with($argument, '--app=');
    } else {
        reset_fail("未知参数：{$argument}（--help 查看用法）");
    }
    if ($consumesValue) {
        $i++;
    }
}

$modes = ($password !== null ? 1 : 0) + ($fromStdin ? 1 : 0) + ($generateLength !== null ? 1 : 0);
if ($modes > 1) {
    reset_fail('--password、--stdin、--generate 只能任选其一。');
}

// ------------------------------------------------------------ resolve paths
$appDir = resolve_app_dir($appOption);

if ($locateOnly) {
    fwrite(STDOUT, "APP-DIR $appDir\n");
    exit(EXIT_OK);
}

$dataDir = resolve_data_dir($dataDirOption);

// np_data_dir() reads $_SERVER first, so pin the resolved directory before
// the bootstrap loads and every helper agrees on the same location.
$_SERVER['NOVAPROTECT_DATA_DIR'] = $dataDir;
putenv('NOVAPROTECT_DATA_DIR=' . $dataDir);

require $appDir . '/bootstrap.php';

if (!is_dir($dataDir)) {
    reset_fail("数据目录不存在：{$dataDir}（可用 --data-dir 指定网站数据目录）");
}
if (!is_writable($dataDir)) {
    reset_fail("数据目录不可写：{$dataDir}（请用 root 执行，或修复属主后重试）");
}
if (!$force && !np_installed()) {
    reset_fail('网站尚未完成安装向导（installation.json 缺失）。请先在浏览器完成安装，或加 --force 强制重置。');
}

// ----------------------------------------------------------- obtain password
if ($generateLength !== null) {
    $newPassword = generate_password($generateLength);
    fwrite(STDOUT, "生成的新口令：$newPassword\n");
} elseif ($password !== null) {
    $newPassword = $password;
} elseif ($fromStdin) {
    $line = fgets(STDIN);
    if ($line === false) {
        reset_fail('标准输入为空。');
    }
    $newPassword = rtrim($line, "\r\n");
} else {
    fwrite(STDOUT, "重置 NovaProtect 网站后台管理员口令\n数据目录：$dataDir\n");
    $first = read_hidden('新的管理员口令（10 到 128 字节）：');
    $second = read_hidden('再输入一次确认：');
    if ($first !== $second) {
        reset_fail('两次输入不一致，未做任何修改。');
    }
    $newPassword = $first;
}

$passwordLength = strlen($newPassword);
if ($passwordLength < 10 || $passwordLength > 128) {
    reset_fail("新口令长度需为 10 到 128 字节（当前 {$passwordLength}）。");
}

// ------------------------------------------------------------------- reset
try {
    np_set_admin_password($newPassword);
} catch (Throwable $exception) {
    reset_fail('写入口令失败：' . $exception->getMessage() . "（$dataDir/admin.json）");
}

$adminPath = $dataDir . '/admin.json';
if (!repair_owner($adminPath, $dataDir)) {
    fwrite(STDERR, "警告：无法将 $adminPath 的属主对齐数据目录，PHP-FPM 可能读不到新口令；请执行 chown www:www $adminPath\n");
}

// Self-check: the new password must verify through the shared reader.
$storedHash = np_admin_password_hash();
if ($storedHash === null || !np_verify_password($newPassword, $storedHash)) {
    reset_fail("重置后自检失败，新口令未生效：$adminPath");
}

$sessions = $keepSessions ? 0 : invalidate_sessions($dataDir);
$limits = drop_admin_login_limits($dataDir);

fwrite(STDOUT, "RESET-OK 管理员口令已重置\n");
fwrite(STDOUT, "数据目录：$dataDir\n");
fwrite(STDOUT, "口令文件：$adminPath\n");
fwrite(STDOUT, $keepSessions ? "后台会话：按要求保留\n" : "已失效后台会话：$sessions 个\n");
if ($limits > 0) {
    fwrite(STDOUT, "已清除登录限速记录：$limits 条\n");
}
fwrite(STDOUT, '现在可用新口令登录：' . np_site_url() . "/admin/login\n");
exit(EXIT_OK);
