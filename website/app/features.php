<?php
declare(strict_types=1);

/** Feature data stays outside releases so a code rollback never rolls back site data. */
function np_text(mixed $value, int $max, string $label, bool $required = true): string
{
    if (!is_string($value) || !preg_match('//u', $value)) throw new InvalidArgumentException($label . '格式无效。');
    $value = trim($value);
    if (strlen($value) > $max || ($required && $value === '')) throw new InvalidArgumentException($label . '不能为空且不能超过 ' . $max . ' 字节。');
    return $value;
}

function np_integer(mixed $value, int $min, int $max, string $label): int
{
    $integer = filter_var($value, FILTER_VALIDATE_INT);
    if ($integer === false || $integer < $min || $integer > $max) throw new InvalidArgumentException($label . '范围应为 ' . $min . ' 到 ' . $max . '。');
    return $integer;
}

function np_migrate(): void
{
    // Schema 2 removed the user account and membership system; only the
    // administrator password, install state and release data remain.
    if (!np_installed() || (np_read_json(np_data_dir() . '/schema.json')['version'] ?? 0) >= 2) return;
    np_transaction('schema', static function (string $path): void {
        if ((np_read_json($path)['version'] ?? 0) >= 2) return;
        np_atomic_write($path, ['version' => 2, 'migratedAt' => gmdate('c'), 'websiteVersion' => np_website_version()]);
    });
}

/**
 * Read a bounded little-endian value from a PE file handle. Uploaded client
 * installers are parsed as data only; they are never executed by PHP.
 */
function np_pe_read(mixed $handle, int $offset, int $length): ?string
{
    if ($offset < 0 || $length < 0 || $length > 16777216 || fseek($handle, $offset, SEEK_SET) !== 0) {
        return null;
    }
    $value = '';
    while (strlen($value) < $length && !feof($handle)) {
        $chunk = fread($handle, $length - strlen($value));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $value .= $chunk;
    }
    return strlen($value) === $length ? $value : null;
}

function np_pe_u16(string $value, int $offset): ?int
{
    if ($offset < 0 || $offset + 2 > strlen($value)) return null;
    $decoded = unpack('vvalue', substr($value, $offset, 2));
    return is_array($decoded) ? (int) ($decoded['value'] ?? 0) : null;
}

function np_pe_u32(string $value, int $offset): ?int
{
    if ($offset < 0 || $offset + 4 > strlen($value)) return null;
    $decoded = unpack('Vvalue', substr($value, $offset, 4));
    return is_array($decoded) ? (int) ($decoded['value'] ?? 0) : null;
}

function np_pe_rva_offset(int $rva, array $sections, int $fileSize): ?int
{
    foreach ($sections as $section) {
        $start = (int) ($section['rva'] ?? 0);
        $span = max((int) ($section['virtualSize'] ?? 0), (int) ($section['rawSize'] ?? 0));
        if ($span < 1 || $rva < $start || $rva >= $start + $span) continue;
        $offset = (int) ($section['rawPointer'] ?? 0) + ($rva - $start);
        if ($offset < 0 || $offset >= $fileSize) return null;
        return $offset;
    }
    return null;
}

function np_pe_resource_data(mixed $handle, int $resourceOffset, array $sections, int $fileSize, int $relative, bool $root = true, int $depth = 0): ?array
{
    if ($depth > 6 || $relative < 0 || $relative > $fileSize - $resourceOffset - 16) return null;
    $directory = np_pe_read($handle, $resourceOffset + $relative, 16);
    if ($directory === null) return null;
    $named = np_pe_u16($directory, 12);
    $ids = np_pe_u16($directory, 14);
    if ($named === null || $ids === null || $named + $ids > 2048) return null;
    $count = $named + $ids;
    for ($index = 0; $index < $count; $index++) {
        $entry = np_pe_read($handle, $resourceOffset + $relative + 16 + ($index * 8), 8);
        if ($entry === null) return null;
        $name = np_pe_u32($entry, 0);
        $child = np_pe_u32($entry, 4);
        if ($name === null || $child === null) return null;
        $id = ($name & 0x80000000) !== 0 ? null : $name;
        if ($root && $id !== 16) continue; // RT_VERSION
        if (($child & 0x80000000) !== 0) {
            $nested = np_pe_resource_data($handle, $resourceOffset, $sections, $fileSize, $child & 0x7fffffff, false, $depth + 1);
            if ($nested !== null) return $nested;
            continue;
        }
        $dataEntry = np_pe_read($handle, $resourceOffset + ($child & 0x7fffffff), 16);
        if ($dataEntry === null) return null;
        $dataRva = np_pe_u32($dataEntry, 0);
        $dataSize = np_pe_u32($dataEntry, 4);
        if ($dataRva === null || $dataSize === null || $dataSize < 1 || $dataSize > 4194304) return null;
        $dataOffset = np_pe_rva_offset($dataRva, $sections, $fileSize);
        if ($dataOffset === null || $dataOffset > $fileSize - $dataSize) return null;
        return ['offset' => $dataOffset, 'size' => $dataSize];
    }
    return null;
}

function np_pe_version_resource_blob(string $path): ?string
{
    $fileSize = filesize($path);
    if ($fileSize === false || $fileSize < 512 || $fileSize > 1073741824) return null;
    $handle = fopen($path, 'rb');
    if ($handle === false) return null;
    try {
        $dos = np_pe_read($handle, 0, 64);
        if ($dos === null || substr($dos, 0, 2) !== 'MZ') return null;
        $peOffset = np_pe_u32($dos, 60);
        if ($peOffset === null || $peOffset < 64 || $peOffset > $fileSize - 256) return null;
        $nt = np_pe_read($handle, $peOffset, 24);
        if ($nt === null || substr($nt, 0, 4) !== "PE\0\0") return null;
        $sectionCount = np_pe_u16($nt, 6);
        $optionalSize = np_pe_u16($nt, 20);
        if ($sectionCount === null || $optionalSize === null || $sectionCount < 1 || $sectionCount > 96 || $optionalSize < 96 || $optionalSize > 4096) return null;
        $optional = np_pe_read($handle, $peOffset + 24, $optionalSize);
        if ($optional === null) return null;
        $magic = np_pe_u16($optional, 0);
        $dataDirectory = $magic === 0x10b ? 96 : ($magic === 0x20b ? 112 : 0);
        if ($dataDirectory < 1) return null;
        $resourceRva = np_pe_u32($optional, $dataDirectory + (8 * 2));
        $resourceSize = np_pe_u32($optional, $dataDirectory + (8 * 2) + 4);
        if ($resourceRva === null || $resourceSize === null || $resourceRva < 1 || $resourceSize < 1) return null;

        $sectionTable = $peOffset + 24 + $optionalSize;
        $sections = [];
        for ($index = 0; $index < $sectionCount; $index++) {
            $section = np_pe_read($handle, $sectionTable + ($index * 40), 40);
            if ($section === null) return null;
            $virtualSize = np_pe_u32($section, 8);
            $rva = np_pe_u32($section, 12);
            $rawSize = np_pe_u32($section, 16);
            $rawPointer = np_pe_u32($section, 20);
            if ($virtualSize === null || $rva === null || $rawSize === null || $rawPointer === null) return null;
            $sections[] = ['virtualSize' => $virtualSize, 'rva' => $rva, 'rawSize' => $rawSize, 'rawPointer' => $rawPointer];
        }
        $resourceOffset = np_pe_rva_offset($resourceRva, $sections, $fileSize);
        if ($resourceOffset === null || $resourceSize > $fileSize - $resourceOffset) return null;
        $resource = np_pe_resource_data($handle, $resourceOffset, $sections, $fileSize, 0);
        if ($resource === null) return null;
        return np_pe_read($handle, $resource['offset'], min((int) $resource['size'], 4194304));
    } finally {
        fclose($handle);
    }
}

/** Validate PE headers and ensure section data does not escape the uploaded file. */
function np_pe_is_executable(string $path): bool
{
    $fileSize = filesize($path);
    if ($fileSize === false || $fileSize < 512 || $fileSize > 1073741824) return false;
    $handle = fopen($path, 'rb');
    if ($handle === false) return false;
    try {
        $dos = np_pe_read($handle, 0, 64);
        if ($dos === null || substr($dos, 0, 2) !== 'MZ') return false;
        $peOffset = np_pe_u32($dos, 60);
        if ($peOffset === null || $peOffset < 64 || $peOffset > $fileSize - 24) return false;
        $nt = np_pe_read($handle, $peOffset, 24);
        if ($nt === null || substr($nt, 0, 4) !== "PE\0\0") return false;
        $sectionCount = np_pe_u16($nt, 6);
        $optionalSize = np_pe_u16($nt, 20);
        if ($sectionCount === null || $optionalSize === null || $sectionCount < 1 || $sectionCount > 96 || $optionalSize < 96 || $optionalSize > 4096) return false;
        $optionalOffset = $peOffset + 24;
        $optional = np_pe_read($handle, $optionalOffset, $optionalSize);
        if ($optional === null || !in_array(np_pe_u16($optional, 0), [0x10b, 0x20b], true)) return false;
        $sectionTable = $optionalOffset + $optionalSize;
        $sectionBytes = $sectionCount * 40;
        if ($sectionTable > $fileSize || $sectionBytes > $fileSize - $sectionTable) return false;
        for ($index = 0; $index < $sectionCount; $index++) {
            $section = np_pe_read($handle, $sectionTable + ($index * 40), 40);
            if ($section === null) return false;
            $rawSize = np_pe_u32($section, 16);
            $rawPointer = np_pe_u32($section, 20);
            if ($rawSize === null || $rawPointer === null || $rawPointer > $fileSize || $rawSize > $fileSize - $rawPointer) return false;
        }
        return true;
    } finally {
        fclose($handle);
    }
}

function np_pe_file_version(string $path): ?string
{
    $blob = np_pe_version_resource_blob($path);
    if ($blob === null) return null;
        $signature = "\xbd\x04\xef\xfe";
        $cursor = 0;
        while (($position = strpos($blob, $signature, $cursor)) !== false) {
            // VS_FIXEDFILEINFO stores each DWORD as high-word/low-word;
            // little-endian PE bytes therefore expose minor, major, revision,
            // build in that order.
            $minor = np_pe_u16($blob, $position + 8);
            $major = np_pe_u16($blob, $position + 10);
            $revision = np_pe_u16($blob, $position + 12);
            $build = np_pe_u16($blob, $position + 14);
            if ($major !== null && $minor !== null && $build !== null && $revision !== null && $major <= 65535 && $minor <= 65535 && $build <= 65535 && $revision <= 65535) {
                return $major . '.' . $minor . '.' . $build;
            }
            $cursor = $position + 4;
        }
        return null;
}

function np_pe_align4(int $value): int
{
    return ($value + 3) & ~3;
}

function np_pe_utf16le(string $value): string
{
    if ($value === '') return '';
    $decoded = function_exists('mb_convert_encoding')
        ? mb_convert_encoding($value, 'UTF-8', 'UTF-16LE')
        : (function_exists('iconv') ? iconv('UTF-16LE', 'UTF-8//IGNORE', $value) : false);
    if (!is_string($decoded)) {
        $decoded = '';
        for ($index = 0; $index + 1 < strlen($value); $index += 2) {
            $code = ord($value[$index]) | (ord($value[$index + 1]) << 8);
            if ($code === 0) break;
            $decoded .= $code < 128 ? chr($code) : '?';
        }
    }
    return trim($decoded, " \t\r\n\0");
}

/** Parse the bounded VS_VERSION_INFO tree and return the first Comments value. */
function np_pe_version_string(string $blob, int $offset, int $end, string $targetKey, int $depth = 0): ?string
{
    if ($depth > 8 || $offset < 0 || $offset + 6 > $end) return null;
    $length = np_pe_u16($blob, $offset);
    $valueLength = np_pe_u16($blob, $offset + 2);
    $type = np_pe_u16($blob, $offset + 4);
    if ($length === null || $valueLength === null || $type === null || $length < 8 || $offset + $length > $end) return null;
    $itemEnd = $offset + $length;
    $keyStart = $offset + 6;
    $keyEnd = $keyStart;
    while ($keyEnd + 1 < $itemEnd && np_pe_u16($blob, $keyEnd) !== 0) $keyEnd += 2;
    if ($keyEnd + 1 >= $itemEnd) return null;
    $key = np_pe_utf16le(substr($blob, $keyStart, $keyEnd - $keyStart));
    $valueOffset = np_pe_align4($keyEnd + 2);
    $valueBytes = $type === 1 ? $valueLength * 2 : $valueLength;
    if ($valueBytes < 0 || $valueOffset > $itemEnd || $valueBytes > $itemEnd - $valueOffset) return null;
    if (strcasecmp($key, $targetKey) === 0 && $type === 1 && $valueBytes > 0) {
        $comments = np_pe_utf16le(substr($blob, $valueOffset, $valueBytes));
        if ($comments !== '') return $comments;
    }
    $childOffset = np_pe_align4($valueOffset + $valueBytes);
    while ($childOffset + 6 <= $itemEnd) {
        $childLength = np_pe_u16($blob, $childOffset);
        if ($childLength === null || $childLength < 8 || $childOffset + $childLength > $itemEnd) break;
        $comments = np_pe_version_string($blob, $childOffset, $itemEnd, $targetKey, $depth + 1);
        if ($comments !== null) return $comments;
        $next = np_pe_align4($childOffset + $childLength);
        if ($next <= $childOffset) break;
        $childOffset = $next;
    }
    return null;
}

function np_pe_file_comments(string $path): ?string
{
    $blob = np_pe_version_resource_blob($path);
    if ($blob === null) return null;
    $comments = np_pe_version_string($blob, 0, strlen($blob), 'Comments');
    if ($comments !== null && !preg_match('/^This installation was built with Inno Setup\\.?$/i', trim($comments))) return $comments;
    $description = np_pe_version_string($blob, 0, strlen($blob), 'FileDescription');
    if ($description === null) return null;
    $description = trim((string) preg_replace('/^NovaProtect Client Installer\\s*-\\s*/i', '', $description));
    return $description !== '' ? $description : null;
}

function np_pe_file_description(string $path): ?string
{
    $blob = np_pe_version_resource_blob($path);
    return $blob === null ? null : np_pe_version_string($blob, 0, strlen($blob), 'FileDescription');
}

function np_ini_size_bytes(string $value): int
{
    $value = trim($value);
    if ($value === '' || $value === '0' || $value === '-1') return 0;
    if (!preg_match('/^(\d+(?:\.\d+)?)\s*([KMG])?B?$/iD', $value, $match)) return 0;
    $multiplier = match (strtoupper($match[2] ?? '')) { 'K' => 1024, 'M' => 1048576, 'G' => 1073741824, default => 1 };
    $bytes = (float) $match[1] * $multiplier;
    return $bytes >= PHP_INT_MAX ? PHP_INT_MAX : (int) $bytes;
}

function np_format_bytes(int $bytes): string
{
    if ($bytes >= 1073741824) return rtrim(rtrim(number_format($bytes / 1073741824, 2, '.', ''), '0'), '.') . ' GB';
    if ($bytes >= 1048576) return rtrim(rtrim(number_format($bytes / 1048576, 2, '.', ''), '0'), '.') . ' MB';
    if ($bytes >= 1024) return rtrim(rtrim(number_format($bytes / 1024, 2, '.', ''), '0'), '.') . ' KB';
    return $bytes . ' B';
}

function np_upload_client_release(array $file, string $minimumVersion, bool $forceUpdate, string $releaseNotes, string $actorId): array
{
    $error = $file['error'] ?? UPLOAD_ERR_NO_FILE;
    if (!is_int($error) || $error !== UPLOAD_ERR_OK) {
        throw new InvalidArgumentException(match ($error) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => '客户端安装包超过 PHP-FPM 的 upload_max_filesize 限制；请部署最新网站包并重试。',
            UPLOAD_ERR_PARTIAL => '客户端安装包上传不完整。',
            UPLOAD_ERR_NO_FILE => '请选择客户端 EXE 安装包。',
            default => '客户端安装包上传失败。',
        });
    }
    $temporary = $file['tmp_name'] ?? '';
    $originalName = is_string($file['name'] ?? null) ? basename(str_replace('\\', '/', $file['name'])) : '';
    if (!is_string($temporary) || !is_uploaded_file($temporary)) throw new InvalidArgumentException('上传临时文件无效。');
    return np_publish_client_release($temporary, $originalName, $minimumVersion, $forceUpdate, $releaseNotes, $actorId, true);
}

/**
 * Validate and publish an installer that already exists on the server.
 *
 * $originalName may be empty: the chunked transport never learns the browser
 * filename, so the canonical name is rebuilt from the PE version resource.
 */
function np_publish_client_release(string $temporary, string $originalName, string $minimumVersion, bool $forceUpdate, string $releaseNotes, string $actorId, bool $fromUpload = false): array
{
    if (!is_file($temporary)) throw new InvalidArgumentException('待发布的安装包不存在。');
    if ($originalName !== '' && !preg_match('/\.exe$/iD', $originalName)) throw new InvalidArgumentException('只支持客户端 EXE 安装包；请选择 .exe 文件。');
    $size = filesize($temporary);
    if ($size === false || $size < 1 || $size > 268435456) throw new InvalidArgumentException('客户端安装包大小必须在 1 字节到 256 MB 之间。');
    if (!np_pe_is_executable($temporary)) throw new InvalidArgumentException('上传文件不是有效的 Windows PE EXE；请上传客户端安装包。');
    $nameVersion = null;
    if ($originalName !== '' && preg_match('/^NovaProtect-Setup-(\d+\.\d+\.\d+)\.exe$/iD', $originalName, $match)) $nameVersion = $match[1];
    $peVersion = np_pe_file_version($temporary);
    if ($peVersion === null) throw new InvalidArgumentException('无法从 EXE 的 PE 版本资源识别客户端版本；请上传正式客户端安装包。');
    if ($nameVersion !== null && $peVersion !== $nameVersion) throw new InvalidArgumentException("文件名版本 {$nameVersion} 与 EXE 版本 {$peVersion} 不一致，请上传同一版本的安装包。");
    $description = np_pe_file_description($temporary);
    $hasNovaDescription = is_string($description) && preg_match('/^NovaProtect Client Installer(?:\s*-|$)/i', trim($description));
    if (!$hasNovaDescription) throw new InvalidArgumentException('该 EXE 不是 NovaProtect 客户端安装包。');
    $fileVersion = $peVersion;
    $targetName = 'NovaProtect-Setup-' . $fileVersion . '.exe';
    $minimumVersion = trim($minimumVersion);
    if (!preg_match('/^\d+\.\d+\.\d+$/D', $minimumVersion) || version_compare($minimumVersion, $fileVersion, '>')) throw new InvalidArgumentException('最低可用版本必须是不高于发布版本的三段版本号。');
    $notes = trim($releaseNotes) === ''
        ? np_auto_client_release_notes($temporary, $fileVersion, (int) $size)
        : np_text($releaseNotes, 12000, '更新说明', false);
    $current = np_client_release();
    $currentVersion = (string) ($current['clientVersion'] ?? '');
    if (!preg_match('/^\d+\.\d+\.\d+$/D', $currentVersion) || version_compare($fileVersion, $currentVersion, '<=')) throw new InvalidArgumentException("待发布版本 {$fileVersion} 必须高于当前官网版本 {$currentVersion}；若这是新构建，请先递增客户端版本号再上传。");

    $directory = np_release_dir();
    if (!is_dir($directory) && !mkdir($directory, 0750, true) && !is_dir($directory)) throw new RuntimeException('客户端发布目录不可用。');
    $target = rtrim($directory, '/\\') . '/' . $targetName;
    if (is_file($target)) throw new InvalidArgumentException('该客户端版本已经上传过。');
    $temporaryTarget = $target . '.' . bin2hex(random_bytes(8)) . '.upload';
    $stored = $fromUpload ? @move_uploaded_file($temporary, $temporaryTarget) : @rename($temporary, $temporaryTarget);
    if (!$stored) {
        if ($fromUpload || !@copy($temporary, $temporaryTarget)) throw new RuntimeException('无法保存客户端安装包。');
        @unlink($temporary);
    }
    try {
        chmod($temporaryTarget, 0640);
        $sha256 = hash_file('sha256', $temporaryTarget);
        if (!is_string($sha256) || !preg_match('/^[a-f0-9]{64}$/D', $sha256)) throw new RuntimeException('无法计算客户端安装包 SHA-256。');
        if (!rename($temporaryTarget, $target)) throw new RuntimeException('无法提交客户端安装包。');
        $record = [
            'clientVersion' => $fileVersion,
            'websiteVersion' => np_website_version(),
            'fileName' => $targetName,
            'size' => (int) $size,
            'sha256' => strtolower($sha256),
            'minimumClientVersion' => $minimumVersion,
            'forceUpdate' => $forceUpdate,
            'releaseNotes' => $notes,
            'publishedAt' => gmdate('c'),
            'uploadedBy' => $actorId,
            'status' => 'published',
        ];
        np_transaction('client_releases', static function (string $path) use ($record): void {
            $rows = np_read_json($path);
            foreach ($rows as $row) if (is_array($row) && ($row['clientVersion'] ?? '') === $record['clientVersion']) throw new InvalidArgumentException('该客户端版本已经存在发布记录。');
            $rows[] = $record;
            np_atomic_write($path, array_slice($rows, -100));
            np_atomic_write(np_data_dir() . '/client_release.json', $record);
        });
        return $record;
    } catch (Throwable $exception) {
        @unlink($temporaryTarget);
        @unlink($target);
        throw $exception;
    }
}

/**
 * Build the changelog entry without asking the administrator to type anything.
 *
 * Priority: an explicit catalog shipped next to the website wins, otherwise the
 * summary embedded in the installer's version resource is expanded into a
 * structured entry. The summary is the same string the build writes into
 * VersionInfoDescription ("NovaProtect Client Installer - <summary>"), so the
 * changelog always matches the binary that was actually uploaded.
 */
function np_auto_client_release_notes(string $installerPath, string $version, int $size): string
{
    $catalogPath = NP_ROOT . '/client-release-notes.json';
    if (is_file($catalogPath)) {
        try {
            $catalog = np_read_json($catalogPath);
            $notes = $catalog[$version] ?? null;
            if (is_string($notes) && trim($notes) !== '') return np_text($notes, 12000, '更新说明', false);
        } catch (Throwable $exception) {
            error_log('NovaProtect release notes catalog ignored: ' . get_class($exception));
        }
    }
    return np_compose_client_release_notes($version, np_pe_file_comments($installerPath), $size);
}

/** Turn the one-line installer summary into a multi-line changelog entry. */
function np_compose_client_release_notes(string $version, ?string $summary, int $size): string
{
    $items = [];
    if (is_string($summary) && trim($summary) !== '') {
        foreach (preg_split('/[；;]+/u', $summary) ?: [] as $item) {
            $item = trim((string) preg_replace('/^[\s\-*·•]+/u', '', $item));
            if ($item !== '') $items[] = $item;
        }
    }
    if (!$items) $items[] = '改进在线更新与后台发布流程';
    $lines = ['NovaProtect 客户端 ' . $version . '（Windows x64 · ' . np_format_bytes($size) . '）'];
    foreach ($items as $item) $lines[] = '- ' . $item;
    return implode("\n", $lines);
}

function np_audit(string $actor, string $action, array $metadata = []): void
{
    np_transaction('audit', static function ($path) use ($actor, $action, $metadata): void {
        $rows = np_read_json($path);
        $rows[] = ['at' => gmdate('c'), 'actorId' => $actor, 'action' => $action, 'metadata' => $metadata];
        np_atomic_write($path, array_slice($rows, -2000));
    });
}

function np_upgrade_store_dir(): string
{
    return rtrim(np_env('NOVAPROTECT_UPDATES_DIR', '/www/server/novaprotect/updates'), "/\\");
}

function np_upgrade_packages(): array
{
    $rows = array_values(array_filter(np_read_json(np_data_dir() . '/upgrade_packages.json'), static fn($row): bool => is_array($row)));
    foreach ($rows as &$row) {
        $row['execution'] = np_upgrade_execution_status($row);
    }
    unset($row);
    usort($rows, static fn(array $left, array $right): int => strcmp((string) ($right['uploadedAt'] ?? ''), (string) ($left['uploadedAt'] ?? '')));
    return $rows;
}

function np_upgrade_execution_status(array $row): array
{
    $staging = is_string($row['stagingPath'] ?? null) ? $row['stagingPath'] : '';
    if ($staging === '' || !is_dir($staging)) return ['status' => 'missing'];
    foreach (['execution.json' => 'result', 'execution-running.json' => 'running', 'execution-request.json' => 'queued'] as $file => $status) {
        $path = $staging . DIRECTORY_SEPARATOR . $file;
        if (!is_file($path)) continue;
        try {
            $value = np_read_json($path);
            return ['status' => $status, 'requestedAt' => $value['requestedAt'] ?? null, 'startedAt' => $value['startedAt'] ?? null, 'completedAt' => $value['completedAt'] ?? null, 'exitCode' => $value['exitCode'] ?? null, 'message' => is_string($value['message'] ?? null) ? $value['message'] : null];
        } catch (Throwable) {
            return ['status' => 'invalid'];
        }
    }
    return ['status' => 'ready'];
}

function np_request_upgrade_execution(string $id, string $actorId): array
{
    if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iD', $id)) {
        throw new InvalidArgumentException('升级包编号无效。');
    }
    $record = null;
    foreach (np_upgrade_packages() as $row) {
        if (($row['id'] ?? '') === $id) { $record = $row; break; }
    }
    if (!is_array($record)) throw new InvalidArgumentException('升级包记录不存在。');
    $staging = (string) ($record['stagingPath'] ?? '');
    $root = realpath(np_upgrade_store_dir());
    $resolved = $staging !== '' ? realpath($staging) : false;
    if ($root === false || $resolved === false || !str_starts_with($resolved, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) || !is_file($resolved . '/upgrade.sh')) {
        throw new InvalidArgumentException('升级包文件已缺失或不在受控目录。');
    }
    $execution = np_upgrade_execution_status($record);
    if (in_array($execution['status'], ['queued', 'running'], true)) throw new InvalidArgumentException('该升级包已经提交执行，请等待结果。');
    if ($execution['status'] === 'result' && (int) ($execution['exitCode'] ?? 1) === 0) throw new InvalidArgumentException('该升级包已经执行完成。');
    np_atomic_write($resolved . '/execution-request.json', ['id' => $id, 'requestedAt' => gmdate('c'), 'requestedBy' => $actorId]);
    np_audit($actorId, 'upgrade-execute-request', ['packageId' => $id, 'websiteVersion' => $record['websiteVersion'] ?? '']);
    return $record;
}

function np_upgrade_remove_tree(string $path): void
{
    if (is_link($path) || is_file($path)) {
        @unlink($path);
        return;
    }
    if (!is_dir($path)) return;
    $items = scandir($path);
    if ($items === false) return;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        np_upgrade_remove_tree($path . DIRECTORY_SEPARATOR . $item);
    }
    @rmdir($path);
}

function np_upgrade_zip_entry_content(\ZipArchive $zip, string $name, int $index, int $limit): string
{
    $stat = $zip->statIndex($index);
    $size = (int) ($stat['size'] ?? 0);
    if ($size < 0 || $size > $limit) throw new InvalidArgumentException('升级包文件过大：' . $name);
    $stream = $zip->getStream($name);
    if ($stream === false) throw new InvalidArgumentException('无法读取升级包文件：' . $name);
    $content = '';
    try {
        while (!feof($stream)) {
            $chunk = fread($stream, min(1048576, $limit + 1 - strlen($content)));
            if ($chunk === false) throw new InvalidArgumentException('读取升级包文件失败：' . $name);
            $content .= $chunk;
            if (strlen($content) > $limit) throw new InvalidArgumentException('升级包文件过大：' . $name);
        }
    } finally {
        fclose($stream);
    }
    return $content;
}

function np_upgrade_zip_entry_hash(\ZipArchive $zip, string $name, int $index): string
{
    $stream = $zip->getStream($name);
    if ($stream === false) throw new InvalidArgumentException('无法读取升级包文件：' . $name);
    $context = hash_init('sha256');
    try {
        while (!feof($stream)) {
            $chunk = fread($stream, 1048576);
            if ($chunk === false) throw new InvalidArgumentException('读取升级包文件失败：' . $name);
            if ($chunk !== '') hash_update($context, $chunk);
        }
    } finally {
        fclose($stream);
    }
    return hash_final($context);
}

function np_upgrade_validate_archive(string $archive, ?string $originalName = null): array
{
    if (!class_exists('ZipArchive')) throw new InvalidArgumentException('服务器缺少 PHP Zip 扩展，无法校验升级包。');
    if (!is_file($archive) || !is_readable($archive)) throw new InvalidArgumentException('升级包临时文件不可读。');
    $size = filesize($archive);
    if ($size === false || $size < 1 || $size > 268435456) throw new InvalidArgumentException('升级包大小必须在 1 字节到 256 MB 之间。');
    // The chunked transport never learns the browser filename; the archive
    // itself is proof enough, because ZipArchive::open rejects anything that is
    // not a readable ZIP.
    if (is_string($originalName) && $originalName !== '' && strtolower(pathinfo($originalName, PATHINFO_EXTENSION)) !== 'zip') throw new InvalidArgumentException('只能上传 ZIP 升级包。');

    $zip = new \ZipArchive();
    if ($zip->open($archive) !== true) throw new InvalidArgumentException('ZIP 文件无法打开或已损坏。');
    try {
        if ($zip->numFiles < 1 || $zip->numFiles > 2000) throw new InvalidArgumentException('升级包文件数量无效。');
        $entries = [];
        $totalSize = 0;
        for ($index = 0; $index < $zip->numFiles; $index++) {
            $name = $zip->getNameIndex($index);
            if (!is_string($name) || $name === '' || str_contains($name, "\0") || str_contains($name, '\\') || str_starts_with($name, '/') || preg_match('~(^|/)\.\.?(/|$)~', $name)) {
                throw new InvalidArgumentException('升级包包含非法路径。');
            }
            if (isset($entries[$name])) throw new InvalidArgumentException('升级包包含重复文件：' . $name);
            $stat = $zip->statIndex($index);
            $entrySize = (int) ($stat['size'] ?? 0);
            if ($entrySize < 0 || $entrySize > 268435456 || $totalSize > 536870912 - $entrySize) throw new InvalidArgumentException('升级包解压体积超过限制。');
            $totalSize += $entrySize;
            $isDirectory = str_ends_with($name, '/');
            if (!$isDirectory && method_exists($zip, 'getExternalAttributesIndex')) {
                $opsys = 0; $attributes = 0;
                if ($zip->getExternalAttributesIndex($index, $opsys, $attributes) && $opsys === 3 && (($attributes >> 16) & 0170000) === 0120000) {
                    throw new InvalidArgumentException('升级包不允许包含符号链接。');
                }
            }
            if (!$isDirectory) $entries[$name] = $index;
        }

        $required = [
            'SHA256SUMS', 'VERSION', 'release.json', 'package.json', 'README.md', 'upgrade.sh',
            'app/bootstrap.php', 'app/features.php', 'app/upload.php', 'app/site.php', 'app/portal.php', 'app/view.php', 'app/version.json', 'public/index.php', 'public/.user.ini',
            'public/css/site.css', 'public/js/upload-progress.js', 'public/assets/novaprotect.png', 'public/favicon.ico',
            'deploy/upgrade.sh', 'deploy/migrate.php', 'deploy/rollback.sh', 'deploy/health-check.sh', 'deploy/upgrade-executor.sh', 'deploy/novaprotect-upgrade-executor.service', 'deploy/novaprotect-upgrade-executor.timer',
            'deploy/cdnfly-edge-policy.json', 'deploy/cdnfly-check.sh', 'deploy/CDNFLY.md',
        ];
        foreach ($required as $name) if (!isset($entries[$name])) throw new InvalidArgumentException('升级包缺少文件：' . $name);
        // Only the full-install entry points are forbidden. configure_nginx.py
        // and nginx-location.conf must stay allowed: deploy/upgrade.sh requires
        // them, and tools/package-website.ps1 ships both in the upgrade bundle.
        foreach (['install.sh', 'deploy/install.sh', 'deploy/entry-install.sh'] as $forbidden) {
            if (isset($entries[$forbidden])) throw new InvalidArgumentException('升级包不能包含完整安装入口：' . $forbidden);
        }

        $metadata = json_decode(np_upgrade_zip_entry_content($zip, 'package.json', $entries['package.json'], 1048576), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($metadata) || ($metadata['product'] ?? '') !== 'NovaProtect' || ($metadata['packageType'] ?? '') !== 'upgrade') throw new InvalidArgumentException('package.json 不是 NovaProtect 离线升级包。');
        if (($metadata['purpose'] ?? '') !== 'offline-upgrade') throw new InvalidArgumentException('package.json 升级用途无效。');
        // PowerShell's ConvertTo-Json collapses a one-element array into a
        // scalar, so accept both shapes; the contract is still "exactly one
        // entry point, and it is upgrade.sh".
        $entryPoints = $metadata['entryPoints'] ?? [];
        if (is_string($entryPoints)) $entryPoints = [$entryPoints];
        if (!is_array($entryPoints) || $entryPoints !== ['upgrade.sh']) throw new InvalidArgumentException('升级包入口不符合精简包要求。');

        $version = trim(np_upgrade_zip_entry_content($zip, 'VERSION', $entries['VERSION'], 128));
        if (!preg_match('/^\d+\.\d+\.\d+$/D', $version) || version_compare($version, np_website_version(), '<=')) throw new InvalidArgumentException('升级包网站版本必须高于当前版本 ' . np_website_version() . '。');
        if ((string) ($metadata['websiteVersion'] ?? '') !== $version) throw new InvalidArgumentException('package.json 网站版本与 VERSION 不一致。');

        $release = json_decode(np_upgrade_zip_entry_content($zip, 'release.json', $entries['release.json'], 1048576), true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($release) || ($release['websiteVersion'] ?? '') !== $version) throw new InvalidArgumentException('release.json 网站版本无效。');
        $clientFile = (string) ($release['fileName'] ?? '');
        $clientHash = strtolower((string) ($release['sha256'] ?? ''));
        if (!preg_match('/^NovaProtect-Setup-\d+\.\d+\.\d+\.exe$/D', $clientFile) || !preg_match('/^[a-f0-9]{64}$/D', $clientHash)) throw new InvalidArgumentException('release.json 客户端发布信息无效。');
        // The client installer is optional in an upgrade archive: slim packages
        // reuse the copy already in the server's download store, and
        // deploy/upgrade.sh re-verifies it against release.json before use.
        $downloadEntry = 'downloads/' . $clientFile;
        if (isset($entries[$downloadEntry]) && np_upgrade_zip_entry_hash($zip, $downloadEntry, $entries[$downloadEntry]) !== $clientHash) throw new InvalidArgumentException('客户端安装包 SHA-256 与 release.json 不一致。');

        $manifest = np_upgrade_zip_entry_content($zip, 'SHA256SUMS', $entries['SHA256SUMS'], 4194304);
        $manifestNames = [];
        foreach (preg_split('/\r?\n/', $manifest) ?: [] as $line) {
            if ($line === '') continue;
            if (!preg_match('/^([a-f0-9]{64})  (.+)$/D', $line, $matches)) throw new InvalidArgumentException('SHA256SUMS 格式无效。');
            $manifestName = $matches[2];
            if ($manifestName === 'SHA256SUMS' || !isset($entries[$manifestName]) || isset($manifestNames[$manifestName])) throw new InvalidArgumentException('SHA256SUMS 文件清单无效。');
            if (np_upgrade_zip_entry_hash($zip, $manifestName, $entries[$manifestName]) !== $matches[1]) throw new InvalidArgumentException('升级包文件校验失败：' . $manifestName);
            $manifestNames[$manifestName] = true;
        }
        if (count($manifestNames) !== count($entries) - 1) throw new InvalidArgumentException('SHA256SUMS 未覆盖所有升级包文件。');

        $upgradeScript = np_upgrade_zip_entry_content($zip, 'deploy/upgrade.sh', $entries['deploy/upgrade.sh'], 1048576);
        if (!str_starts_with($upgradeScript, "#!/usr/bin/env bash") || str_contains($upgradeScript, "\r")) throw new InvalidArgumentException('升级脚本格式无效。');
        return ['websiteVersion' => $version, 'clientVersion' => (string) ($release['clientVersion'] ?? ''), 'fileName' => $clientFile, 'size' => $size, 'sha256' => strtolower((string) hash_file('sha256', $archive)), 'fileCount' => count($entries), 'metadata' => $metadata];
    } catch (JsonException $exception) {
        throw new InvalidArgumentException('升级包 JSON 元数据无效。', 0, $exception);
    } finally {
        $zip->close();
    }
}

function np_upload_upgrade_package(array $file, string $actorId): array
{
    $error = $file['error'] ?? UPLOAD_ERR_NO_FILE;
    if (!is_int($error) || $error !== UPLOAD_ERR_OK) {
        $message = match ($error) { UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => '上传文件超过服务器限制。', UPLOAD_ERR_PARTIAL => '升级包上传不完整。', UPLOAD_ERR_NO_FILE => '请选择升级 ZIP。', default => '升级包上传失败。' };
        throw new InvalidArgumentException($message);
    }
    $temporary = $file['tmp_name'] ?? '';
    $originalName = is_string($file['name'] ?? null) ? basename(str_replace('\\', '/', $file['name'])) : '';
    if (!is_string($temporary) || !is_uploaded_file($temporary)) throw new InvalidArgumentException('上传临时文件无效。');
    return np_publish_upgrade_package($temporary, $originalName, $actorId, true);
}

/** Validate and store an offline upgrade archive that already sits on disk. */
function np_publish_upgrade_package(string $temporary, string $originalName, string $actorId, bool $fromUpload = false): array
{
    $validated = np_upgrade_validate_archive($temporary, $originalName);
    $id = np_uuid();
    $directory = np_upgrade_store_dir() . '/' . $validated['websiteVersion'] . '/' . $id;
    $staging = $directory . '/package';
    if (!mkdir($staging, 0700, true) && !is_dir($staging)) throw new RuntimeException('无法创建升级包存储目录。');
    $archive = $directory . '/NovaProtect-Website-' . $validated['websiteVersion'] . '-Offline.zip';
    try {
        $stored = $fromUpload ? @move_uploaded_file($temporary, $archive) : @rename($temporary, $archive);
        if (!$stored) {
            if ($fromUpload || !@copy($temporary, $archive)) throw new RuntimeException('无法保存升级包。');
            @unlink($temporary);
        }
        chmod($archive, 0600);
        $zip = new \ZipArchive();
        if ($zip->open($archive) !== true || !$zip->extractTo($staging)) throw new RuntimeException('无法展开已校验的升级包。');
        $zip->close();
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($staging, FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $item) {
            if ($item->isLink()) throw new RuntimeException('升级包展开后检测到符号链接。');
            chmod($item->getPathname(), $item->isDir() ? 0700 : 0600);
        }
        $record = ['id' => $id, 'websiteVersion' => $validated['websiteVersion'], 'clientVersion' => $validated['clientVersion'], 'fileName' => $validated['fileName'], 'originalName' => $originalName !== '' ? $originalName : $validated['fileName'], 'size' => $validated['size'], 'sha256' => $validated['sha256'], 'fileCount' => $validated['fileCount'], 'archivePath' => $archive, 'stagingPath' => $staging, 'status' => 'validated', 'uploadedAt' => gmdate('c'), 'uploadedBy' => $actorId];
        np_transaction('upgrade_packages', static function ($path) use ($record): void {
            $rows = np_upgrade_packages();
            foreach ($rows as $existing) if (($existing['websiteVersion'] ?? '') === $record['websiteVersion'] && ($existing['status'] ?? '') === 'validated') throw new InvalidArgumentException('该网站版本已经上传过升级包。');
            $rows[] = $record;
            np_atomic_write($path, array_slice($rows, -20));
        });
        return $record;
    } catch (Throwable $exception) {
        np_upgrade_remove_tree($directory);
        throw $exception;
    }
}
