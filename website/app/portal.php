<?php
declare(strict_types=1);

function np_form_start(string $action, bool $admin = false, bool $multipart = false, bool $uploadProgress = false): string
{
    $html = '<form method="post" class="stack-form"' . ($multipart ? ' enctype="multipart/form-data"' : '') . ($uploadProgress ? ' data-upload-progress-form' : '') . '>' . np_hidden_csrf() . '<input type="hidden" name="action" value="' . np_e($action) . '">';
    if ($admin) {
        $id = np_uuid();
        $_SESSION['admin_ops'][$id] = false;
        $_SESSION['admin_ops'] = array_slice($_SESSION['admin_ops'], -150, null, true);
        $html .= '<input type="hidden" name="op_id" value="' . $id . '">';
    }
    return $html;
}

function np_upload_progress(): string
{
    return '<div class="upload-progress" data-upload-progress hidden aria-live="polite"><div class="upload-progress-header"><strong data-upload-status>准备上传</strong><span data-upload-percent>0%</span></div><progress max="100" value="0" data-upload-meter aria-label="上传进度"></progress><p class="field-hint" data-upload-detail>上传开始后会显示实时进度。</p></div>';
}

function np_field(string $name, string $label, string $value = '', string $type = 'text', string $extra = ''): string
{
    return '<div class="field"><label>' . np_e($label) . '<input name="' . np_e($name) . '" type="' . np_e($type) . '" value="' . np_e($value) . '" ' . $extra . '></label></div>';
}

function np_admin_post(string $tab): never
{
    if ($tab === 'client-releases' && np_request_exceeds_post_max_size()) {
        $limit = np_ini_size_bytes((string) ini_get('post_max_size'));
        np_error('本次上传超过 PHP-FPM 的 post_max_size（' . np_format_bytes($limit) . '）；部署新版网站包并等待 PHP-FPM 应用上传配置后重试。', 413);
    }
    if (!np_check_csrf()) np_error('表单已过期，请刷新后重试。', 400);
    $operation = np_text($_POST['op_id'] ?? '', 40, '操作编号');
    if (!array_key_exists($operation, $_SESSION['admin_ops'] ?? [])) np_error('操作已过期，请刷新页面。', 409);
    if ($_SESSION['admin_ops'][$operation]) { np_flash('该操作已经处理。'); np_redirect('/admin?tab=' . $tab); }
    if (!np_rate_limit('admin-write', 'admin', 100, 300)) np_error('操作过于频繁，请稍后重试。', 429);
    $action = np_text($_POST['action'] ?? '', 40, '操作');
    $message = '已保存。';
    try {
        switch ($action) {
            case 'upgrade-upload':
                $record = np_upload_upgrade_package($_FILES['upgrade_package'] ?? [], 'admin');
                $message = '升级包 ' . $record['websiteVersion'] . ' 已上传并校验，后台可直接提交升级。'; break;
            case 'upgrade-execute':
                $record = np_request_upgrade_execution(np_text($_POST['package_id'] ?? '', 40, '升级包'), 'admin');
                $message = '升级包 ' . $record['websiteVersion'] . ' 已提交给服务器升级执行器，完成后刷新本页查看结果。'; break;
            case 'client-release-upload':
                $minimum = np_text($_POST['minimum_client_version'] ?? '', 32, '最低可用版本');
                $notes = np_text($_POST['release_notes'] ?? '', 12000, '更新说明', false);
                $record = np_upload_client_release($_FILES['client_installer'] ?? [], $minimum, ($_POST['force_update'] ?? '') === '1', $notes, 'admin');
                $message = '客户端 ' . $record['clientVersion'] . ' 已识别、校验并立即发布；客户端下次检查更新时会收到该版本。'; break;
            default: throw new InvalidArgumentException('不支持的管理操作。');
        }
        $_SESSION['admin_ops'][$operation] = true;
        np_audit('admin', $action, ['operationId' => $operation]);
        np_flash($message);
    } catch (InvalidArgumentException $e) { np_flash($e->getMessage()); }
    np_redirect('/admin?tab=' . $tab);
}

function np_admin_upgrades(): string
{
    $rows = np_upgrade_packages();
    $html = '<section class="surface admin-panel"><h2>上传网站离线升级包</h2><p>仅上传 NovaProtect 生成的精简升级 ZIP。系统会校验网站版本、SHA-256 清单、客户端安装包哈希和升级包布局；上传后可直接提交给服务器 root 升级执行器。</p>' . np_form_start('upgrade-upload', true, true, true) . '<div class="field"><label>精简升级 ZIP<input type="file" name="upgrade_package" accept=".zip,application/zip" required></label><small>建议使用 artifacts/website-upgrade/&lt;版本&gt; 下的 ZIP，单包最大 256 MB。</small></div>' . np_upload_progress() . '<button class="button button-primary" type="submit" data-upload-submit>上传并校验升级包</button></form></section>';
    $html .= '<section class="surface admin-panel"><h2>已上传升级包</h2><div class="table-scroll"><table><caption>离线升级包记录</caption><thead><tr><th>网站版本</th><th>状态</th><th>文件</th><th>大小</th><th>SHA-256</th><th>上传时间</th><th>操作</th></tr></thead><tbody>';
    foreach ($rows as $row) {
        $path = is_string($row['stagingPath'] ?? null) ? $row['stagingPath'] : '';
        $available = $path !== '' && is_file($path . '/upgrade.sh') && is_file($path . '/SHA256SUMS');
        $execution = is_array($row['execution'] ?? null) ? $row['execution'] : ['status' => 'ready'];
        $status = !$available ? '文件缺失' : match ((string) ($execution['status'] ?? 'ready')) {
            'queued' => '已提交，等待执行器', 'running' => '正在升级', 'result' => ((int) ($execution['exitCode'] ?? 1) === 0 ? '升级完成' : '升级失败，可重试'), 'invalid' => '执行状态损坏', default => '已校验，待执行'
        };
        $size = is_int($row['size'] ?? null) || is_float($row['size'] ?? null) ? number_format((float) $row['size'] / 1048576, 2) . ' MB' : '—';
        $canExecute = $available && in_array((string) ($execution['status'] ?? 'ready'), ['ready', 'result'], true) && !((string) ($execution['status'] ?? '') === 'result' && (int) ($execution['exitCode'] ?? 1) === 0);
        $actionForm = $canExecute ? np_form_start('upgrade-execute', true) . '<input type="hidden" name="package_id" value="' . np_e((string) ($row['id'] ?? '')) . '"><button class="button button-small button-primary">一键升级</button></form>' : '<span class="field-hint">刷新查看</span>';
        $html .= '<tr><td><strong>' . np_e((string) ($row['websiteVersion'] ?? '')) . '</strong><small>客户端 ' . np_e((string) ($row['clientVersion'] ?? '')) . '</small></td><td><span class="status ' . ($available ? 'status-ok' : 'status-danger') . '">' . $status . '</span>' . (!empty($execution['message']) ? '<small>' . np_e((string) $execution['message']) . '</small>' : '') . '</td><td>' . np_e((string) ($row['originalName'] ?? $row['fileName'] ?? '')) . '</td><td>' . $size . '</td><td><code class="hash-value">' . np_e((string) ($row['sha256'] ?? '')) . '</code></td><td>' . np_e((string) ($row['uploadedAt'] ?? '')) . '</td><td>' . $actionForm . '</td></tr>';
    }
    if (!$rows) $html .= '<tr><td colspan="7">暂无已上传升级包。</td></tr>';
    $html .= '</tbody></table></div><p class="notice">一键升级会创建受控执行请求，由 root 定时执行器调用已校验的升级脚本；升级脚本自行备份、迁移、健康检查和失败回滚。</p></section>';
    return $html;
}

function np_admin_client_releases(): string
{
    $current = np_client_release();
    $rows = np_client_release_history();
    $defaultMinimum = (string) ($current['clientVersion'] ?? '0.0.0');
    $uploadLimit = np_ini_size_bytes((string) ini_get('upload_max_filesize'));
    $postLimit = np_ini_size_bytes((string) ini_get('post_max_size'));
    $effectiveLimit = min(array_filter([$uploadLimit, $postLimit], static fn(int $limit): bool => $limit > 0) ?: [0]);
    $limitNotice = $effectiveLimit > 0 && $effectiveLimit < 268435456
        ? '<p class="notice">当前 PHP-FPM 文件上传上限约为 ' . np_e(np_format_bytes($effectiveLimit)) . '，小于客户端发布页的 256 MB 上限；请部署新版网站包并等待 PHP-FPM 应用上传配置。</p>'
        : '';
    $html = '<section class="surface admin-panel"><h2>发布客户端新版本</h2><p>选择客户端 EXE 后会自动识别 PE 版本、自动规范化文件名并校验安装包。更新说明留空时，会自动读取安装包的更新摘要；不需要手动填写。</p>' . $limitNotice . np_form_start('client-release-upload', true, true, true) . '<div class="field"><label>客户端安装包（EXE）<input type="file" name="client_installer" accept=".exe" required></label><small>仅接受 NovaProtect 客户端安装包；最大 256 MB。版本号必须高于当前官网版本 ' . np_e($defaultMinimum) . '。</small></div><div class="form-grid">' . np_field('minimum_client_version', '最低可用版本', $defaultMinimum, 'text', 'required pattern="\\d+\\.\\d+\\.\\d+" maxlength="32"') . '<label class="check-label"><input type="checkbox" name="force_update" value="1" checked>强制更新：低于最低版本时禁止使用</label></div><div class="field"><label>客户端更新说明<textarea name="release_notes" rows="6" maxlength="12000" placeholder="留空将自动生成更新说明"></textarea></label></div>' . np_upload_progress() . '<button class="button button-primary" type="submit" data-upload-submit>上传并立即发布</button></form></section>';
    $html .= '<section class="surface admin-panel"><h2>客户端更新日志</h2><div class="table-scroll"><table><caption>已发布客户端版本</caption><thead><tr><th>版本</th><th>最低版本</th><th>策略</th><th>说明</th><th>时间</th><th>SHA-256</th></tr></thead><tbody>';
    foreach ($rows as $row) {
        $isCurrent = (string) ($row['clientVersion'] ?? '') === (string) ($current['clientVersion'] ?? '') && (string) ($row['sha256'] ?? '') === strtolower((string) ($current['sha256'] ?? ''));
        $html .= '<tr><td><strong>' . np_e((string) ($row['clientVersion'] ?? '')) . '</strong>' . ($isCurrent ? '<small>当前生效</small>' : '') . '</td><td>' . np_e((string) ($row['minimumClientVersion'] ?? '')) . '</td><td>' . (($row['forceUpdate'] ?? false) ? '强制更新' : '可选更新') . '</td><td class="release-notes-cell">' . nl2br(np_e((string) ($row['releaseNotes'] ?? ''))) . '</td><td>' . np_e((string) ($row['publishedAt'] ?? '')) . '</td><td><code class="hash-value">' . np_e((string) ($row['sha256'] ?? '')) . '</code></td></tr>';
    }
    if (!$rows) $html .= '<tr><td colspan="6">暂无客户端发布记录。</td></tr>';
    return $html . '</tbody></table></div><p class="notice">当前客户端元数据保存到服务器共享数据目录，网站升级不会覆盖；安装包本体保存在网站根目录之外。</p></section>';
}

function np_admin_page(string $tab, int $page): never
{
    $tabs = ['client-releases' => '客户端发布', 'upgrades' => '版本与升级'];
    $nav = '';
    foreach ($tabs as $key => $label) $nav .= '<a href="/admin?tab=' . $key . '"' . ($key === $tab ? ' aria-current="page"' : '') . '>' . $label . '</a>';
    $body = match ($tab) {
        'upgrades' => np_admin_upgrades(),
        default => np_admin_client_releases(),
    };
    np_page('管理后台', '<main class="admin-shell"><div class="page-heading"><div><div class="eyebrow">NovaProtect administration</div><h1>管理后台</h1><p class="lede">客户端发布与网站升级。</p></div><form method="post" action="/logout" class="nav-form"><input type="hidden" name="csrf" value="' . np_e(np_csrf_token()) . '"><button type="submit">退出登录</button></form></div><nav class="admin-tabs" aria-label="管理功能">' . $nav . '</nav>' . np_flash_html() . $body . '</main>');
}
