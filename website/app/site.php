<?php
declare(strict_types=1);

function np_home(array $release): void
{
    $body = '<main><section class="hero"><div class="hero-copy"><div class="eyebrow">Windows code protection</div><h1>NovaProtect</h1><p class="hero-lede">面向 Windows EXE 的可信代码保护工作台。</p><p class="hero-support">支持 C/C++、C#/VB .NET、Rust 和 Golang EXE。以目标文件中的 NovaProtect SDK marker 作为函数与区域对象的事实来源。</p><div class="hero-actions"><a class="button button-primary" href="/download">下载客户端</a><a class="button button-secondary" href="/client-updates">更新日志</a></div><div class="hero-meta"><span class="status-dot"></span> 网站版本 ' . np_e(np_website_version()) . ' · 客户端 ' . np_e($release['clientVersion'] ?? '2.2.3') . '</div></div><div class="hero-console"><div class="console-bar"><span class="console-dot"></span><span class="console-dot"></span><span class="console-dot"></span><span class="console-title">novaprotect.project</span></div><div class="console-body"><div><span class="code-muted">target</span> <span class="code-value">native-pe / x64</span></div><div><span class="code-muted">marker</span> <span class="code-value">NovaProtect SDK marker</span></div><div><span class="code-muted">sections</span> <span class="code-value">encrypted</span></div><div><span class="code-muted">imports</span> <span class="code-value">virtualized</span></div><div><span class="code-muted">activation</span> <span class="code-value">bound</span></div><div class="console-divider"></div><div><span class="code-success">build ready</span> <span class="code-muted">request / effective / conflicts persisted</span></div></div></div></section><section class="section-block"><div class="section-heading"><div><div class="eyebrow">Product surface</div><h2>从项目配置到发布前检查</h2></div><p>官网提供客户端下载与更新日志；保护能力全部在本地客户端内完成。</p></div><div class="feature-grid"><article class="feature-item"><span class="feature-index">01</span><h3>可信对象编辑</h3><p>只展示真实 SDK marker 区域，不把任意符号、导出或反编译结果伪装成函数。</p></article><article class="feature-item"><span class="feature-index">02</span><h3>请求 / 生效 / 冲突</h3><p>统一模型记录请求区域、生效区域与冲突项，导出前即可核对差异。</p></article><article class="feature-item"><span class="feature-index">03</span><h3>发布前检查</h3><p>虚拟化、混淆、加密与校验项在打包前一次跑完，问题就地定位。</p></article></div></section><section class="section-block"><div class="section-heading"><div><div class="eyebrow">Release flow</div><h2>官网只负责分发客户端</h2></div><p>安装包与更新说明由后台发布，客户端启动时自动检查更新。</p></div><div class="feature-grid"><article class="feature-item"><span class="feature-index">04</span><h3>公开下载</h3><p>无需账户，直接下载当前版本安装包，页面提供 SHA-256 校验。</p></article><article class="feature-item"><span class="feature-index">05</span><h3>自动更新</h3><p>客户端按最低可用版本判断是否强制更新，后台可查看发布历史。</p></article><article class="feature-item"><span class="feature-index">06</span><h3>后台发布</h3><p>上传新安装包即自动识别版本、校验哈希并立即对客户端生效。</p></article></div></section></main>';
    np_page('NovaProtect 代码保护工具', $body);
}

function np_client_updates_page(array $releases): never
{
    $items = '';
    foreach ($releases as $release) {
        $notes = trim((string) ($release['releaseNotes'] ?? ''));
        $items .= '<article class="surface announcement"><div class="announcement-meta"><span class="status ' . (($release['forceUpdate'] ?? false) ? 'status-danger' : 'status-ok') . '">' . (($release['forceUpdate'] ?? false) ? '强制更新' : '可选更新') . '</span><time>' . np_e((string) ($release['publishedAt'] ?? '')) . '</time></div><h2>客户端 ' . np_e((string) ($release['clientVersion'] ?? '')) . '</h2><p class="announcement-body">' . nl2br(np_e($notes !== '' ? $notes : '本次版本没有填写更新说明。')) . '</p><p class="field-hint">最低可用版本：' . np_e((string) ($release['minimumClientVersion'] ?? $release['clientVersion'] ?? '')) . '</p></article>';
    }
    np_page('客户端更新日志', '<main class="content-shell"><div class="page-heading"><div><div class="eyebrow">NovaProtect client releases</div><h1>客户端更新日志</h1><p class="lede">查看客户端版本、更新说明和最低可用版本。</p></div><a class="button" href="/download">下载客户端</a></div><div class="announcement-list">' . ($items !== '' ? $items : '<p class="empty-state">暂无客户端更新日志。</p>') . '</div></main>');
}

function np_admin_login_page(string $error = ''): never
{
    np_page('管理员登录', '<main class="auth-shell"><section class="auth-panel"><div class="eyebrow">NovaProtect administration</div><h1>管理员登录</h1><p class="lede">网站没有用户账户系统；此处仅用于发布客户端与网站升级。</p>' . np_form_error($error) . '<form method="post" class="stack-form" action="/admin/login">' . np_hidden_csrf() . '<div class="field"><label for="password">管理员口令</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus></div><button class="button button-primary button-wide" type="submit">登录后台</button></form></section></main>');
}

function np_handle_admin_login(): never
{
    if (!np_check_csrf()) np_admin_login_page('表单已过期，请刷新后重试。');
    if (!np_admin_login_allowed()) { http_response_code(429); np_admin_login_page('尝试次数过多，请五分钟后再试。'); }
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $hash = np_admin_password_hash();
    if ($hash === null || strlen($password) > 128 || !np_verify_password($password, $hash)) np_admin_login_page('口令不正确。');
    np_admin_sign_in();
    np_redirect('/admin');
}

function np_install_page(string $error = ''): void
{
    $checks = array(
        'PHP ' . PHP_VERSION . '（要求 8.4+）' => version_compare(PHP_VERSION, '8.4.0', '>='),
        'JSON / session / hash 扩展' => function_exists('json_encode') && function_exists('session_start') && function_exists('hash_pbkdf2'),
        '安装包 SHA-256 校验' => np_release_file(true) !== null,
        'OpenSSL/随机数' => function_exists('random_bytes'),
        '可写数据目录：' . np_data_dir() => is_dir(np_data_dir()) && is_writable(np_data_dir())
    );
    $rows = '';
    foreach ($checks as $label => $ok) $rows .= '<li class="' . ($ok ? 'check-ok' : 'check-fail') . '">' . ($ok ? '✓ ' : '✗ ') . np_e($label) . '</li>';
    np_page('安装向导', '<main class="auth-shell"><section class="auth-panel"><div class="eyebrow">NovaProtect setup</div><h1>安装向导</h1><div class="setup-steps" aria-label="安装步骤"><span>01 环境检查</span><span>02 设置管理员口令</span><span>03 锁定安装</span></div><p class="lede">完成一次初始化后，网站会锁定安装入口；该口令用于登录后台发布客户端与网站升级。</p><ul class="setup-checks">' . $rows . '</ul>' . np_form_error($error) . '<form method="post" class="stack-form">' . np_hidden_csrf() . '<div class="field"><label for="setup_token">安装口令</label><input id="setup_token" name="setup_token" autocomplete="off" type="password" required><small>安装脚本在终端显示的一次性口令。</small></div><div class="field"><label for="password">管理员口令</label><input id="password" name="password" type="password" minlength="10" maxlength="128" autocomplete="new-password" required><small>10 到 128 字节；用于登录 /admin 后台。</small></div><div class="field"><label for="confirm_password">确认管理员口令</label><input id="confirm_password" name="confirm_password" type="password" minlength="10" maxlength="128" autocomplete="new-password" required></div><button class="button button-primary button-wide" type="submit">完成安装</button></form><p class="notice">安装目录：' . np_e(np_data_dir()) . '<br>网站不保存任何用户账户；后台仅使用这一个管理员口令。</p></section></main>');
}

function np_handle_install(): void
{
    if (np_installed()) np_redirect('/admin');
    if (!np_check_csrf()) np_install_page('表单已过期，请刷新后重试。');
    if (!np_rate_limit('setup', $_SERVER['REMOTE_ADDR'] ?? 'local', 8, 300)) { http_response_code(429); np_install_page('安装尝试过多，请五分钟后再试。'); }
    $token = $_POST['setup_token'] ?? null;
    $setup = np_read_json(np_data_dir() . '/setup.json');
    $tokenHash = np_setup_token_hash();
    $expiresAt = is_string($setup['expiresAt'] ?? null) ? strtotime($setup['expiresAt']) : false;
    if ($tokenHash === null || $expiresAt === false || $expiresAt < time() || !is_string($token) || strlen($token) > 128 || !hash_equals($tokenHash, hash('sha256', $token))) np_install_page('安装口令不正确或已过期。请使用安装脚本终端显示的口令重新部署。');
    $password = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
    $confirm = is_string($_POST['confirm_password'] ?? null) ? $_POST['confirm_password'] : '';
    if (strlen($password) < 10 || strlen($password) > 128 || $password !== $confirm) np_install_page('管理员口令需要 10 到 128 字节，且两次输入必须一致。');
    if (np_release_file(true) === null) np_install_page('安装包缺失或校验失败，请重新上传完整发布包。');
    $done = np_transaction('installation', static function (string $path) use ($password): bool {
        if ((np_read_json($path)['installed'] ?? false) === true) return false;
        np_set_admin_password($password);
        np_atomic_write($path, ['installed' => true, 'websiteVersion' => np_website_version(), 'installedAt' => gmdate('c')]);
        return true;
    });
    if (!$done) np_install_page('安装已完成；原数据保持不变。');
    np_migrate(); np_remove_setup_token(); np_admin_sign_in(); np_redirect('/admin');
}
