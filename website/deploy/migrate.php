<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "migration is CLI-only\n");
    exit(2);
}

require dirname(__DIR__) . '/app/bootstrap.php';

try {
    if (!np_installed()) {
        throw new RuntimeException('website is not installed');
    }
    np_migrate();
    fwrite(STDOUT, 'MIGRATION-OK ' . np_website_version() . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDERR, 'MIGRATION-FAILED ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}
