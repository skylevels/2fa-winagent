<?php
declare(strict_types=1);

// Installer-only check: never print configuration values or exception details.
require dirname(__DIR__) . '/src/Config.php';
try {
    if ($argc !== 2) { throw new RuntimeException('Invalid arguments.'); }
    TwoFactorAgent\Config::load($argv[1]);
} catch (Throwable) {
    fwrite(STDERR, "Agent configuration validation failed. Check the documented configuration fields and allowed IP addresses.\n");
    exit(1);
}
