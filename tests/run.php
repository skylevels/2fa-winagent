<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/core.php';
require __DIR__ . '/local_admin.php';
require __DIR__ . '/transport.php';
require __DIR__ . '/support.php';
require __DIR__ . '/revoke_retry.php';
require __DIR__ . '/durations.php';
require __DIR__ . '/ingress.php';
require __DIR__ . '/protocol.php';
require __DIR__ . '/gateway.php';
require __DIR__ . '/logging.php';
require __DIR__ . '/tls.php';
require __DIR__ . '/certificate.php';
echo "{$GLOBALS['test_count']} tests, {$GLOBALS['test_failures']} failures.\n";
exit($GLOBALS['test_failures'] === 0 ? 0 : 1);
