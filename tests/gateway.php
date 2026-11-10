<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use React\EventLoop\Loop;
use TwoFactorAgent\PowerShellGateway;

if (PHP_OS_FAMILY === 'Windows') {
    echo "SKIP POSIX subprocess fixture; run PowerShell adapter checks on Windows.\n";
    return;
}

function awaitGateway(React\Promise\PromiseInterface $promise): mixed
{
    $result = null;
    $error = null;
    $promise->then(static function ($value) use (&$result): void { $result = $value; },
        static function ($failure) use (&$error): void { $error = $failure; });
    Loop::run();
    if ($error !== null) { throw $error; }
    return $result;
}

test('gateway subprocess validates JSON, protects configuration, times out and recovers', function (): void {
    $fixture = tempnam(sys_get_temp_dir(), '2fa-gateway-');
    $php = PHP_BINARY;
    if (str_contains($php, "\n") || str_contains($php, ' ')) {
        unlink($fixture);
        throw new RuntimeException('Fixture needs a PHP executable path without spaces.');
    }
    $source = <<<'PHP'
<?php
$request = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
if ($request['action'] === 'sleep') { sleep(5); }
if ($request['action'] === 'invalid') { echo 'invalid'; exit; }
if ($request['action'] === 'failure') {
    echo json_encode(['ok' => false, 'error' => ['code' => 'workstations_limit', 'message' => 'test']]); exit;
}
echo json_encode(['ok' => true, 'result' => ['controller' => $request['config']['domainController']]]);
PHP;
    file_put_contents($fixture, '#!' . $php . "\n" . $source);
    chmod($fixture, 0700);
    try {
        $gateway = new PowerShellGateway(testConfig(['powershellPath' => $fixture, 'processTimeoutSeconds' => 1]));
        eq(awaitGateway($gateway->execute(['action' => 'health', 'config' => ['domainController' => 'wrong.example.test']]))['controller'], 'dc1.example.test');
        foreach (['failure' => 409, 'invalid' => 502, 'sleep' => 504] as $action => $status) {
            expectError(fn () => awaitGateway($gateway->execute(['action' => $action])), $status);
        }
        eq(awaitGateway($gateway->execute(['action' => 'health']))['controller'], 'dc1.example.test');
    } finally {
        unlink($fixture);
    }
});

test('oversized directory stdin is rejected before starting a child', function (): void {
    $gateway = new PowerShellGateway(testConfig(['powershellPath' => '/nonexistent/never-started']));
    expectError(fn () => awaitResult($gateway->execute(['action' => 'health', 'padding' => str_repeat('x', 3000)])), 400);
});

test('a hung directory process does not stop event loop ticks and is terminated before reuse', function (): void {
    $fixture = tempnam(sys_get_temp_dir(), '2fa-gateway-hang-');
    $source = <<<'PHP'
<?php
stream_get_contents(STDIN);
sleep(30);
PHP;
    file_put_contents($fixture, '#!' . PHP_BINARY . "\n" . $source);
    chmod($fixture, 0700);
    $ticks = 0;
    $timer = Loop::addPeriodicTimer(0.02, function () use (&$ticks): void { ++$ticks; });
    try {
        $gateway = new PowerShellGateway(testConfig(['powershellPath' => $fixture, 'processTimeoutSeconds' => 1]));
        $promise = $gateway->execute(['action' => 'health']);
        expectError(fn () => awaitResult($gateway->execute(['action' => 'health'])), 503);
        $promise->then(null, static function () use ($timer): void { Loop::cancelTimer($timer); });
        $started = microtime(true);
        expectError(fn () => awaitGateway($promise), 504);
        eq($ticks >= 5, true);
        eq(microtime(true) - $started < 3, true);
    } finally {
        Loop::cancelTimer($timer);
        unlink($fixture);
    }
});
