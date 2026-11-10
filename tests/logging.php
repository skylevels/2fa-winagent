<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use TwoFactorAgent\AuditLogger;
use TwoFactorAgent\GrantManager;
use TwoFactorAgent\HttpServer;

function logFixture(callable $test): void
{
    $path = sys_get_temp_dir() . '/2fa-audit-' . bin2hex(random_bytes(8));
    mkdir($path, 0700);
    try { $test($path); }
    finally {
        foreach (glob($path . '/*') ?: [] as $file) { if (is_file($file) || is_link($file)) { unlink($file); } }
        if (is_dir($path)) { rmdir($path); }
    }
}

test('daily audit records are UTF8 JSON and omit secrets headers and raw requests', function (): void {
    logFixture(function (string $path): void {
        $logger = new AuditLogger(testConfig(['logDirectory' => $path]), fn () => 1793890800);
        $logger->record('access_result', ['login' => "ivanov\nsecond-line", 'computer' => 'PC-A', 'status' => 'granted',
            'apiSecretHex' => 'SECRET_VALUE', 'headers' => ['Authorization' => 'SECRET_HEADER'], 'body' => 'SECRET_BODY', 'exception' => 'SECRET_EXCEPTION']);
        $files = glob($path . '/*.jsonl'); eq(count($files), 1);
        $contents = file_get_contents($files[0]); $lines = explode("\n", trim($contents)); eq(count($lines), 2);
        $record = json_decode($lines[1], true, 32, JSON_THROW_ON_ERROR);
        eq($record['login'], "ivanov\nsecond-line"); eq($record['agent_id'], 'dc1'); eq($record['status'], 'granted');
        eq(str_contains($contents, 'SECRET_'), false);
    });
});

test('daily files switch at UTC midnight and do not overwrite previous logs', function (): void {
    logFixture(function (string $path): void {
        $now = strtotime('2026-10-31T23:59:59Z');
        $logger = new AuditLogger(testConfig(['logDirectory' => $path]), function () use (&$now) { return $now; });
        $logger->record('agent_started'); ++$now; $logger->record('access_result');
        eq(count(file($path . '/agent-2026-10-31.jsonl')), 2);
        eq(count(file($path . '/agent-2026-11-01.jsonl')), 1);
    });
});

test('logging failure is visible and later records recover without throwing', function (): void {
    logFixture(function (string $path): void {
        $logger = new AuditLogger(testConfig(['logDirectory' => $path]));
        rename($path, $path . '-away');
        try { $logger->record('cleanup_failed'); eq($logger->status()['logging_error'], 'log_write_failed'); }
        finally { rename($path . '-away', $path); }
        $logger->record('directory_ready'); eq($logger->status(), ['logging_error' => null, 'dropped_log_records' => 1]);
    });
});

test('missing private log directory blocks startup without creating an unprotected folder', function (): void {
    logFixture(function (string $path): void {
        $missing = $path . '/missing';
        try { new AuditLogger(testConfig(['logDirectory' => $missing])); }
        catch (RuntimeException) { eq(file_exists($missing), false); return; }
        throw new RuntimeException('Expected startup failure.');
    });
});

test('log fields are bounded and invalid UTF8 cannot corrupt JSON lines', function (): void {
    logFixture(function (string $path): void {
        $logger = new AuditLogger(testConfig(['logDirectory' => $path]));
        $logger->record('command_failed', ['login' => str_repeat('x', 10000), 'reason' => "bad\xff"]);
        $rows = file(glob($path . '/*.jsonl')[0]); $record = json_decode($rows[1], true, 32, JSON_THROW_ON_ERROR);
        eq(strlen($record['login']), 256); eq($logger->status()['logging_error'], null);
    });
});

test('revocation continues if logging becomes unavailable after grant', function (): void {
    logFixture(function (string $path): void {
        $clock = new FakeClock(); $directory = new FakeDirectory(); $config = testConfig(['logDirectory' => $path]);
        $logger = new AuditLogger($config, fn () => (int) $clock->wall);
        $manager = new GrantManager($config, $directory, fn () => $clock->wall, fn () => $clock->mono, $logger);
        awaitResult($manager->initialize()); grant($manager, $clock, 1, 'PC-A', 1);
        rename($path, $path . '-away');
        try {
            $clock->advance(1); $manager->tick(); eq($directory->pcs, ['2FA-BLOCK']);
            eq($manager->status()['logging_error'], 'log_write_failed'); eq($manager->status()['active_grants'], 0);
        } finally { rename($path . '-away', $path); }
        $events = array_map(fn ($line) => json_decode($line, true)['event'], file(glob($path . '/*.jsonl')[0]));
        eq(in_array('access_result', $events), true);
    });
});

test('HTTP diagnostics never record attacker-controlled exception text or signatures', function (): void {
    logFixture(function (string $path): void {
        $config = testConfig(['logDirectory' => $path]); $logger = new AuditLogger($config);
        $server = new HttpServer($config, fn () => React\Promise\reject(new RuntimeException('TOP_SECRET_MESSAGE', 503)), $logger);
        $response = awaitResult($server->handle(transportRequest($config)));
        eq($response->getStatusCode(), 503);
        $contents = file_get_contents(glob($path . '/*.jsonl')[0]);
        eq(str_contains($contents, 'TOP_SECRET_MESSAGE'), false);
        eq(str_contains($contents, 'api_error'), true); eq(str_contains($contents, 'X-2FA'), false);
    });
});

test('log configuration rejects drive roots relative paths and UNC paths', function (): void {
    foreach (['logs', 'C:\\', '\\\\server\\share', '/','//server/share', "C:\\2fa\\logs\n"] as $path) {
        transportThrows(fn () => testConfig(['logDirectory' => $path]));
    }
});
