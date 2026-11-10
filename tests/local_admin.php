<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use React\Promise\Deferred;
use TwoFactorAgent\LocalAdminServer;

function localAdminAccept(LocalAdminServer $server, string $id, string $command, bool $dryRun = false): void
{
    (new ReflectionMethod($server, 'accept'))->invoke($server, ['id' => $id, 'command' => $command, 'dryRun' => $dryRun]);
}
function localAdminRequests(LocalAdminServer $server): array
{
    return (new ReflectionProperty($server, 'requests'))->getValue($server);
}

test('local console command is executed once for a repeated request id', function (): void {
    [$manager, $directory] = fixture();
    $server = new LocalAdminServer(testConfig(), $manager);
    $id = str_repeat('a', 64);
    localAdminAccept($server, $id, 'disable');
    localAdminAccept($server, $id, 'disable');
    eq(count(array_filter($directory->calls, fn ($call) => $call['action'] === 'bulk-disable')), 1);
    eq(localAdminRequests($server)[$id]['response']['result']['status'], 'disabled');
});

test('local status remains available while a bulk command has not completed', function (): void {
    [$manager, $directory] = fixture();
    $pending = new Deferred();
    $directory->bulkBatches = [$pending];
    $server = new LocalAdminServer(testConfig(), $manager);
    localAdminAccept($server, str_repeat('b', 64), 'enable');
    localAdminAccept($server, str_repeat('c', 64), 'status');
    eq(localAdminRequests($server)[str_repeat('b', 64)]['response'], null);
    eq(localAdminRequests($server)[str_repeat('c', 64)]['response']['result']['bulk_running'], true);
    $pending->resolve(['found' => 1, 'changed' => 1, 'excluded' => 0, 'failed' => 0]);
    eq(localAdminRequests($server)[str_repeat('b', 64)]['response']['result']['status'], 'enabled');
});

test('local console rejects unknown commands and exposes bounded safe failures', function (): void {
    [$manager, $directory] = fixture();
    $server = new LocalAdminServer(testConfig(), $manager);
    try { localAdminAccept($server, str_repeat('d', 64), '/v1/admin/disable'); throw new LogicException('Accepted route as local command.'); }
    catch (RuntimeException) {}
    $directory->fail['bulk-disable'] = 1;
    localAdminAccept($server, str_repeat('e', 64), 'disable');
    $response = localAdminRequests($server)[str_repeat('e', 64)]['response'];
    eq($response['ok'], false);
    eq($response['error']['code'], 'local_command_failed');
    eq(str_contains(json_encode($response), 'Fake AD'), false);
});

test('local pipe name is stable and does not contain a host or network endpoint', function (): void {
    eq(LocalAdminServer::pipeName('dosifey'), 'Elemer-2FA-' . hash('sha256', 'dosifey'));
    eq(str_contains(LocalAdminServer::pipeName('dosifey'), '\\'), false);
    eq(LocalAdminServer::pipeName('dosifey') === LocalAdminServer::pipeName('pimen'), false);
});

test('local bridge bounds its pipe input while retaining pending commands and fresh status', function (): void {
    [$manager, $directory] = fixture();
    $pending = new Deferred();
    $directory->bulkBatches = [$pending];
    $server = new LocalAdminServer(testConfig(), $manager);
    $pendingId = str_repeat('a', 64);
    localAdminAccept($server, $pendingId, 'enable');
    $complete = new ReflectionMethod($server, 'complete');
    foreach (['b', 'c', 'd'] as $letter) {
        localAdminAccept($server, str_repeat($letter, 64), 'status');
        $complete->invoke($server, str_repeat($letter, 64), ['ok' => true, 'result' => ['detail' => str_repeat('x', 2500)]]);
    }
    localAdminAccept($server, str_repeat('e', 64), 'status');
    $input = (new ReflectionMethod($server, 'snapshotInput'))->invoke($server);
    eq(strlen($input) <= 3000, true);
    $entries = array_column(json_decode($input, true, 32, JSON_THROW_ON_ERROR)['entries'], null, 'id');
    eq($entries[$pendingId]['response'], null);
    eq($entries[str_repeat('e', 64)]['response']['result']['bulk_running'], true);
    eq(isset($entries[str_repeat('b', 64)]), false);
    $pending->resolve(['found' => 1, 'changed' => 1, 'excluded' => 0, 'failed' => 0]);
    eq(localAdminRequests($server)[$pendingId]['response']['result']['status'], 'enabled');
});

test('a large latest console result remains pollable within the pipe input bound', function (): void {
    [$manager, $directory] = fixture();
    $pending = new Deferred();
    $directory->bulkBatches = [$pending];
    $server = new LocalAdminServer(testConfig(), $manager);
    localAdminAccept($server, str_repeat('a', 64), 'enable');
    $id = str_repeat('b', 64);
    localAdminAccept($server, $id, 'status');
    $result = ['ok' => true, 'result' => ['detail' => str_repeat('x', 2500)]];
    (new ReflectionMethod($server, 'complete'))->invoke($server, $id, $result);
    $input = (new ReflectionMethod($server, 'snapshotInput'))->invoke($server);
    eq(strlen($input) <= 3000, true);
    $entries = array_column(json_decode($input, true, 32, JSON_THROW_ON_ERROR)['entries'], null, 'id');
    eq($entries[$id]['response'], $result);
    eq($entries[str_repeat('a', 64)]['response'], null);
    $pending->resolve(['found' => 1, 'changed' => 1, 'excluded' => 0, 'failed' => 0]);
});

test('a hung local console bridge is killed without blocking and its buffered command is discarded', function (): void {
    [$manager, $directory] = fixture();
    $initialCalls = $directory->calls;
    $server = new LocalAdminServer(testConfig(), $manager);
    $request = json_encode(['event' => 'request', 'id' => str_repeat('f', 64), 'command' => 'disable', 'dryRun' => false], JSON_THROW_ON_ERROR);
    $child = 'fwrite(STDOUT, ' . var_export($request, true) . '); fflush(STDOUT); sleep(10);';
    $process = proc_open([PHP_BINARY, '-r', $child], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) { throw new RuntimeException('Unable to start test bridge.'); }
    fclose($pipes[0]);
    unset($pipes[0]);
    $set = fn (string $name, mixed $value) => (new ReflectionProperty($server, $name))->setValue($server, $value);
    $get = fn (string $name) => (new ReflectionProperty($server, $name))->getValue($server);
    $poll = new ReflectionMethod($server, 'poll');
    $set('running', true);
    $set('process', $process);
    $set('pipes', $pipes);
    $set('processDeadline', hrtime(true) / 1e9 + 330);
    try {
        $before = hrtime(true) / 1e9;
        $poll->invoke($server);
        eq(hrtime(true) / 1e9 - $before < 0.5, true);
        eq($get('processTimedOut'), false);
        // Let the real child place a syntactically valid mutation in stdout,
        // then hang: timed-out output must never become a directory command.
        usleep(100000);
        $set('processDeadline', 0.0);
        $before = hrtime(true) / 1e9;
        $poll->invoke($server);
        eq(hrtime(true) / 1e9 - $before < 0.5, true);
        eq($get('processTimedOut'), true);
        $deadline = hrtime(true) / 1e9 + 2;
        while (is_resource($get('process')) && hrtime(true) / 1e9 < $deadline) {
            usleep(10000);
            $poll->invoke($server);
        }
        eq($get('process'), null);
        eq($get('pipes'), []);
        eq($get('retryAfter') > hrtime(true) / 1e9, true);
        eq(localAdminRequests($server), []);
        eq($directory->calls, $initialCalls);
    } finally { $server->stop(); }
});
