<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/core.php';
require_once __DIR__ . '/transport.php';
require_once __DIR__ . '/support.php';

use React\Promise\Deferred;
use TwoFactorAgent\Auth;
use TwoFactorAgent\HttpServer;

function durationBody(FakeClock $clock, int $sequence, int $ttl, bool $support): array
{
    return $support ? supportCommand($clock, $sequence, $ttl) : command($clock, $sequence, 'PC-A', $ttl);
}

test('duration defaults preserve the ordinary and support contracts and advertise integer limits', function (): void {
    $config = testConfig();
    eq($config->get('grantDurationSeconds'), 300);
    eq($config->get('supportDurationSeconds'), 60);
    [$manager] = fixture();
    $status = awaitResult($manager->handle('/v1/status', []));
    eq($status['grant_duration_seconds'], 300);
    eq($status['support_duration_seconds'], 60);
});

test('duration configuration accepts both independent integer boundaries', function (): void {
    foreach ([30, 300, 600] as $pair) {
        foreach ([30, 60, 180] as $support) {
            $config = testConfig(['grantDurationSeconds' => $pair, 'supportDurationSeconds' => $support]);
            eq($config->get('grantDurationSeconds'), $pair);
            eq($config->get('supportDurationSeconds'), $support);
        }
    }
});

test('duration configuration rejects out-of-range values and numeric coercion', function (): void {
    foreach (['grantDurationSeconds' => 600, 'supportDurationSeconds' => 180] as $field => $maximum) {
        foreach ([29, 0, -1, $maximum + 1, 30.0, '30', true, false, null, [], INF, NAN] as $invalid) {
            transportThrows(fn () => testConfig([$field => $invalid]));
        }
    }
});

test('an ordinary grant configured for six hundred seconds expires at its original deadline', function (): void {
    [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 600]);
    $body = command($clock, 1, 'PC-A', 600);
    $result = awaitResult($manager->handle('/v1/grants', $body));
    eq($result['status'], 'granted');
    eq($result['expires_at'], $body['expires_at']);
    $clock->advance(599); $manager->tick();
    eq(in_array('PC-A', $directory->pcs, true), true);
    eq($manager->status()['active_grants'], 1);
    $clock->advance(1); $manager->tick();
    eq($directory->pcs, ['2FA-BLOCK']);
    eq($manager->status()['active_grants'], 0);
});

test('a support grant configured for one hundred eighty seconds restores the baseline at its deadline', function (): void {
    [$manager, $directory, $clock] = fixture(['supportDurationSeconds' => 180]);
    $body = supportCommand($clock, 1, 180);
    $result = awaitResult($manager->handle('/v1/support/grants', $body));
    eq($result['status'], 'granted');
    eq($result['expires_at'], $body['expires_at']);
    $clock->advance(179); $manager->tick();
    eq($directory->pcs, []);
    eq($manager->status()['active_support_grants'], 1);
    $clock->advance(1); $manager->tick();
    eq($directory->pcs, ['2FA-BLOCK']);
    eq($manager->status()['active_support_grants'], 0);
});

test('the thirty second configuration minimum is enforced by both expiry timers', function (): void {
    foreach ([false, true] as $support) {
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 30, 'supportDurationSeconds' => 30]);
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        eq(awaitResult($manager->handle($path, durationBody($clock, 1, 30, $support)))['status'], 'granted');
        $clock->advance(29); $manager->tick();
        eq($manager->status()['active_grants'], 1);
        $clock->advance(1); $manager->tick();
        eq($directory->pcs, ['2FA-BLOCK']);
        eq($manager->status()['active_grants'], 0);
    }
});

test('a delivered command may have less than thirty seconds remaining without extending its deadline', function (): void {
    foreach ([false, true] as $support) {
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 30, 'supportDurationSeconds' => 30]);
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $body = durationBody($clock, 1, 1, $support);
        $result = awaitResult($manager->handle($path, $body));
        eq($result['status'], 'granted');
        eq($result['expires_at'], $body['expires_at']);
        $clock->advance(1); $manager->tick();
        eq($directory->pcs, ['2FA-BLOCK']);
        eq($manager->status()['active_grants'], 0);
    }
});

test('requests exceeding either configured duration are rejected before an AD lookup or write', function (): void {
    foreach ([[30, 30], [90, 70], [600, 180]] as [$pair, $support]) {
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => $pair, 'supportDurationSeconds' => $support]);
        expectError(fn () => awaitResult($manager->handle('/v1/grants', command($clock, 1, 'PC-A', $pair + 1))), 409);
        expectError(fn () => awaitResult($manager->handle('/v1/support/grants', supportCommand($clock, 2, $support + 1))), 409);
        eq(array_column($directory->calls, 'action'), ['health']);
        eq($directory->pcs, ['OLD-PC']);
    }
});

test('configured custom durations retain their monotonic deadline through lookup and clock rollback', function (): void {
    foreach ([false => 90, true => 70] as $support => $ttl) {
        $support = (bool) $support;
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 90, 'supportDurationSeconds' => 70]);
        $directory->lookupHold = new Deferred();
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $body = durationBody($clock, 1, $ttl, $support);
        $pending = $manager->handle($path, $body);
        $clock->mono += 20;
        $clock->wall -= 1000;
        $directory->lookupHold->resolve(['userId' => $directory->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
        $result = awaitResult($pending);
        eq($result['status'], 'granted');
        eq($result['expires_at'], $body['expires_at']);
        $clock->mono += $ttl - 21; $manager->tick();
        eq($manager->status()['active_grants'], 1);
        $clock->mono += 1; $manager->tick();
        eq($directory->pcs, ['2FA-BLOCK']);
        eq($manager->status()['active_grants'], 0);
    }
});

test('lookup crossing a configured custom deadline cannot start a late AD grant after clock rollback', function (): void {
    foreach ([false => 90, true => 70] as $support => $ttl) {
        $support = (bool) $support;
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 90, 'supportDurationSeconds' => 70]);
        $directory->lookupHold = new Deferred();
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $pending = $manager->handle($path, durationBody($clock, 1, $ttl, $support));
        $clock->mono += $ttl + 1;
        $clock->wall -= 1000;
        $directory->lookupHold->resolve(['userId' => $directory->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
        expectError(fn () => awaitResult($pending), 409);
        eq(array_column($directory->calls, 'action'), ['health', 'resolve']);
        eq($directory->pcs, ['OLD-PC']);
    }
});

test('a slow AD write crossing a configured custom deadline returns failure and is cleaned', function (): void {
    foreach ([false => 90, true => 70] as $support => $ttl) {
        $support = (bool) $support;
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 90, 'supportDurationSeconds' => 70]);
        $directory->hold = new Deferred();
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $pending = $manager->handle($path, durationBody($clock, 1, $ttl, $support));
        $clock->mono += $ttl + 1;
        $clock->wall -= 1000;
        $directory->hold->resolve(['excluded' => false]);
        expectError(fn () => awaitResult($pending), 409);
        eq($directory->pcs, ['2FA-BLOCK']);
        eq($manager->status()['active_grants'], 0);
        eq($manager->status()['pending_cleanup'], 0);
    }
});

test('replaying a command under custom duration settings cannot restart its timer', function (): void {
    foreach ([false => 90, true => 70] as $support => $ttl) {
        $support = (bool) $support;
        [$manager, $directory, $clock] = fixture(['grantDurationSeconds' => 90, 'supportDurationSeconds' => 70]);
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $body = durationBody($clock, 1, $ttl, $support);
        awaitResult($manager->handle($path, $body));
        $clock->advance(20);
        $calls = $directory->calls;
        $result = awaitResult($manager->handle($path, $body));
        eq($result['status'], 'already_processed');
        eq($result['expires_at'], $body['expires_at']);
        eq($directory->calls, $calls);
        $clock->advance($ttl - 20); $manager->tick();
        eq($directory->pcs, ['2FA-BLOCK']);
        eq($manager->status()['active_grants'], 0);
    }
});

test('signed HTTP status advertises the configured durations without querying AD', function (): void {
    $overrides = ['grantDurationSeconds' => 600, 'supportDurationSeconds' => 180];
    [$manager, $directory] = fixture($overrides);
    $config = testConfig($overrides);
    $server = new HttpServer($config, [$manager, 'handle']);
    $request = transportRequest($config);
    $calls = $directory->calls;
    $response = awaitResult($server->handle($request));
    eq($response->getStatusCode(), 200);
    $body = (string) $response->getBody();
    $decoded = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
    eq($decoded['ok'], true);
    eq($decoded['result']['grant_duration_seconds'], 600);
    eq($decoded['result']['support_duration_seconds'], 180);
    eq($decoded['result']['capabilities'], ['support_all_v1']);
    eq($directory->calls, $calls);
    eq($response->getHeaderLine('X-2FA-Agent-Id'), $config->get('agentId'));
    eq($response->getHeaderLine('X-2FA-Response-Signature'), Auth::responseSignature(
        hex2bin($config->get('apiSecretHex')), $config->get('agentId'),
        $request->getHeaderLine('X-2FA-Nonce'), 200, $body));
});
