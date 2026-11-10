<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/core.php';
require_once __DIR__ . '/transport.php';
require_once __DIR__ . '/support.php';

use React\Promise\Deferred;

function retryRevokeBody(FakeClock $clock, int $sequence = 2, bool $support = false): array
{
    $body = $support ? supportCommand($clock, $sequence) : command($clock, $sequence);
    unset($body['expires_at']);
    return $body;
}

function retryWriteCalls(FakeDirectory $directory): array
{
    return array_values(array_filter(array_column($directory->calls, 'action'),
        static fn (string $action): bool => in_array($action, ['grant', 'revoke', 'support-grant', 'support-revoke', 'expire'], true)));
}

test('failed pair revoke retries the identical UUID after internal cleanup and then replays without writes', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    eq($manager->status()['pending_cleanup'], 0);
    eq(in_array('PC-A', $directory->pcs, true), false);

    $result = awaitResult($manager->handle('/v1/revocations', $body));
    eq($result['status'], 'revoked');
    eq($result['request_id'], $body['request_id']);
    eq($result['sequence'], $body['sequence']);
    $writes = retryWriteCalls($directory);
    $replay = awaitResult($manager->handle('/v1/revocations', $body));
    eq($replay['status'], 'already_processed');
    eq($replay['original_status'], 'revoked');
    eq(retryWriteCalls($directory), $writes);
});

test('failed support revoke retries the identical UUID after whole-user cleanup', function (): void {
    [$manager, $directory, $clock] = fixture();
    supportGrant($manager, $clock, 1);
    $directory->fail['support-revoke'] = 1;
    $body = retryRevokeBody($clock, 2, true);
    expectError(fn () => awaitResult($manager->handle('/v1/support/revocations', $body)), 503);
    eq($directory->pcs, ['2FA-BLOCK']);
    eq($manager->status()['pending_cleanup'], 0);

    $result = awaitResult($manager->handle('/v1/support/revocations', $body));
    eq($result['status'], 'revoked');
    eq($result['scope'], 'support_all');
    eq($result['sequence'], 2);
    eq($manager->status()['active_support_grants'], 0);
});

test('an unresolved failed revoke remains retryable after the ten minute result window', function (): void {
    foreach ([false, true] as $support) {
        [$manager, $directory, $clock] = fixture();
        $support ? supportGrant($manager, $clock, 1) : grant($manager, $clock, 1);
        $action = $support ? 'support-revoke' : 'revoke';
        $path = $support ? '/v1/support/revocations' : '/v1/revocations';
        $directory->fail[$action] = 1;
        $body = retryRevokeBody($clock, 2, $support);
        expectError(fn () => awaitResult($manager->handle($path, $body)), 503);
        $clock->advance(601);
        $manager->tick();
        eq(awaitResult($manager->handle($path, $body))['status'], 'revoked');
    }
});

test('a second temporary failure does not consume the only permitted revoke retry', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $body = retryRevokeBody($clock);
    foreach ([1, 2] as $attempt) {
        $directory->fail['revoke'] = 1;
        expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
        eq($manager->status()['pending_cleanup'], 0);
    }
    eq(awaitResult($manager->handle('/v1/revocations', $body))['status'], 'revoked');
});

test('the same revoke can recover while its earlier automatic cleanup is still pending', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 2;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    eq($manager->status()['pending_cleanup'], 1);
    eq(awaitResult($manager->handle('/v1/revocations', $body))['status'], 'revoked');
    eq($manager->status()['pending_cleanup'], 0);
    eq($manager->status()['active_grants'], 0);
});

test('an old failed pair revoke cannot remove a newer grant of the same computer', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    grant($manager, $clock, 3);
    $before = $directory->pcs;
    $writes = retryWriteCalls($directory);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 409);
    eq($directory->pcs, $before);
    eq(retryWriteCalls($directory), $writes);
    eq($manager->status()['active_grants'], 1);
});

test('failed revoke retry respects the shared high-water across support and pair modes', function (): void {
    foreach ([false, true] as $support) {
        [$manager, $directory, $clock] = fixture();
        $support ? supportGrant($manager, $clock, 1) : grant($manager, $clock, 1);
        $action = $support ? 'support-revoke' : 'revoke';
        $path = $support ? '/v1/support/revocations' : '/v1/revocations';
        $directory->fail[$action] = 1;
        $body = retryRevokeBody($clock, 2, $support);
        expectError(fn () => awaitResult($manager->handle($path, $body)), 503);
        $support ? grant($manager, $clock, 3) : supportGrant($manager, $clock, 3);
        $before = $directory->pcs;
        $writes = retryWriteCalls($directory);
        expectError(fn () => awaitResult($manager->handle($path, $body)), 409);
        eq($directory->pcs, $before);
        eq(retryWriteCalls($directory), $writes);
        eq($manager->status()['active_grants'], 1);
    }
});

test('failed revoke UUID still rejects changes to fields or endpoint before directory lookup', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    $calls = $directory->calls;
    foreach ([['computer' => 'PC-B'], ['login' => 'another-user'], ['sequence' => 3]] as $change) {
        expectError(fn () => awaitResult($manager->handle('/v1/revocations', array_replace($body, $change))), 409);
    }
    expectError(fn () => awaitResult($manager->handle('/v1/support/revocations', retryRevokeBody($clock, 2, true))), 409);
    eq($directory->calls, $calls);
});

test('a different UUID cannot use equal sequence as a failed revoke retry', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    $body['request_id'] = '99999999-9999-4999-8999-999999999999';
    $writes = retryWriteCalls($directory);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 409);
    eq(retryWriteCalls($directory), $writes);
});

test('a reassigned login cannot direct an old failed revoke to another user GUID', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    $directory->id = '22222222-2222-4222-8222-222222222222';
    $directory->pcs = ['PC-A'];
    $writes = retryWriteCalls($directory);
    foreach ([false, true] as $excluded) {
        $directory->excluded = $excluded;
        expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 409);
        eq($directory->pcs, ['PC-A']);
        eq(retryWriteCalls($directory), $writes);
    }
});

test('failed revoke retries remain disabled after local bulk disable', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    eq(awaitResult($manager->handleLocal('disable', ['dryRun' => false]))['status'], 'disabled');
    eq($directory->pcs, []);
    $calls = $directory->calls;
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 409);
    eq($directory->calls, $calls);
    eq($directory->pcs, []);
});

test('failed revoke retries cannot bypass a running local bulk operation', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    $held = new Deferred();
    $directory->bulkBatches = [$held];
    $bulk = $manager->handleLocal('enable', ['dryRun' => true]);
    $calls = $directory->calls;
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 409);
    eq($directory->calls, $calls);
    $held->resolve(['dryRun' => true, 'found' => 1, 'changed' => 0, 'excluded' => 0, 'failed' => 0,
                    'complete' => true, 'nextCursor' => null]);
    eq(awaitResult($bulk)['status'], 'preview');
    eq(awaitResult($manager->handle('/v1/revocations', $body))['status'], 'revoked');
});

test('a full command cache permits recovery of an existing failed revoke without admitting a new ID', function (): void {
    [$manager, $directory, $clock] = fixture(['maxRememberedRequests' => 100]);
    $originalUser = $directory->id;
    grant($manager, $clock, 1);
    $directory->fail['revoke'] = 1;
    $body = retryRevokeBody($clock);
    expectError(fn () => awaitResult($manager->handle('/v1/revocations', $body)), 503);
    for ($sequence = 3; $sequence <= 100; ++$sequence) {
        $directory->id = sprintf('22222222-2222-4222-8222-%012d', $sequence);
        eq(revoke($manager, $clock, $sequence)['status'], 'revoked');
    }
    $directory->id = $originalUser;
    eq(awaitResult($manager->handle('/v1/revocations', $body))['status'], 'revoked');
    $calls = $directory->calls;
    expectError(fn () => revoke($manager, $clock, 101), 503);
    eq($directory->calls, $calls);
});

test('cached failed grants remain non-retryable and never reopen access', function (): void {
    foreach ([false, true] as $support) {
        [$manager, $directory, $clock] = fixture();
        $action = $support ? 'support-grant' : 'grant';
        $path = $support ? '/v1/support/grants' : '/v1/grants';
        $body = $support ? supportCommand($clock, 1) : command($clock, 1);
        $directory->fail[$action] = 1;
        expectError(fn () => awaitResult($manager->handle($path, $body)), 503);
        eq($directory->pcs, ['2FA-BLOCK']);
        $calls = $directory->calls;
        expectError(fn () => awaitResult($manager->handle($path, $body)), 503);
        eq($directory->calls, $calls);
        eq($manager->status()['active_grants'], 0);
    }
});
