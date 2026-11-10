<?php
declare(strict_types=1);

use React\Promise\Deferred;
use TwoFactorAgent\Auth;
use TwoFactorAgent\GrantManager;
use TwoFactorAgent\HttpServer;

function supportCommand(FakeClock $clock, int $sequence, int $ttl = 60): array
{
    $body = command($clock, $sequence, 'UNUSED', $ttl);
    unset($body['computer']);
    return $body;
}
function supportGrant(GrantManager $manager, FakeClock $clock, int $sequence, int $ttl = 60): array
{
    return awaitResult($manager->handle('/v1/support/grants', supportCommand($clock, $sequence, $ttl)));
}
function supportRevoke(GrantManager $manager, FakeClock $clock, int $sequence): array
{
    $body = supportCommand($clock, $sequence);
    unset($body['expires_at']);
    return awaitResult($manager->handle('/v1/support/revocations', $body));
}

test('support capability is explicit and counters include both independent lease types', function (): void {
    [$m, $d, $c] = fixture();
    eq($m->status()['capabilities'], ['support_all_v1']);
    eq($m->status()['active_support_grants'], 0);
    grant($m, $c, 1);
    $d->id = '22222222-2222-4222-8222-222222222222';
    supportGrant($m, $c, 2);
    eq($m->status()['active_support_grants'], 1);
    eq($m->status()['active_grants'], 2);
});
test('support clears workstation restrictions for sixty seconds then restores only the deny baseline', function (): void {
    [$m, $d, $c] = fixture();
    $result = supportGrant($m, $c, 1);
    eq($result['scope'], 'support_all');
    eq($result['status'], 'granted');
    eq(isset($result['computer']), false);
    eq($result['expires_at'], supportCommand($c, 1)['expires_at']);
    eq($d->pcs, []);
    $c->advance(59); $m->tick(); eq($d->pcs, []);
    $c->advance(1); $m->tick(); eq($d->pcs, ['2FA-BLOCK']);
    eq($m->status()['active_support_grants'], 0);
});
test('support refuses expired or greater-than-sixty-second requests before directory writes', function (): void {
    [$m, $d, $c] = fixture();
    foreach ([0, -1, 61, 300] as $ttl) {
        expectError(fn () => supportGrant($m, $c, 1, $ttl), 409);
    }
    eq(array_column($d->calls, 'action'), ['health']);
    eq($d->pcs, ['OLD-PC']);
});
test('support and pair endpoints reject each others body and any caller-supplied scope', function (): void {
    [$m, $d, $c] = fixture();
    expectError(fn () => awaitResult($m->handle('/v1/support/grants', command($c, 1, 'PC-A', 60))), 400);
    expectError(fn () => awaitResult($m->handle('/v1/grants', supportCommand($c, 1))), 400);
    expectError(fn () => awaitResult($m->handle('/v1/support/grants', supportCommand($c, 1) + ['scope' => 'pair'])), 400);
    expectError(fn () => awaitResult($m->handle('/v1/support/revocations', supportCommand($c, 1))), 400);
    eq(array_column($d->calls, 'action'), ['health']);
});
test('support early revoke confirms the baseline and cancels its old timer', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1);
    $result = supportRevoke($m, $c, 2);
    eq($result['status'], 'revoked'); eq($result['scope'], 'support_all'); eq($result['expires_at'], null);
    eq($d->pcs, ['2FA-BLOCK']); eq($m->status()['active_support_grants'], 0);
    $before = count($d->calls); $c->advance(60); $m->tick(); eq(count($d->calls), $before);
});
test('support revoke on a fallback instance works without its own timer', function (): void {
    [$m, $d, $c] = fixture(); $d->pcs = [];
    eq(supportRevoke($m, $c, 1)['status'], 'revoked'); eq($d->pcs, ['2FA-BLOCK']);
});
test('support replay is idempotent does not extend the deadline and reports inactive after expiry', function (): void {
    [$m, $d, $c] = fixture(); $body = supportCommand($c, 1);
    awaitResult($m->handle('/v1/support/grants', $body));
    $before = count($d->calls); $c->advance(30);
    $replay = awaitResult($m->handle('/v1/support/grants', $body));
    eq($replay['original_status'], 'granted'); eq($replay['currently_active'], true);
    eq($replay['expires_at'], $body['expires_at']); eq(count($d->calls), $before);
    $c->advance(30); $m->tick(); eq($d->pcs, ['2FA-BLOCK']);
    eq(awaitResult($m->handle('/v1/support/grants', $body))['currently_active'], false);
});
test('new support renewal replaces the old deadline without an old timer clearing it', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1);
    $c->advance(30); supportGrant($m, $c, 2); $c->advance(30); $m->tick();
    eq($d->pcs, []); eq($m->status()['active_support_grants'], 1);
    $c->advance(30); $m->tick(); eq($d->pcs, ['2FA-BLOCK']);
});
test('pair and support never overlap and opposite-scope revokes cannot overwrite a live lease', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1);
    expectError(fn () => grant($m, $c, 2), 409);
    expectError(fn () => revoke($m, $c, 3), 409);
    eq($d->pcs, []); supportRevoke($m, $c, 4); grant($m, $c, 5);
    $before = $d->pcs;
    expectError(fn () => supportGrant($m, $c, 6), 409);
    expectError(fn () => supportRevoke($m, $c, 7), 409);
    eq($d->pcs, $before);
});
test('shared sequence rejects an old support revoke after a later ordinary grant', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 10); supportRevoke($m, $c, 20); grant($m, $c, 30);
    expectError(fn () => supportRevoke($m, $c, 15), 409);
    eq(in_array('PC-A', $d->pcs, true), true);
    revoke($m, $c, 40);
    expectError(fn () => supportGrant($m, $c, 25), 409);
});
test('same UUID cannot be replayed against a different scope endpoint', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1);
    expectError(fn () => grant($m, $c, 1, 'PC-A', 60), 409);
    expectError(fn () => supportRevoke($m, $c, 1), 409);
    eq($d->pcs, []);
});
test('a support revocation that arrives first suppresses a delayed support grant', function (): void {
    [$m, $d, $c] = fixture(); supportRevoke($m, $c, 2);
    expectError(fn () => supportGrant($m, $c, 1), 409); eq($d->pcs, ['2FA-BLOCK']);
});
test('support expiry failure remains pending and blocks new access until baseline is confirmed', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1); $d->fail['expire'] = 1;
    $c->advance(60); $m->tick(); eq($m->status()['pending_cleanup'], 1); eq($d->pcs, []);
    expectError(fn () => supportGrant($m, $c, 2), 409);
    expectError(fn () => grant($m, $c, 3), 409);
    $c->advance(5); $m->tick(); eq($d->pcs, ['2FA-BLOCK']); eq($m->status()['pending_cleanup'], 0);
    eq(grant($m, $c, 4)['status'], 'granted');
});
test('unconfirmed support grant and revoke schedule whole-user cleanup instead of false success', function (): void {
    [$m, $d, $c] = fixture(); $d->fail['support-grant'] = 1;
    expectError(fn () => supportGrant($m, $c, 1), 503); eq($d->pcs, ['2FA-BLOCK']);
    supportGrant($m, $c, 2); $d->fail['support-revoke'] = 1;
    expectError(fn () => supportRevoke($m, $c, 3), 503); eq($d->pcs, ['2FA-BLOCK']);
    eq($m->status()['active_support_grants'], 0);
});
test('support write that crosses expiry never reports granted and is cleaned immediately', function (): void {
    [$m, $d, $c] = fixture(); $d->hold = new Deferred();
    $pending = $m->handle('/v1/support/grants', supportCommand($c, 1));
    $c->advance(61); $d->hold->resolve(['excluded' => false]);
    expectError(fn () => awaitResult($pending), 409); eq($d->pcs, ['2FA-BLOCK']);
});
test('support expiry during a stalled lookup prevents any grant write', function (): void {
    [$m, $d, $c] = fixture(); $d->lookupHold = new Deferred();
    $pending = $m->handle('/v1/support/grants', supportCommand($c, 1));
    $c->advance(61);
    $d->lookupHold->resolve(['userId' => $d->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
    expectError(fn () => awaitResult($pending), 409);
    eq(in_array('support-grant', array_column($d->calls, 'action'), true), false); eq($d->pcs, ['OLD-PC']);
});
test('support monotonic expiry survives wall clock rollback during directory lookup', function (): void {
    [$m, $d, $c] = fixture(); $d->lookupHold = new Deferred();
    $pending = $m->handle('/v1/support/grants', supportCommand($c, 1));
    $c->mono += 20; $c->wall -= 1000;
    $d->lookupHold->resolve(['userId' => $d->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
    eq(awaitResult($pending)['status'], 'granted');
    $c->mono += 40; $m->tick(); eq($d->pcs, ['2FA-BLOCK']);
});
test('support respects exclusions on lookup on write and on expiry', function (): void {
    [$m, $d, $c] = fixture(); $d->excluded = true;
    eq(supportGrant($m, $c, 1)['status'], 'excluded'); eq($d->pcs, ['OLD-PC']);
    $d->excluded = false; $d->excludeDuringWrite = true;
    eq(supportGrant($m, $c, 2)['status'], 'excluded'); eq($d->pcs, ['OLD-PC']);
    $d->excludeDuringWrite = false; supportGrant($m, $c, 3); $d->excluded = true;
    $c->advance(60); $m->tick(); eq($d->pcs, []); eq($m->status()['active_support_grants'], 0);
});
test('bulk disable cancels support timers and late revokes never reinstall the stub', function (): void {
    [$m, $d, $c] = fixture(); supportGrant($m, $c, 1);
    eq(awaitResult($m->handleLocal('disable', ['dryRun' => false]))['status'], 'disabled');
    $before = count($d->calls);
    expectError(fn () => supportRevoke($m, $c, 2), 409);
    expectError(fn () => revoke($m, $c, 3), 409);
    eq(count($d->calls), $before); $c->advance(60); $m->tick(); eq($d->pcs, []);
});
test('failed bulk disable does not claim cleanup success or let a late revoke reinstall the stub', function (): void {
    [$m, $d, $c] = fixture(); grant($m, $c, 1); $d->fail['bulk-disable'] = 1;
    expectError(fn () => awaitResult($m->handleLocal('disable', ['dryRun' => false])), 503);
    $before = $d->pcs;
    expectError(fn () => supportRevoke($m, $c, 2), 409);
    expectError(fn () => revoke($m, $c, 3), 409);
    eq($d->pcs, $before); eq($m->status()['enabled'], false);
    eq($m->status()['last_directory_error'], 'bulk_unconfirmed');
});
test('support uses existing mobile HMAC and signed responses while endpoint substitution fails', function (): void {
    [$m, $d, $c] = fixture(); $config = transportConfig();
    $server = new HttpServer($config, fn ($path, $body) => $m->handle($path, $body));
    $body = json_encode(supportCommand($c, 1), JSON_THROW_ON_ERROR);
    $request = transportRequest($config, '/v1/support/grants', $body);
    $response = awaitResult($server->handle($request));
    eq($response->getStatusCode(), 200);
    $decoded = json_decode((string) $response->getBody(), true, 16, JSON_THROW_ON_ERROR);
    eq($decoded['result']['scope'], 'support_all');
    eq($response->getHeaderLine('X-2FA-Response-Signature'), Auth::responseSignature(
        hex2bin($config->get('apiSecretHex')), $config->get('agentId'), $request->getHeaderLine('X-2FA-Nonce'),
        200, (string) $response->getBody(),
    ));
    $ordinary = transportRequest($config, '/v1/grants', $body);
    $tampered = $ordinary->withUri($ordinary->getUri()->withPath('/v1/support/grants'));
    eq(awaitResult($server->handle($tampered))->getStatusCode(), 401);
    $status = awaitResult($server->handle(transportRequest($config)));
    eq(json_decode((string) $status->getBody(), true)['result']['capabilities'], ['support_all_v1']);
    eq($status->getHeaderLine('X-2FA-Agent-Id'), 'dc1');
});
