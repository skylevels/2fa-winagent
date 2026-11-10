<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use TwoFactorAgent\DirectoryGateway;
use TwoFactorAgent\GrantManager;
use React\Promise\PromiseInterface;
use React\Promise\Deferred;
use function React\Promise\resolve;
use function React\Promise\reject;

final class FakeDirectory implements DirectoryGateway
{
    public array $pcs = ['OLD-PC'];
    public array $calls = [];
    public array $fail = [];
    public bool $excluded = false;
    public bool $missingGroup = false;
    public bool $excludeDuringWrite = false;
    public bool $partial = false;
    public array $bulkBatches = [];
    public ?Deferred $hold = null;
    public ?Deferred $lookupHold = null;
    public bool $userMissing = false;
    public string $id = '11111111-1111-4111-8111-111111111111';
    public function execute(array $request): PromiseInterface
    {
        $this->calls[] = $request;
        $action = $request['action'];
        if (($this->fail[$action] ?? 0) > 0) {
            --$this->fail[$action];
            return reject(new RuntimeException('Fake AD unavailable.', 503));
        }
        if ($action === 'health') {
            return $this->missingGroup ? reject(new RuntimeException('No group.', 503)) : resolve([]);
        }
        if ($action === 'ensure-bypass') { $this->missingGroup = false; return resolve([]); }
        $user = ['userId' => $this->id, 'login' => 'ivanov-dd', 'excluded' => $this->excluded, 'reason' => 'bypass'];
        if ($action === 'resolve') {
            if ($this->userMissing) { return reject(new RuntimeException('Fake user not found.', 404)); }
            return $this->lookupHold !== null ? $this->lookupHold->promise() : resolve($user);
        }
        if ($this->excludeDuringWrite) { $user['excluded'] = true; }
        if ($user['excluded']) { return resolve($user + ['changed' => false]); }
        if (str_starts_with($action, 'bulk-')) {
            if ($this->bulkBatches !== []) {
                $batch = array_shift($this->bulkBatches);
                return $batch instanceof Deferred ? $batch->promise() : resolve($batch);
            }
            if (!$request['dryRun']) { $this->pcs = $action === 'bulk-disable' ? [] : array_values(array_unique([...$this->pcs, '2FA-BLOCK'])); }
            return resolve(['dryRun' => $request['dryRun'], 'found' => 1, 'changed' => 1, 'excluded' => 0, 'failed' => $this->partial ? 1 : 0]);
        }
        if ($action === 'grant' || $action === 'support-grant') {
            $this->pcs = $action === 'support-grant' ? [] : array_values(array_unique([...$this->pcs, $request['computer']]));
            if ($this->hold !== null) { return $this->hold->promise(); }
        } elseif ($action === 'revoke') {
            $this->pcs = array_values(array_unique([...array_diff($this->pcs, [$request['computer']]), '2FA-BLOCK']));
        } elseif ($action === 'expire' || $action === 'support-revoke') { $this->pcs = ['2FA-BLOCK']; }
        return resolve($user + ['changed' => true]);
    }
}
final class FakeClock { public float $wall = 1800000000; public float $mono = 100; public function advance(float $n): void { $this->wall += $n; $this->mono += $n; } }
function fixture(array $config = []): array
{
    $clock = new FakeClock(); $directory = new FakeDirectory();
    $manager = new GrantManager(testConfig($config), $directory, fn () => $clock->wall, fn () => $clock->mono);
    awaitResult($manager->initialize());
    return [$manager, $directory, $clock];
}
function command(FakeClock $clock, int $sequence, string $pc = 'PC-A', int $ttl = 300): array
{
    return ['request_id' => sprintf('00000000-0000-4000-8000-%012d', $sequence), 'sequence' => $sequence,
        'login' => 'ivanov-dd', 'computer' => $pc, 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', (int) $clock->wall + $ttl)];
}
function grant(GrantManager $m, FakeClock $c, int $seq, string $pc = 'PC-A', int $ttl = 300): array
{ return awaitResult($m->handle('/v1/grants', command($c, $seq, $pc, $ttl))); }
function revoke(GrantManager $m, FakeClock $c, int $seq, string $pc = 'PC-A'): array
{ $body = command($c, $seq, $pc); unset($body['expires_at']); return awaitResult($m->handle('/v1/revocations', $body)); }

test('grant appends and expiry removes all PCs including original entries', function (): void {
    [$m,$d,$c] = fixture(); eq(grant($m,$c,1)['status'], 'granted'); eq($d->pcs, ['OLD-PC','PC-A']);
    $c->advance(300); $m->tick(); eq($d->pcs, ['2FA-BLOCK']); eq($m->status()['active_grants'], 0);
});
test('renewal changes only this pair deadline and old timer does not fire', function (): void {
    [$m,$d,$c] = fixture(); grant($m,$c,1); $c->advance(200); grant($m,$c,2);
    $c->advance(100); $m->tick(); eq(in_array('PC-A',$d->pcs), true);
    $c->advance(200); $m->tick(); eq($d->pcs, ['2FA-BLOCK']);
});
test('first expiring pair clears all user grants and remaining local timers', function (): void {
    [$m,$d,$c] = fixture(); grant($m,$c,1,'PC-A',100); grant($m,$c,2,'PC-B',200);
    $c->advance(100); $m->tick(); eq($d->pcs, ['2FA-BLOCK']); eq($m->status()['active_grants'],0);
    $count=count($d->calls); $c->advance(100); $m->tick(); eq(count($d->calls),$count);
});
test('early revoke removes one pair and its timer but preserves another pair', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1,'PC-A',100); grant($m,$c,2,'PC-B',200); revoke($m,$c,3);
    eq($d->pcs,['OLD-PC','PC-B','2FA-BLOCK']); $c->advance(100); $m->tick(); eq(in_array('PC-B',$d->pcs),true);
});
test('revoke works when this process has no timer for pair', function (): void {
    [$m,$d,$c]=fixture(); $d->pcs=['PC-A','PC-B']; revoke($m,$c,1); eq($d->pcs,['PC-B','2FA-BLOCK']);
});
test('duplicate request does not extend and reports current state after expiry', function (): void {
    [$m,$d,$c]=fixture(); $b=command($c,1); awaitResult($m->handle('/v1/grants',$b));
    $c->advance(10); $r=awaitResult($m->handle('/v1/grants',$b)); eq($r['status'],'already_processed'); eq($r['currently_active'],true);
    $c->advance(290); $m->tick(); $r=awaitResult($m->handle('/v1/grants',$b)); eq($r['currently_active'],false);
});
test('request ID collision and stale out-of-order command rejected', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,2); $b=command($c,2,'PC-B'); expectError(fn()=>awaitResult($m->handle('/v1/grants',$b)),409);
    expectError(fn()=>grant($m,$c,1),409); revoke($m,$c,3); eq(grant($m,$c,2)['currently_active'],false);
});
test('revocation arriving first suppresses old delayed grant', function (): void {
    [$m,$d,$c]=fixture(); revoke($m,$c,2); expectError(fn()=>grant($m,$c,1),409); eq(in_array('PC-A',$d->pcs),false);
});
test('sequence survives ten minute result eviction', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,2); $c->advance(601); $m->tick();
    expectError(fn()=>grant($m,$c,1),409); eq(grant($m,$c,3)['status'],'granted');
});
test('expired invalid and overlong requests never write', function (): void {
    [$m,$d,$c]=fixture(); expectError(fn()=>grant($m,$c,1,'PC-A',0),409); expectError(fn()=>grant($m,$c,2,'PC-A',301),409);
    expectError(fn()=>grant($m,$c,3,'2FA-BLOCK'),400); $b=command($c,4); $b['login']='x*)(objectClass=*)';
    expectError(fn()=>awaitResult($m->handle('/v1/grants',$b)),400); eq($d->pcs,['OLD-PC']);
});
test('expired grant in a slow write never returns granted and is cleaned', function (): void {
    [$m,$d,$c]=fixture(); $d->hold=new Deferred(); $failure=null;
    $m->handle('/v1/grants',command($c,1,'PC-A',1))->catch(function($e)use(&$failure){$failure=$e;});
    $c->advance(2); $d->hold->resolve(['excluded'=>false]); eq($failure->getCode(),409); eq($d->pcs,['2FA-BLOCK']);
});
test('uncertain grant triggers whole-user cleanup', function (): void {
    [$m,$d,$c]=fixture(); $d->fail['grant']=1; expectError(fn()=>grant($m,$c,1),503);
    eq($d->pcs,['2FA-BLOCK']); eq($m->status()['pending_cleanup'],0);
});
test('failed expiry is retained retried and blocks renewal until confirmed', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1,'PC-A',1); $d->fail['expire']=1; $c->advance(1); $m->tick();
    eq($m->status()['pending_cleanup'],1); expectError(fn()=>grant($m,$c,2),409);
    $c->advance(5); $m->tick(); eq($d->pcs,['2FA-BLOCK']); eq($m->status()['pending_cleanup'],0);
});
test('failed revoke retries pair only and preserves other grants', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); grant($m,$c,2,'PC-B'); $d->fail['revoke']=1;
    expectError(fn()=>revoke($m,$c,3),503); eq(in_array('PC-B',$d->pcs),true); eq(in_array('PC-A',$d->pcs),false);
});
test('bypass before grant and before expiry leaves directory untouched', function (): void {
    [$m,$d,$c]=fixture(); $d->excluded=true; eq(grant($m,$c,1)['status'],'excluded'); eq($d->pcs,['OLD-PC']);
    $d->excluded=false; grant($m,$c,2,'PC-A',1); $d->excluded=true; $before=$d->pcs;
    $c->advance(1); $m->tick(); eq($d->pcs,$before); eq($m->status()['active_grants'],0);
});
test('membership changes during lookup-write gap are honored', function (): void {
    [$m,$d,$c]=fixture(); $d->excludeDuringWrite=true; eq(grant($m,$c,1)['status'],'excluded'); eq($d->pcs,['OLD-PC']);
});
test('bulk previews do not change mode or timers', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); $before=$d->pcs; eq(awaitResult($m->handleLocal('disable',[]))['status'],'preview');
    eq($m->status()['enabled'],true); eq($m->status()['active_grants'],1); eq($d->pcs,$before);
});
test('bulk disable clears timers and prevents delayed reinstallation of stub', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); awaitResult($m->handleLocal('disable',['dryRun'=>false]));
    eq($d->pcs,[]); eq($m->status()['enabled'],false); $c->advance(500); $m->tick(); eq($d->pcs,[]);
    expectError(fn()=>grant($m,$c,2),409);
    awaitResult($m->handleLocal('enable',['dryRun'=>false])); eq($d->pcs,['2FA-BLOCK']); eq(grant($m,$c,3)['status'],'granted');
});
test('failed bulk disable still cancels local timers and exposes failure', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); $d->fail['bulk-disable']=1;
    expectError(fn()=>awaitResult($m->handleLocal('disable',['dryRun'=>false])),503);
    eq($m->status()['active_grants'],0); eq($m->status()['enabled'],false); eq($m->status()['last_directory_error'],'bulk_unconfirmed');
});
test('partial bulk is explicit', function (): void {
    [$m,$d,$c]=fixture(); $d->partial=true; eq(awaitResult($m->handleLocal('disable',['dryRun'=>false]))['status'],'partial');
});
test('monotonic deadline survives wall clock going backwards', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); $c->mono+=300; $c->wall-=1000; $m->tick(); eq($d->pcs,['2FA-BLOCK']);
});
test('not-ready startup allows explicit group creation then grants', function (): void {
    [$m,$d,$c]=fixture(); $d->missingGroup=true; awaitResult($m->initialize()); eq($m->status()['ready'],false);
    expectError(fn()=>grant($m,$c,1),503); awaitResult($m->handleLocal('ensure-bypass',['dryRun'=>false]));
    eq($m->status()['ready'],true); eq(grant($m,$c,2)['status'],'granted');
});
test('restart intentionally forgets timers and does not pretend to recover AD', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1); $m2=new GrantManager(testConfig(),$d,fn()=>$c->wall,fn()=>$c->mono);
    awaitResult($m2->initialize()); $c->advance(300); $m2->tick(); eq(in_array('PC-A',$d->pcs),true); eq($m2->status()['active_grants'],0);
});
test('queue serializes revoke after a delayed grant write', function (): void {
    [$m,$d,$c]=fixture(); $d->hold=new Deferred(); $p=$m->handle('/v1/grants',command($c,1));
    $b=command($c,2); unset($b['expires_at']); $q=$m->handle('/v1/revocations',$b); eq($m->status()['queued_requests'],1);
    $d->hold->resolve(['excluded'=>false]); eq(awaitResult($p)['status'],'granted'); eq(awaitResult($q)['status'],'revoked'); eq($d->pcs,['OLD-PC','2FA-BLOCK']);
});

test('bulk yields to expiry between batches and aggregates counts', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1,'PC-A',1);
    $first=new Deferred();
    $summary=['dryRun'=>false,'found'=>10,'changed'=>8,'excluded'=>2,'failed'=>0,'errors'=>[], 'complete'=>true,'nextCursor'=>null];
    $d->bulkBatches=[$first,$summary];
    $p=$m->handleLocal('enable',['dryRun'=>false]); eq($m->status()['bulk_running'],true);
    $c->advance(2); $first->resolve(array_replace($summary,['complete'=>false,'nextCursor'=>$d->id]));
    $r=awaitResult($p); eq($r['summary']['found'],20); eq($r['summary']['excluded'],4);
    $actions=array_column($d->calls,'action'); eq(array_slice($actions,-3),['bulk-enable','expire','bulk-enable']);
    eq($m->status()['bulk_running'],false);
});
test('disable takes priority over overdue cleanup after an in-flight grant', function (): void {
    [$m,$d,$c]=fixture(); grant($m,$c,1,'PC-A',1); $d->hold=new Deferred();
    $p=$m->handle('/v1/grants',command($c,2,'PC-B')); $q=$m->handleLocal('disable',['dryRun'=>false]);
    $c->advance(2); $d->hold->resolve(['excluded'=>false]); awaitResult($p); eq(awaitResult($q)['status'],'disabled');
    eq(in_array('expire',array_column($d->calls,'action')),false); eq($d->pcs,[]);
});
test('bulk rejects concurrent new grants while allowing status', function (): void {
    [$m,$d,$c]=fixture(); $first=new Deferred(); $d->bulkBatches=[$first];
    $p=$m->handleLocal('enable',['dryRun'=>false]); $q=$m->handle('/v1/grants',command($c,1));
    expectError(fn()=>awaitResult($q),409);
    eq(awaitResult($m->handle('/v1/status',[]))['bulk_running'],true);
    $first->resolve(['dryRun'=>false,'found'=>1,'changed'=>1,'excluded'=>0,'failed'=>0,'errors'=>[], 'complete'=>false,'nextCursor'=>$d->id]);
    expectError(fn()=>awaitResult($q),409); eq(awaitResult($p)['status'],'enabled');
});
test('null dryRun cannot accidentally perform an admin operation', function (): void {
    [$m,$d,$c]=fixture(); expectError(fn()=>awaitResult($m->handleLocal('disable',['dryRun'=>null])),400);
    eq($m->status()['enabled'],true);
});


test('HTTP dispatcher refuses local commands and obsolete administrative endpoints', function (): void {
    [$manager, $directory, $clock] = fixture();
    grant($manager, $clock, 1);
    $before = $directory->pcs;
    foreach (['enable', 'disable', 'ensure-bypass'] as $command) {
        foreach (['/v1/admin/' . $command, 'local:' . $command] as $path) {
            expectError(fn () => awaitResult($manager->handle($path, ['dryRun' => false])), 404);
        }
    }
    eq($directory->pcs, $before);
    eq($manager->status()['active_grants'], 1);
    eq($manager->status()['enabled'], true);
    eq(awaitResult($manager->handleLocal('status', []))['active_grants'], 1);
});

test('a missing login does not mark a healthy directory unavailable', function (): void {
    [$manager, $directory, $clock] = fixture();
    $directory->userMissing = true;
    expectError(fn () => grant($manager, $clock, 1), 404);
    eq($manager->status()['ready'], true);
    eq($manager->status()['last_directory_error'], null);
    $directory->userMissing = false;
    eq(grant($manager, $clock, 2)['status'], 'granted');
    eq(count(array_filter(array_column($directory->calls, 'action'), fn ($action) => $action === 'health')), 1);
});

test('clock rollback during directory lookup cannot extend the original five minute deadline', function (): void {
    [$manager, $directory, $clock] = fixture();
    $directory->lookupHold = new Deferred();
    $pending = $manager->handle('/v1/grants', command($clock, 1));
    $clock->mono += 100;
    $clock->wall -= 1000;
    $directory->lookupHold->resolve(['userId' => $directory->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
    eq(awaitResult($pending)['status'], 'granted');
    $clock->mono += 200;
    $manager->tick();
    eq($directory->pcs, ['2FA-BLOCK']);
    eq($manager->status()['active_grants'], 0);
});

test('a grant that expires during lookup never writes even if the wall clock rolled back', function (): void {
    [$manager, $directory, $clock] = fixture();
    $directory->lookupHold = new Deferred();
    $pending = $manager->handle('/v1/grants', command($clock, 1, 'PC-A', 1));
    $clock->mono += 2;
    $clock->wall -= 1000;
    $directory->lookupHold->resolve(['userId' => $directory->id, 'login' => 'ivanov-dd', 'excluded' => false, 'reason' => null]);
    expectError(fn () => awaitResult($pending), 409);
    eq($directory->pcs, ['OLD-PC']);
    eq(in_array('grant', array_column($directory->calls, 'action')), false);
});

test('queued HTTP revoke times out while the active directory write is still running', function (): void {
    [$manager, $directory, $clock] = fixture(['queueWaitTimeoutSeconds' => 2]);
    $directory->hold = new Deferred();
    $active = $manager->handle('/v1/grants', command($clock, 1));
    $body = command($clock, 2); unset($body['expires_at']);
    $waiting = $manager->handle('/v1/revocations', $body);
    $clock->advance(3); $manager->tick();
    expectError(fn () => awaitResult($waiting), 503);
    eq($manager->status()['queued_requests'], 0);
    eq(in_array('revoke', array_column($directory->calls, 'action')), false);
    $directory->hold->resolve(['excluded' => false]);
    eq(awaitResult($active)['status'], 'granted');
    eq(in_array('revoke', array_column($directory->calls, 'action')), false);
});

test('local bulk disable remains queued beyond the HTTP waiting limit', function (): void {
    [$manager, $directory, $clock] = fixture(['queueWaitTimeoutSeconds' => 2]);
    $directory->hold = new Deferred();
    $active = $manager->handle('/v1/grants', command($clock, 1));
    $disable = $manager->handleLocal('disable', ['dryRun' => false]);
    $clock->advance(3); $manager->tick();
    eq($manager->status()['queued_requests'], 1);
    $directory->hold->resolve(['excluded' => false]);
    eq(awaitResult($active)['status'], 'granted');
    eq(awaitResult($disable)['status'], 'disabled');
    eq($directory->pcs, []);
    eq($manager->status()['active_grants'], 0);
});

test('malformed HTTP commands are rejected before joining a blocked writer queue', function (): void {
    [$manager, $directory, $clock] = fixture();
    $directory->hold = new Deferred();
    $active = $manager->handle('/v1/grants', command($clock, 1));
    $body = command($clock, 2); unset($body['computer']);
    expectError(fn () => awaitResult($manager->handle('/v1/grants', $body)), 400);
    eq($manager->status()['queued_requests'], 0);
    $directory->hold->resolve(['excluded' => false]);
    eq(awaitResult($active)['status'], 'granted');
});

test('clock rollback while queued cannot extend the submitted grant deadline', function (): void {
    [$manager, $directory, $clock] = fixture(['queueWaitTimeoutSeconds' => 2]);
    $directory->hold = new Deferred();
    $active = $manager->handle('/v1/grants', command($clock, 1));
    $waiting = $manager->handle('/v1/grants', command($clock, 2, 'PC-B', 10));
    $clock->mono += 1;
    $clock->wall -= 100;
    $directory->hold->resolve(['excluded' => false]);
    eq(awaitResult($active)['status'], 'granted');
    eq(awaitResult($waiting)['status'], 'granted');
    $clock->mono += 9;
    $manager->tick();
    eq($directory->pcs, ['2FA-BLOCK']);
});
