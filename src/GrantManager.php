<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use Closure;
use DateTimeImmutable;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use RuntimeException;
use Throwable;
use function React\Promise\reject;
use function React\Promise\resolve;

/** Single local writer. State is deliberately volatile and never reconstructed from AD. */
final class GrantManager
{
    private bool $enabled;
    private bool $ready = false;
    private bool $busy = false;
    private bool $lastWasCleanup = false;
    private ?array $bulk = null;
    private array $queue = [];
    private array $leases = [];
    /** All-workstation support leases are exclusive with ordinary pair leases. */
    private array $supportLeases = [];
    private array $cleanup = [];
    private array $sequences = [];
    private array $commands = [];
    private ?string $lastDirectoryError = null;
    private Closure $wall;
    private Closure $mono;

    public function __construct(
        private readonly Config $config,
        private readonly DirectoryGateway $directory,
        ?callable $wallClock = null,
        ?callable $monotonicClock = null,
        private readonly ?AuditLogger $logger = null,
    ) {
        $this->enabled = $config->get('startEnabled');
        $this->wall = $wallClock === null ? static fn (): float => microtime(true) : Closure::fromCallable($wallClock);
        $this->mono = $monotonicClock === null ? static fn (): float => hrtime(true) / 1e9 : Closure::fromCallable($monotonicClock);
    }

    /** Even an unconfigured AD permits authenticated status and explicit group bootstrap. */
    public function initialize(): PromiseInterface
    {
        return $this->directory->execute(['action' => 'health'])->then(
            function (array $result): void {
                $this->ready = true;
                $this->lastDirectoryError = null;
                $this->logger?->record('directory_ready', ['ready' => true]);
            },
            function (Throwable $error): void {
                $this->ready = false;
                $this->lastDirectoryError = 'directory_not_ready';
                $this->logger?->record('directory_not_ready', ['ready' => false, 'error_code' => 'directory_not_ready']);
            },
        );
    }

    public function handle(string $path, array $payload): PromiseInterface
    {
        foreach ($this->commands as $id => $command) {
            // Preserve a failed revocation's identity while it is the latest
            // command for this user. Otherwise eviction would leave its equal
            // sequence permanently rejected, even after a transient AD fault.
            $latestFailedRevoke = ($command['retry_revoke'] ?? false) === true
                && ($command['sequence'] ?? null) === ($this->sequences[$command['user_id']] ?? null);
            if ($command['until'] <= ($this->mono)() && !$latestFailedRevoke) {
                unset($this->commands[$id]);
            }
        }
        if ($path === '/v1/status') {
            if ($payload !== []) {
                return reject(new RuntimeException('Status accepts an empty object.', 400));
            }
            return resolve($this->status());
        }
        if (!in_array($path, ['/v1/grants', '/v1/revocations', '/v1/support/grants', '/v1/support/revocations'], true)) {
            return reject(new RuntimeException('Unknown endpoint.', 404));
        }
        return $this->enqueue($path, $payload);
    }

    /** Called only by the local Windows administrative transport; never by HTTP. */
    public function handleLocal(string $command, array $payload): PromiseInterface
    {
        if ($command === 'status') {
            return $this->handle('/v1/status', $payload);
        }
        if (!in_array($command, ['enable', 'disable', 'ensure-bypass'], true)) {
            return reject(new RuntimeException('Unknown local command.', 404));
        }
        return $this->enqueue('local:' . $command, $payload);
    }

    private function enqueue(string $path, array $payload): PromiseInterface
    {
        $queueDeadline = null;
        $grantDeadline = null;
        if (!str_starts_with($path, 'local:')) {
            try {
                $grant = str_ends_with($path, '/grants');
                $support = str_starts_with($path, '/v1/support/');
                $this->validateCommand($payload, $grant, $support);
                $queueDeadline = ($this->mono)() + $this->config->get('queueWaitTimeoutSeconds');
                if ($grant && !isset($this->commands[strtolower($payload['request_id'])])) {
                    $grantDeadline = ($this->mono)() + $this->parseExpiry($payload['expires_at'], $this->config->get($support ? 'supportDurationSeconds' : 'grantDurationSeconds')) - ($this->wall)();
                }
            } catch (Throwable $error) {
                return reject($error);
            }
        }
        if ($this->bulk !== null) {
            return reject(new RuntimeException('A bulk operation is in progress; retry after completion.', 409));
        }
        if (count($this->queue) >= $this->config->get('maxPendingRequests')) {
            return reject(new RuntimeException('Command queue is full.', 429));
        }
        $deferred = new Deferred();
        if ($path === 'local:disable' && $payload === ['dryRun' => false]) {
            array_unshift($this->queue, [$path, $payload, $deferred, $queueDeadline, $grantDeadline]);
        } else {
            $this->queue[] = [$path, $payload, $deferred, $queueDeadline, $grantDeadline];
        }
        $this->pump();
        return $deferred->promise();
    }

    public function tick(): void
    {
        $this->pump();
    }

    public function status(): array
    {
        return [
            'agent_id' => $this->config->get('agentId'),
            'enabled' => $this->enabled,
            'ready' => $this->ready,
            'active_grants' => array_sum(array_map('count', $this->leases)) + count($this->supportLeases),
            'active_support_grants' => count($this->supportLeases),
            'capabilities' => ['support_all_v1'],
            'grant_duration_seconds' => $this->config->get('grantDurationSeconds'),
            'support_duration_seconds' => $this->config->get('supportDurationSeconds'),
            'pending_cleanup' => count($this->cleanup),
            'queued_requests' => count($this->queue),
            'bulk_running' => $this->bulk !== null,
            'last_directory_error' => $this->lastDirectoryError,
            'server_time' => gmdate('Y-m-d\TH:i:s\Z', (int) ($this->wall)()),
            'state_storage' => 'memory',
        ] + ($this->logger?->status() ?? []);
    }

    private function pump(): void
    {
        // Expire waiting HTTP writes even while a slow AD operation owns the
        // writer. A timed-out queued request must never run minutes later.
        $this->expireQueued();
        if ($this->busy) {
            return;
        }
        $this->discoverExpired();
        // Fair scheduling: one cleanup, then one waiting command. Disable has priority.
        $disablePending = isset($this->queue[0]) && $this->queue[0][0] === 'local:disable'
            && $this->queue[0][1] === ['dryRun' => false];
        $candidates = $this->cleanup;
        uasort($candidates, static fn (array $a, array $b): int => $a['retryAt'] <=> $b['retryAt']);
        foreach ($candidates as $userId => $cleanup) {
            if ($disablePending || ($this->lastWasCleanup && ($this->queue !== [] || $this->bulk !== null))) {
                break;
            }
            if ($cleanup['retryAt'] <= ($this->mono)()) {
                $this->busy = true;
                $this->lastWasCleanup = true;
                $this->runCleanup($userId)->then(
                    fn () => $this->finished(),
                    fn () => $this->finished(),
                );
                return;
            }
        }
        if ($this->queue === []) {
            if ($this->bulk !== null) {
                $this->busy = true;
                $this->lastWasCleanup = false;
                $this->bulkStep();
            }
            return;
        }
        [$path, $payload, $deferred, , $grantDeadline] = array_shift($this->queue);
        $this->busy = true;
        $this->lastWasCleanup = false;
        if (in_array($path, ['local:enable', 'local:disable'], true)) {
            try {
                $this->startBulk($path, $payload, $deferred);
            } catch (Throwable $error) {
                $deferred->reject($error);
            }
            $this->finished();
            return;
        }
        try {
            $promise = str_starts_with($path, 'local:')
                ? $this->administrative($path, $payload)
                : $this->command($path, $payload, $grantDeadline);
        } catch (Throwable $error) {
            $promise = reject($error);
        }
        $promise->then(
            function (array $result) use ($deferred): void {
                $deferred->resolve($result);
                $this->finished();
            },
            function (Throwable $error) use ($deferred, $path, $payload): void {
                $this->logger?->record('command_failed', array_intersect_key($payload, array_flip(['request_id', 'login', 'computer', 'sequence']))
                    + ['route' => $path, 'http_status' => (int) $error->getCode()]);
                $deferred->reject($error);
                $this->finished();
            },
        );
    }

    private function finished(): void
    {
        $this->busy = false;
        $this->pump();
    }

    private function expireQueued(): void
    {
        $now = ($this->mono)();
        $waiting = [];
        $expired = [];
        foreach ($this->queue as $entry) {
            if ($entry[3] !== null && $entry[3] <= $now) {
                $expired[] = $entry;
            } else {
                $waiting[] = $entry;
            }
        }
        $this->queue = $waiting;
        foreach ($expired as [$path, $payload, $deferred]) {
            $this->logger?->record('command_queue_timeout', array_intersect_key($payload, array_flip(['request_id', 'login', 'computer', 'sequence']))
                + ['route' => $path, 'http_status' => 503]);
            $deferred->reject(new RuntimeException('Request waited too long for the directory writer; no directory operation was started.', 503));
        }
    }

    private function command(string $path, array $body, ?float $grantDeadline = null): PromiseInterface
    {
        if ($this->bulk !== null) {
            throw new RuntimeException('A bulk operation is in progress; retry after completion.', 409);
        }
        $grant = str_ends_with($path, '/grants');
        $support = str_starts_with($path, '/v1/support/');
        $this->validateCommand($body, $grant, $support);
        $id = strtolower($body['request_id']);
        $body['request_id'] = $id;
        $body['login'] = strtolower($body['login']);
        if (!$support) {
            $body['computer'] = strtoupper($body['computer']);
        }
        ksort($body);
        $fingerprint = hash('sha256', $path . '\n' . json_encode($body, JSON_THROW_ON_ERROR));
        $retryRevocation = null;
        if (isset($this->commands[$id])) {
            $previous = $this->commands[$id];
            if (!hash_equals($previous['fingerprint'], $fingerprint)) {
                throw new RuntimeException('request_id was already used with different data.', 409);
            }
            if (isset($previous['error'])) {
                if (!$grant && ($previous['retry_revoke'] ?? false) === true) {
                    // Recheck the original GUID and sequence after resolving
                    // the login, before reattempting this same revocation.
                    $retryRevocation = $previous;
                } else {
                    throw new RuntimeException('Previous attempt failed; check status and retry with a new sequence and request_id.', $previous['error']);
                }
            } else {
                $result = $previous['result'];
                $result['original_status'] = $result['status'];
                $result['status'] = 'already_processed';
                $result['currently_active'] = $support
                    ? $this->isSupportActive($result['user_id'])
                    : $this->isActive($result['user_id'], $result['computer']);
                $this->logger?->record('command_replayed', $result);
                return resolve($result);
            }
        }
        // Successful results live for ten minutes. The latest failed revocation
        // and per-user high-water sequence survive normal result eviction.
        if (!isset($this->commands[$id]) && count($this->commands) >= $this->config->get('maxRememberedRequests')) {
            throw new RuntimeException('Command history capacity reached; controlled maintenance is required.', 503);
        }
        if (!$this->enabled) {
            throw new RuntimeException('Second factor is disabled on this agent.', 409);
        }
        $expiry = $grant ? $this->parseExpiry($body['expires_at'], $this->config->get($support ? 'supportDurationSeconds' : 'grantDurationSeconds')) : null;
        // Preserve the deadline measured at receipt across both queued waiting
        // and directory lookups, even when the system clock is adjusted.
        $deadline = $grant ? min($grantDeadline ?? INF, ($this->mono)() + $expiry - ($this->wall)()) : null;
        if ($grant && $deadline <= ($this->mono)()) {
            throw new RuntimeException('Grant expired before the directory operation.', 409);
        }
        if (!$this->ready) {
            return $this->initialize()->then(function () use ($path, $body, $deadline): PromiseInterface {
                if (!$this->ready) {
                    throw new RuntimeException('Directory is not ready.', 503);
                }
                return $this->command($path, $body, $deadline);
            });
        }
        return $this->directory->execute(['action' => 'resolve', 'login' => $body['login']])->then(
            function (array $user) use ($body, $id, $fingerprint, $grant, $support, $expiry, $deadline, $retryRevocation): PromiseInterface {
                $userId = strtolower($user['userId']);
                if ($retryRevocation !== null
                    && ($retryRevocation['user_id'] !== $userId
                        || $retryRevocation['sequence'] !== $body['sequence']
                        || ($this->sequences[$userId] ?? null) !== $body['sequence'])) {
                    throw new RuntimeException('Failed revocation was superseded or its user identity changed.', 409);
                }
                $base = [
                    'request_id' => $id, 'user_id' => $userId, 'login' => $user['login'],
                    'sequence' => $body['sequence'],
                ];
                $base += $support ? ['scope' => 'support_all'] : ['computer' => $body['computer']];
                if (!isset($this->sequences[$userId]) && count($this->sequences) >= $this->config->get('maxRememberedRequests')) {
                    throw new RuntimeException('User sequence capacity reached.', 503);
                }
                if ($user['excluded']) {
                    $this->sequences[$userId] = max($body['sequence'], $this->sequences[$userId] ?? 0);
                    unset($this->leases[$userId], $this->supportLeases[$userId], $this->cleanup[$userId]);
                    return resolve($this->remember($id, $fingerprint, $base + ['status' => 'excluded', 'reason' => $user['reason']]));
                }
                if ($body['sequence'] <= ($this->sequences[$userId] ?? 0) && $retryRevocation === null) {
                    throw new RuntimeException('Stale sequence for this user.', 409);
                }
                // Both modes change the same AD attribute. Keep one common
                // high-water sequence and never let a command of either mode
                // overwrite an outstanding lease belonging to the other mode.
                if (($support && isset($this->leases[$userId])) || (!$support && isset($this->supportLeases[$userId]))) {
                    throw new RuntimeException('Another access scope is active for this user.', 409);
                }
                if ($grant && isset($this->cleanup[$userId])) {
                    throw new RuntimeException('Previous access cleanup is not confirmed.', 409);
                }
                $alreadyLeased = $support ? isset($this->supportLeases[$userId]) : isset($this->leases[$userId][$body['computer']]);
                if ($grant && !$alreadyLeased
                    && $this->status()['active_grants'] >= $this->config->get('maxActiveGrants')) {
                    throw new RuntimeException('Active grant capacity reached.', 503);
                }
                $this->sequences[$userId] = $body['sequence'];
                if ($grant) {
                    if ($expiry <= ($this->wall)() || $deadline <= ($this->mono)()) {
                        throw new RuntimeException('Grant expired while waiting for the directory.', 409);
                    }
                    // Register intent before dispatch. An uncertain write must still be cleaned up.
                    $lease = [
                        'wall' => $expiry,
                        'mono' => $deadline,
                    ];
                    if ($support) {
                        $this->supportLeases[$userId] = $lease;
                    } else {
                        $this->leases[$userId][$body['computer']] = $lease;
                    }
                }
                $request = ['action' => ($support ? 'support-' : '') . ($grant ? 'grant' : 'revoke'), 'userId' => $userId];
                if (!$support) {
                    $request['computer'] = $body['computer'];
                }
                return $this->directory->execute($request)->then(
                    function (array $result) use ($id, $fingerprint, $base, $userId, $body, $grant, $support, $expiry): array {
                        $this->lastDirectoryError = null;
                        if ($result['excluded']) {
                            unset($this->leases[$userId], $this->supportLeases[$userId], $this->cleanup[$userId]);
                            return $this->remember($id, $fingerprint, $base + ['status' => 'excluded', 'reason' => $result['reason']]);
                        }
                        if (!$grant && $support) {
                            // support-revoke confirms the complete deny baseline,
                            // including recovery when this instance has no timer.
                            unset($this->supportLeases[$userId], $this->cleanup[$userId]);
                        } elseif (!$grant) {
                            unset($this->leases[$userId][$body['computer']]);
                            $this->dropEmptyUser($userId);
                            if (isset($this->cleanup[$userId]) && !$this->cleanup[$userId]['full']) {
                                unset($this->cleanup[$userId]['computers'][$body['computer']]);
                                if ($this->cleanup[$userId]['computers'] === []) {
                                    unset($this->cleanup[$userId]);
                                }
                            }
                        } elseif (!($support ? $this->isSupportActive($userId) : $this->isActive($userId, $body['computer']))) {
                            $this->scheduleCleanup($userId, null);
                            throw new RuntimeException('Grant expired during application; cleanup is pending.', 409);
                        }
                        return $this->remember($id, $fingerprint, $base + [
                            'status' => $grant ? 'granted' : 'revoked',
                            'expires_at' => $grant ? gmdate('Y-m-d\TH:i:s\Z', (int) $expiry) : null,
                        ]);
                    },
                )->catch(function (Throwable $error) use ($id, $fingerprint, $userId, $body, $grant, $support): never {
                    $this->scheduleCleanup($userId, $grant || $support ? null : $body['computer']);
                    $this->lastDirectoryError = 'directory_write_unconfirmed';
                    $code = $error->getCode() === 409 ? 409 : 503;
                    $this->commands[$id] = ['fingerprint' => $fingerprint, 'error' => $code,
                        'retry_revoke' => !$grant, 'user_id' => $userId, 'sequence' => $body['sequence'],
                        'until' => ($this->mono)() + 600];
                    throw new RuntimeException('Directory change is unconfirmed; cleanup will be retried.', $code);
                });
            },
            function (Throwable $error): never {
                // A missing login is a request failure, not an AD outage. Keep
                // healthy status and avoid an extra health roundtrip next time.
                if ($error->getCode() === 404) {
                    throw new RuntimeException('Directory user was not found.', 404);
                }
                $this->lastDirectoryError = 'directory_lookup_failed';
                $this->ready = false;
                throw new RuntimeException('Directory lookup failed.', 503);
            },
        );
    }

    private function administrative(string $path, array $body): PromiseInterface
    {
        if (array_diff(array_keys($body), ['dryRun']) !== [] || (array_key_exists('dryRun', $body) && !is_bool($body['dryRun']))) {
            throw new RuntimeException('Only the boolean dryRun field is accepted.', 400);
        }
        $dryRun = $body['dryRun'] ?? true;
        if ($path === 'local:ensure-bypass') {
            if ($dryRun) {
                return resolve(['status' => 'preview', 'action' => 'ensure-bypass']);
            }
            return $this->directory->execute(['action' => 'ensure-bypass'])->then(
                fn (array $result): PromiseInterface => $this->initialize()->then(function () use ($result): array {
                    $this->logger?->record('bypass_group_ready', ['ready' => $this->ready]);
                    return ['status' => 'group_ready', 'ready' => $this->ready, 'summary' => $result];
                }),
            );
        }
        throw new RuntimeException('Unknown administrative operation.', 404);
    }

    private function startBulk(string $path, array $body, Deferred $deferred): void
    {
        if (array_diff(array_keys($body), ['dryRun']) !== [] || (array_key_exists('dryRun', $body) && !is_bool($body['dryRun']))) {
            throw new RuntimeException('Only the boolean dryRun field is accepted.', 400);
        }
        if ($this->bulk !== null) {
            throw new RuntimeException('Another bulk operation is running.', 409);
        }
        $dryRun = $body['dryRun'] ?? true;
        $enable = $path === 'local:enable';
        if (!$dryRun && !$enable) {
            // Cancel every local expiry before clear-all; failed bulk clearing stays disabled.
            $this->enabled = false;
            $this->leases = [];
            $this->supportLeases = [];
            $this->cleanup = [];
        }
        $this->bulk = ['enable' => $enable, 'dryRun' => $dryRun, 'deferred' => $deferred, 'cursor' => null,
            'summary' => ['dryRun' => $dryRun, 'found' => 0, 'changed' => 0, 'excluded' => 0, 'failed' => 0, 'errors' => []]];
        $this->logger?->record('bulk_started', ['action' => $enable ? 'enable' : 'disable', 'dry_run' => $dryRun, 'enabled' => $this->enabled]);
    }

    /** Batches release the writer between groups so live timers can be serviced. */
    private function bulkStep(): void
    {
        $state = $this->bulk;
        $request = ['action' => $state['enable'] ? 'bulk-enable' : 'bulk-disable', 'dryRun' => $state['dryRun'], 'batchSize' => 10];
        if ($state['cursor'] !== null) {
            $request['cursor'] = $state['cursor'];
        }
        $this->directory->execute($request)->then(
            function (array $batch) use ($state): void {
                foreach (['found', 'changed', 'excluded', 'failed'] as $field) {
                    $this->bulk['summary'][$field] += $batch[$field];
                }
                $this->bulk['summary']['errors'] = array_slice(array_merge($this->bulk['summary']['errors'], $batch['errors'] ?? []), 0, 5);
                if (!($batch['complete'] ?? true)) {
                    $cursor = $batch['nextCursor'] ?? null;
                    if (!is_string($cursor) || $cursor === $state['cursor']) {
                        throw new RuntimeException('Invalid bulk cursor.', 502);
                    }
                    $this->bulk['cursor'] = $cursor;
                    $this->finished();
                    return;
                }
                $summary = $this->bulk['summary'];
                $failed = $summary['failed'] > 0;
                if (!$state['dryRun'] && $state['enable'] && !$failed) {
                    $this->enabled = true;
                    $this->ready = true;
                }
                $this->lastDirectoryError = $failed ? 'bulk_partial_failure' : null;
                $this->logger?->record('bulk_completed', array_intersect_key($summary, array_flip(['found', 'changed', 'excluded', 'failed']))
                    + ['action' => $state['enable'] ? 'enable' : 'disable', 'dry_run' => $state['dryRun'], 'enabled' => $this->enabled,
                       'status' => $failed ? 'partial' : 'complete']);
                $this->bulk = null;
                $state['deferred']->resolve(['status' => $failed ? 'partial' : ($state['dryRun'] ? 'preview' : ($state['enable'] ? 'enabled' : 'disabled')), 'enabled' => $this->enabled, 'summary' => $summary]);
                $this->finished();
            },
        )->catch(function (Throwable $error) use ($state): void {
            $this->lastDirectoryError = 'bulk_unconfirmed';
            $this->logger?->record('bulk_failed', ['action' => $state['enable'] ? 'enable' : 'disable', 'dry_run' => $state['dryRun'], 'error_code' => 'bulk_unconfirmed']);
            $this->bulk = null;
            $state['deferred']->reject(new RuntimeException('Bulk operation is unconfirmed; inspect status and retry the command.', 503));
            $this->finished();
        });
    }

    private function discoverExpired(): void
    {
        foreach ($this->supportLeases as $userId => $lease) {
            if ($lease['wall'] <= ($this->wall)() || $lease['mono'] <= ($this->mono)()) {
                $this->scheduleCleanup($userId, null);
            }
        }
        foreach ($this->leases as $userId => $computers) {
            foreach ($computers as $computer => $lease) {
                if ($lease['wall'] <= ($this->wall)() || $lease['mono'] <= ($this->mono)()) {
                    $this->scheduleCleanup($userId, null);
                    break;
                }
            }
        }
    }

    private function scheduleCleanup(string $userId, ?string $computer): void
    {
        if (!isset($this->cleanup[$userId])) {
            $this->cleanup[$userId] = ['full' => false, 'computers' => [], 'retryAt' => ($this->mono)()];
        }
        if ($computer === null) {
            $this->cleanup[$userId]['full'] = true;
        } else {
            $this->cleanup[$userId]['computers'][$computer] = true;
        }
    }

    private function runCleanup(string $userId): PromiseInterface
    {
        $cleanup = $this->cleanup[$userId];
        $computer = $cleanup['full'] ? null : array_key_first($cleanup['computers']);
        $request = ['action' => $cleanup['full'] ? 'expire' : 'revoke', 'userId' => $userId];
        if ($computer !== null) {
            $request['computer'] = $computer;
        }
        return $this->directory->execute($request)->then(
            function (array $result) use ($userId, $cleanup, $computer): void {
                $this->logger?->record('access_cleanup', ['user_id' => $userId, 'login' => $result['login'] ?? null,
                    'computer' => $computer, 'action' => $cleanup['full'] ? 'expire_all' : 'revoke_pair',
                    'status' => $result['excluded'] ? 'excluded' : 'cleared']);
                if ($cleanup['full'] || $result['excluded']) {
                    unset($this->leases[$userId], $this->supportLeases[$userId], $this->cleanup[$userId]);
                } else {
                    unset($this->leases[$userId][$computer], $this->cleanup[$userId]['computers'][$computer]);
                    $this->dropEmptyUser($userId);
                    if ($this->cleanup[$userId]['computers'] === []) {
                        unset($this->cleanup[$userId]);
                    }
                }
                $this->lastDirectoryError = null;
            },
            function (Throwable $error) use ($userId): void {
                $this->lastDirectoryError = 'cleanup_failed';
                $this->logger?->record('cleanup_failed', ['user_id' => $userId, 'error_code' => 'directory_unavailable']);
                $this->cleanup[$userId]['retryAt'] = ($this->mono)() + 5.0;
            },
        );
    }

    private function isActive(string $userId, string $computer): bool
    {
        $lease = $this->leases[$userId][$computer] ?? null;
        return $lease !== null && !isset($this->cleanup[$userId])
            && $lease['wall'] > ($this->wall)() && $lease['mono'] > ($this->mono)();
    }

    private function isSupportActive(string $userId): bool
    {
        $lease = $this->supportLeases[$userId] ?? null;
        return $lease !== null && !isset($this->cleanup[$userId])
            && $lease['wall'] > ($this->wall)() && $lease['mono'] > ($this->mono)();
    }

    private function dropEmptyUser(string $userId): void
    {
        if (($this->leases[$userId] ?? []) === []) {
            unset($this->leases[$userId]);
        }
    }

    private function remember(string $id, string $fingerprint, array $result): array
    {
        $this->commands[$id] = ['fingerprint' => $fingerprint, 'result' => $result, 'until' => ($this->mono)() + 600];
        $this->logger?->record('access_result', $result);
        return $result;
    }

    private function validateCommand(array $body, bool $grant, bool $support = false): void
    {
        $fields = ['request_id', 'sequence', 'login'];
        if (!$support) {
            $fields[] = 'computer';
        }
        if ($grant) {
            $fields[] = 'expires_at';
        }
        if (array_diff($fields, array_keys($body)) !== [] || array_diff(array_keys($body), $fields) !== []) {
            throw new RuntimeException('Unexpected or missing command fields.', 400);
        }
        if (!is_string($body['request_id']) || !preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/Di', $body['request_id'])) {
            throw new RuntimeException('request_id must be a UUID.', 400);
        }
        if (!is_int($body['sequence']) || $body['sequence'] < 1 || $body['sequence'] > 9007199254740991) {
            throw new RuntimeException('sequence must be a positive safe integer increasing for each user.', 400);
        }
        if (!is_string($body['login']) || !preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,19}\z/D', $body['login'])) {
            throw new RuntimeException('login must be a simple sAMAccountName of at most 20 characters.', 400);
        }
        if (!$support && (!is_string($body['computer']) || !preg_match('/\A(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\z/D', $body['computer'])
            || strcasecmp($body['computer'], $this->config->get('stub')) === 0)) {
            throw new RuntimeException('computer must be a NetBIOS name distinct from the stub.', 400);
        }
        if ($grant && !is_string($body['expires_at'])) {
            throw new RuntimeException('expires_at must be a UTC timestamp.', 400);
        }
    }

    private function parseExpiry(string $value, int $maximum): float
    {
        $time = DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s\Z', $value, new \DateTimeZone('UTC'));
        if ($time === false || $time->format('Y-m-d\TH:i:s\Z') !== $value) {
            throw new RuntimeException('expires_at must use YYYY-MM-DDTHH:MM:SSZ.', 400);
        }
        $timestamp = (float) $time->getTimestamp();
        $remaining = $timestamp - ($this->wall)();
        if ($remaining <= 0 || $remaining > $maximum) {
            throw new RuntimeException('Grant must expire within the next ' . $maximum . ' seconds.', 409);
        }
        return $timestamp;
    }
}
