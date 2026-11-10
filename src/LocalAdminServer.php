<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use React\EventLoop\Loop;
use React\EventLoop\TimerInterface;
use RuntimeException;

/** Local Windows named-pipe administration; it never binds a TCP port. */
final class LocalAdminServer
{
    private mixed $process = null;
    private array $pipes = [];
    private ?TimerInterface $timer = null;
    private bool $running = false;
    private float $retryAfter = 0;
    private array $requests = [];
    private bool $reportedFailure = false;
    private float $processDeadline = 0;
    private float $nextTerminateAt = 0;
    private bool $processTimedOut = false;

    public function __construct(
        private readonly Config $config,
        private readonly GrantManager $manager,
        private readonly ?AuditLogger $logger = null,
    ) {
    }

    public static function pipeName(string $agentId): string
    {
        return 'Elemer-2FA-' . hash('sha256', $agentId);
    }

    public function start(): void
    {
        if ($this->running) {
            return;
        }
        if (PHP_OS_FAMILY !== 'Windows') {
            throw new RuntimeException('Local administration requires Windows named pipes.');
        }
        $this->running = true;
        $this->launch();
        $this->timer = Loop::addPeriodicTimer(0.05, fn () => $this->poll());
    }

    public function stop(): void
    {
        $this->running = false;
        if ($this->timer !== null) {
            Loop::cancelTimer($this->timer);
            $this->timer = null;
        }
        if (is_resource($this->process)) {
            @proc_terminate($this->process, 9);
        }
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                @fclose($pipe);
            }
        }
        $this->pipes = [];
        if (is_resource($this->process)) {
            @proc_close($this->process);
        }
        $this->process = null;
    }

    private function launch(): void
    {
        $input = $this->snapshotInput();
        $script = dirname(__DIR__) . '/powershell/LocalAdmin.ps1';
        $command = [$this->config->get('powershellPath'), '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $script,
            '-Mode', 'Server', '-PipeName', self::pipeName($this->config->get('agentId'))];
        $pipes = [];
        $process = @proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), null,
            ['bypass_shell' => true, 'create_process_group' => true]);
        if (!is_resource($process)) {
            throw new RuntimeException('Unable to start local administration.');
        }
        $this->process = $process;
        $this->pipes = $pipes;
        // The child normally waits up to 300s for a pipe client, then up to
        // 5s each for reading/writing. Bound startup and a hung child as well;
        // polling this deadline never blocks grant or expiry processing.
        $this->processDeadline = hrtime(true) / 1e9 + 330;
        $this->nextTerminateAt = 0;
        $this->processTimedOut = false;
        $offset = 0;
        while ($offset < strlen($input)) {
            $count = @fwrite($pipes[0], substr($input, $offset));
            if ($count === false || $count === 0) {
                @proc_terminate($process, 9);
                break;
            }
            $offset += $count;
        }
        fclose($this->pipes[0]);
        unset($this->pipes[0]);
    }

    /** A single small write fits the anonymous pipe even before PowerShell starts. */
    private function snapshotInput(): string
    {
        foreach ($this->requests as $id => $request) {
            if ($request['completedAt'] !== null && $request['completedAt'] < microtime(true) - 600) {
                unset($this->requests[$id]);
            }
        }
        // Keep room for a fresh status command during a long bulk operation.
        // Completed responses are retained for ten minutes, subject to this bound.
        while (count($this->requests) >= 16) {
            if (!$this->discardOldestCompleted()) { break; }
        }
        do {
            $snapshot = [];
            foreach ($this->requests as $id => $request) {
                $snapshot[] = ['id' => $id, 'command' => $request['command'], 'dryRun' => $request['dryRun'], 'response' => $request['response']];
            }
            $input = json_encode(['secretHex' => $this->config->get('apiSecretHex'), 'entries' => $snapshot], JSON_THROW_ON_ERROR);
            if (strlen($input) <= 3000) { return $input; }
            // Evict completed results only. Pending commands must remain discoverable.
            // Keeping input below the Windows pipe buffer prevents blocking expiry
            // processing when the PowerShell child has not begun reading yet.
        } while ($this->discardOldestCompleted());
        throw new RuntimeException('Local administration snapshot exceeds its bounded size.');
    }

    private function discardOldestCompleted(): bool
    {
        $oldest = null;
        foreach ($this->requests as $id => $request) {
            if ($request['completedAt'] !== null && ($oldest === null || $request['completedAt'] < $this->requests[$oldest]['completedAt'])) {
                $oldest = $id;
            }
        }
        if ($oldest === null) { return false; }
        unset($this->requests[$oldest]);
        return true;
    }

    private function poll(): void
    {
        if (!$this->running) {
            return;
        }
        if (!is_resource($this->process)) {
            if (hrtime(true) / 1e9 >= $this->retryAfter) {
                try {
                    $this->launch();
                } catch (\Throwable) {
                    $this->failed();
                }
            }
            return;
        }
        $status = proc_get_status($this->process);
        if ($status['running']) {
            $now = hrtime(true) / 1e9;
            if ($now >= $this->processDeadline && $now >= $this->nextTerminateAt) {
                $this->processTimedOut = true;
                $this->nextTerminateAt = $now + 1;
                @proc_terminate($this->process, 9);
                $this->failed('local_admin_bridge_timeout');
            }
            return;
        }
        // The one-shot bridge exits before we read anonymous pipes. Windows PHP
        // cannot reliably make these pipes nonblocking; stdout is capped at 2000.
        $stdout = stream_get_contents($this->pipes[1], 3001);
        $stderr = stream_get_contents($this->pipes[2], 3001);
        foreach ($this->pipes as $pipe) {
            fclose($pipe);
        }
        proc_close($this->process);
        $this->pipes = [];
        $this->process = null;
        try {
            if ($this->processTimedOut) {
                throw new RuntimeException('Local administration bridge exceeded its lifetime.');
            }
            if ($status['exitcode'] !== 0 || $stderr !== '' || $stdout === false || strlen($stdout) > 2000) {
                throw new RuntimeException('Invalid local administration bridge response.');
            }
            $message = json_decode($stdout, true, 12, JSON_THROW_ON_ERROR);
            if (!is_array($message) || !in_array($message['event'] ?? null, ['idle', 'request'], true)) {
                throw new RuntimeException('Invalid local administration bridge message.');
            }
            if ($message['event'] === 'request') {
                $this->accept($message);
            }
            $this->reportedFailure = false;
            $this->retryAfter = 0;
        } catch (\Throwable) {
            $this->failed();
        }
    }

    private function failed(string $code = 'local_admin_bridge_failed'): void
    {
        $this->retryAfter = hrtime(true) / 1e9 + 5;
        if (!$this->reportedFailure) {
            $this->logger?->record('local_admin_unavailable', ['error_code' => $code]);
            fwrite(STDERR, "Local console control is unavailable; HTTPS grants and expiry continue.\n");
            $this->reportedFailure = true;
        }
    }

    private function accept(array $message): void
    {
        $id = $message['id'] ?? null;
        $command = $message['command'] ?? null;
        $dryRun = $message['dryRun'] ?? null;
        if (!is_string($id) || !preg_match('/\A[0-9a-f]{64}\z/D', $id)
            || !in_array($command, ['status', 'enable', 'disable', 'ensure-bypass'], true) || !is_bool($dryRun)) {
            throw new RuntimeException('Invalid local console request.');
        }
        if (isset($this->requests[$id])) {
            return;
        }
        if (count($this->requests) >= 16) {
            throw new RuntimeException('Local console result capacity exceeded.');
        }
        $this->requests[$id] = ['command' => $command, 'dryRun' => $dryRun, 'response' => null, 'completedAt' => null];
        $this->logger?->record('local_admin_command', ['action' => $command, 'dry_run' => $dryRun]);
        try {
            $this->manager->handleLocal($command, $command === 'status' ? [] : ['dryRun' => $dryRun])->then(
                fn (array $result) => $this->complete($id, ['ok' => true, 'result' => $result]),
                fn (\Throwable $error) => $this->complete($id, ['ok' => false, 'error' => ['code' => 'local_command_failed',
                    'status' => in_array($error->getCode(), [400, 404, 409, 429, 502, 503, 504], true) ? $error->getCode() : 500,
                    'message' => 'Local command failed; check agent status and logs.']]),
            );
        } catch (\Throwable) {
            $this->complete($id, ['ok' => false, 'error' => ['code' => 'local_command_failed', 'message' => 'Local command failed; check status.']]);
        }
    }

    private function complete(string $id, array $response): void
    {
        if (strlen(json_encode($response, JSON_THROW_ON_ERROR)) > 2600) {
            $response = ['ok' => false, 'error' => ['code' => 'response_limit', 'message' => 'Command result exceeds the local response limit; check status and logs.']];
        }
        $this->requests[$id]['response'] = $response;
        $this->requests[$id]['completedAt'] = microtime(true);
    }
}
