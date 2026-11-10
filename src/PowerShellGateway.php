<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use React\EventLoop\Loop;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use RuntimeException;

final class PowerShellGateway implements DirectoryGateway
{
    private bool $busy = false;

    public function __construct(private readonly Config $config)
    {
    }

    public function execute(array $request): PromiseInterface
    {
        $deferred = new Deferred();
        if ($this->busy) {
            $deferred->reject(new RuntimeException('Directory adapter is busy.', 503));
            return $deferred->promise();
        }
        $script = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'powershell' . DIRECTORY_SEPARATOR . 'Directory.ps1';
        try {
            if (!is_file($script)) {
                throw new RuntimeException('Directory adapter is unavailable.', 503);
            }
            // Configuration is always supplied by this process, never by an API caller.
            $request['config'] = $this->config->directoryConfig();
            $input = json_encode($request, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            // Windows anonymous pipes cannot be made reliably nonblocking. Keep
            // the entire stdin frame below their buffer even if the child stalls.
            if (strlen($input) > 3000) {
                throw new RuntimeException('Directory request is too large.', 400);
            }
            $command = [
                $this->config->get('powershellPath'),
                '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $script,
            ];
            $pipes = [];
            $deadline = hrtime(true) + $this->config->get('processTimeoutSeconds') * 1_000_000_000;
            $process = @proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), null, [
                'bypass_shell' => true,
                'create_process_group' => true,
            ]);
            if (!is_resource($process)) {
                throw new RuntimeException('Unable to start the directory adapter.', 503);
            }
            $this->busy = true;
            $written = 0;
            while ($written < strlen($input)) {
                $count = @fwrite($pipes[0], substr($input, $written));
                if ($count === false || $count === 0) {
                    break;
                }
                $written += $count;
            }
            fclose($pipes[0]);
            $timedOut = false;
            $lastTermination = 0;
            if ($written !== strlen($input)) {
                @proc_terminate($process, 9);
                $timedOut = true;
                $lastTermination = hrtime(true);
                $deferred->reject(new RuntimeException('Directory request could not be delivered; its outcome may be uncertain.', 503));
            }
            $timer = null;
            $timer = Loop::addPeriodicTimer(0.05, function () use ($process, $pipes, $deferred, $deadline, &$timedOut, &$lastTermination, &$timer): void {
                $status = proc_get_status($process);
                if ($status['running']) {
                    if (!$timedOut && hrtime(true) >= $deadline) {
                        $timedOut = true;
                        @proc_terminate($process, 9);
                        $lastTermination = hrtime(true);
                        // Keep the gateway locked until the OS confirms process exit.
                        // This reports the timeout promptly without overlapping AD writes.
                        $deferred->reject(new RuntimeException('Directory operation timed out; its outcome may be uncertain.', 504));
                    } elseif ($timedOut && hrtime(true) - $lastTermination >= 1_000_000_000) {
                        // Retry a failed OS termination without releasing the AD
                        // writer lock or blocking the event loop on proc_close().
                        @proc_terminate($process, 9);
                        $lastTermination = hrtime(true);
                    }
                    return;
                }
                Loop::cancelTimer($timer);
                // Windows anonymous pipes cannot reliably be made nonblocking.
                // Directory.ps1 guarantees its entire response is below 3000 bytes.
                $stdout = stream_get_contents($pipes[1], 4097);
                $stderr = stream_get_contents($pipes[2], 4097);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($process);
                $this->busy = false;
                if ($timedOut) {
                    $deferred->reject(new RuntimeException('Directory operation timed out; its outcome may be uncertain.', 504));
                    return;
                }
                if ($stdout === false || $stderr === false || strlen($stdout) > 3000 || $stderr !== '') {
                    $deferred->reject(new RuntimeException('Directory adapter returned an invalid response.', 502));
                    return;
                }
                try {
                    $decoded = json_decode($stdout, true, 32, JSON_THROW_ON_ERROR);
                    if (!is_array($decoded) || !isset($decoded['ok']) || !is_bool($decoded['ok'])) {
                        throw new RuntimeException('Directory adapter returned an invalid response.', 502);
                    }
                    if ($decoded['ok'] !== true) {
                        $code = $decoded['error']['code'] ?? 'directory_error';
                        $httpStatus = match ($code) {
                            'invalid_request' => 400,
                            'user_not_found' => 404,
                            'workstations_limit' => 409,
                            'response_limit' => 502,
                            default => 503,
                        };
                        $safeCode = is_string($code) && preg_match('/\A[a-z_]{1,64}\z/D', $code) ? $code : 'directory_error';
                        throw new RuntimeException('Directory operation failed: ' . $safeCode, $httpStatus);
                    }
                    if (!is_array($decoded['result'] ?? null)) {
                        throw new RuntimeException('Directory adapter returned an invalid response.', 502);
                    }
                    if ($status['exitcode'] !== 0) {
                        throw new RuntimeException('Directory adapter exited unsuccessfully.', 502);
                    }
                    $deferred->resolve($decoded['result']);
                } catch (\JsonException) {
                    $deferred->reject(new RuntimeException('Directory adapter returned invalid JSON.', 502));
                } catch (\Throwable $error) {
                    $deferred->reject($error);
                }
            });
        } catch (\Throwable $error) {
            $this->busy = false;
            $deferred->reject($error);
        }
        return $deferred->promise();
    }
}
