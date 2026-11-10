<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use Closure;
use RuntimeException;
use Throwable;

/** Append-only diagnostics, never an input for restoring grants or timers. */
final class AuditLogger
{
    private Closure $clock;
    private ?string $error = null;
    private int $dropped = 0;
    private string $directory;

    private const FIELDS = [
        'request_id', 'user_id', 'login', 'computer', 'sequence', 'expires_at', 'scope',
        'status', 'original_status', 'currently_active', 'reason', 'action',
        'enabled', 'ready', 'dry_run', 'found', 'changed', 'excluded', 'failed',
        'error_code', 'http_status', 'peer_ip', 'route', 'listen',
    ];

    public function __construct(private readonly Config $config, ?callable $clock = null)
    {
        $this->clock = $clock === null ? static fn (): int => time() : Closure::fromCallable($clock);
        $this->directory = rtrim($config->get('logDirectory'), '/\\');
        // Only the elevated installer creates this directory and its private ACL.
        if (!is_dir($this->directory) || is_link($this->directory)) {
            throw new RuntimeException('Private log directory is missing or invalid. Run the installer.');
        }
        $this->record('logging_started');
        if ($this->error !== null) {
            throw new RuntimeException('Unable to write the private log directory. Check its permissions and free space.');
        }
    }

    /** Logging failure must not interrupt an already scheduled access revocation. */
    public function record(string $event, array $fields = []): void
    {
        $handle = null;
        try {
            if (!preg_match('/\A[a-z][a-z0-9_]{0,63}\z/D', $event)) {
                throw new RuntimeException('Invalid event.');
            }
            $now = (int) ($this->clock)();
            $entry = ['time' => gmdate('Y-m-d\TH:i:s\Z', $now), 'agent_id' => $this->config->get('agentId'), 'event' => $event];
            foreach (self::FIELDS as $field) {
                if (!array_key_exists($field, $fields)) {
                    continue;
                }
                $value = $fields[$field];
                // No arbitrary context arrays, HTTP headers, raw requests or exceptions.
                if (is_string($value)) {
                    $entry[$field] = substr($value, 0, 256);
                } elseif (is_bool($value) || is_int($value) || $value === null) {
                    $entry[$field] = $value;
                }
            }
            $line = json_encode($entry, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
            $path = $this->directory . DIRECTORY_SEPARATOR . 'agent-' . gmdate('Y-m-d', $now) . '.jsonl';
            if (is_link($path)) {
                throw new RuntimeException('Log links are not allowed.');
            }
            $handle = @fopen($path, 'ab');
            if ($handle === false || !@flock($handle, LOCK_EX | LOCK_NB)) {
                throw new RuntimeException('Log file is unavailable.');
            }
            $offset = 0;
            while ($offset < strlen($line)) {
                $written = @fwrite($handle, substr($line, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Log write failed.');
                }
                $offset += $written;
            }
            if (!@fflush($handle)) {
                throw new RuntimeException('Log flush failed.');
            }
            $this->error = null;
        } catch (Throwable) {
            $this->error = 'log_write_failed';
            ++$this->dropped;
        } finally {
            if (is_resource($handle)) {
                @flock($handle, LOCK_UN);
                @fclose($handle);
            }
        }
    }

    public function status(): array
    {
        return ['logging_error' => $this->error, 'dropped_log_records' => $this->dropped];
    }
}
