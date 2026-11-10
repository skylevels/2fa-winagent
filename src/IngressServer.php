<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use Evenement\EventEmitter;
use React\EventLoop\Loop;
use React\Socket\Connection;
use React\Socket\ConnectionInterface;
use React\Socket\ServerInterface;

/** Bound peers before TLS/HTTP allocate resources; one HTTP request per connection. */
final class IngressServer extends EventEmitter implements ServerInterface
{
    private array $connections = [];
    private array $receiving = [];
    private bool $closed = false;

    public function __construct(private readonly ServerInterface $tcp, private readonly Config $config)
    {
        $tcp->on('connection', function (ConnectionInterface $connection): void {
            $parts = parse_url((string) $connection->getRemoteAddress());
            $ip = Config::normalizeIp((string) ($parts['host'] ?? ''));
            if ($this->closed || !in_array($ip, $this->config->get('allowedIPs'), true)
                || count($this->connections) >= $this->config->get('maxConnections')) {
                $connection->close();
                return;
            }
            $id = spl_object_id($connection);
            $local = parse_url((string) $connection->getLocalAddress());
            $key = self::peerKey($ip, (int) ($parts['port'] ?? 0),
                Config::normalizeIp((string) ($local['host'] ?? '')), (int) ($local['port'] ?? 0));
            $this->connections[$id] = $connection;
            // An absolute deadline prevents trickle bytes from extending a lease.
            // It covers TLS handshake, HTTP headers and the entire request body.
            $this->receiving[$key] = Loop::addTimer($this->config->get('requestReceiveTimeoutSeconds'),
                static fn () => self::closeConnection($connection));
            $connection->on('close', function () use ($id, $key): void {
                $this->received($key);
                unset($this->connections[$id]);
            });
            $this->emit('connection', [$connection]);
        });
        $tcp->on('error', fn (\Throwable $error) => $this->emit('error', [$error]));
    }

    public function requestReceived(string $ip, int $port, string $localIp, int $localPort): void
    {
        $this->received(self::peerKey(Config::normalizeIp($ip), $port, Config::normalizeIp($localIp), $localPort));
    }

    private function received(string $key): void
    {
        if (isset($this->receiving[$key])) {
            Loop::cancelTimer($this->receiving[$key]);
            unset($this->receiving[$key]);
        }
    }

    private static function peerKey(string $ip, int $port, string $localIp, int $localPort): string
    {
        return implode("\0", [$ip, $port, $localIp, $localPort]);
    }

    private static function closeConnection(ConnectionInterface $connection): void
    {
        // React pauses its normal reader while StreamEncryption installs a raw
        // TLS reader. Forced closure must remove that reader before fclose().
        if ($connection instanceof Connection && is_resource($connection->stream)) {
            Loop::removeReadStream($connection->stream);
        }
        $connection->close();
    }

    public function getAddress(): ?string { return $this->tcp->getAddress(); }
    public function pause(): void { $this->tcp->pause(); }
    public function resume(): void { $this->tcp->resume(); }
    public function close(): void
    {
        $this->closed = true;
        $this->tcp->close();
        foreach ($this->connections as $connection) { self::closeConnection($connection); }
        $this->connections = [];
    }
}
