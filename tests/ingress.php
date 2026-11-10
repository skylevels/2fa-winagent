<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use React\EventLoop\Loop;
use React\Socket\ConnectionInterface;
use React\Socket\ServerInterface;
use TwoFactorAgent\IngressServer;

final class IngressTestListener extends Evenement\EventEmitter implements ServerInterface
{
    public function getAddress(): ?string { return 'tcp://127.0.0.1:1234'; }
    public function pause(): void {}
    public function resume(): void {}
    public function close(): void {}
}
final class IngressTestConnection extends Evenement\EventEmitter implements ConnectionInterface
{
    private React\Stream\ThroughStream $stream;
    public function __construct(private readonly string $peer, private readonly string $local = 'tcp://127.0.0.1:1234')
    {
        $this->stream = new React\Stream\ThroughStream();
        foreach (['data', 'end', 'error', 'close'] as $event) {
            $this->stream->on($event, fn (...$args) => $this->emit($event, $args));
        }
    }
    public function getLocalAddress(): ?string { return $this->local; }
    public function getRemoteAddress(): ?string { return $this->peer; }
    public function isReadable(): bool { return $this->stream->isReadable(); }
    public function isWritable(): bool { return $this->stream->isWritable(); }
    public function pause(): void { $this->stream->pause(); }
    public function resume(): void { $this->stream->resume(); }
    public function write($data): bool { return $this->stream->write($data); }
    public function end($data = null): void { $this->stream->end($data); }
    public function close(): void { $this->stream->close(); }
    public function pipe(React\Stream\WritableStreamInterface $destination, array $options = []): React\Stream\WritableStreamInterface
    {
        return $this->stream->pipe($destination, $options);
    }
}

test('TCP ingress rejects untrusted peers before TLS and bounds accepted connections', function (): void {
    $tcp = new IngressTestListener();
    $guard = new IngressServer($tcp, testConfig(['maxConnections' => 1]));
    $accepted = 0;
    $guard->on('connection', function () use (&$accepted): void { ++$accepted; });
    try {
        $wrong = new IngressTestConnection('tcp://192.0.2.77:5000');
        $tcp->emit('connection', [$wrong]);
        eq($wrong->isReadable(), false); eq($accepted, 0);
        $first = new IngressTestConnection('tcp://192.0.2.10:5001');
        $tcp->emit('connection', [$first]); eq($accepted, 1);
        $second = new IngressTestConnection('tcp://192.0.2.10:5002');
        $tcp->emit('connection', [$second]); eq($accepted, 1); eq($second->isReadable(), false);
        $first->close();
        $third = new IngressTestConnection('tcp://192.0.2.10:5003');
        $tcp->emit('connection', [$third]); eq($accepted, 2);
        $guard->close(); eq($third->isReadable(), false);
    } finally { $guard->close(); }
});

test('TCP ingress absolute receive deadline closes stalled clients but not accepted AD work', function (): void {
    $tcp = new IngressTestListener();
    $guard = new IngressServer($tcp, testConfig(['requestReceiveTimeoutSeconds' => 1]));
    $stalled = new IngressTestConnection('tcp://192.0.2.10:5010');
    // The remote tuple can repeat when connecting to different local IPs.
    $working = new IngressTestConnection('tcp://192.0.2.10:5010', 'tcp://127.0.0.2:1234');
    try {
        $tcp->emit('connection', [$stalled]);
        $tcp->emit('connection', [$working]);
        $guard->requestReceived('192.0.2.10', 5010, '127.0.0.2', 1234);
        Loop::run();
        eq($stalled->isReadable(), false);
        eq($working->isReadable(), true);
    } finally { $guard->close(); }
});

test('forced ingress shutdown removes the separate reader used during a paused TLS handshake', function (): void {
    $tcp = new IngressTestListener();
    $guard = new IngressServer($tcp, testConfig());
    $connection = new class(tmpfile(), Loop::get()) extends React\Socket\Connection {
        public function getRemoteAddress(): ?string { return 'tcp://192.0.2.10:5020'; }
        public function getLocalAddress(): ?string { return 'tcp://127.0.0.1:1234'; }
    };
    try {
        $guard->on('connection', static function ($connection): void {
            // StreamEncryption pauses the regular reader and registers its own.
            $connection->pause();
            Loop::addReadStream($connection->stream, static function (): void {});
        });
        $tcp->emit('connection', [$connection]);
        $guard->close();
        // A stale reader makes StreamSelectLoop throw on the closed resource.
        Loop::run();
        eq($connection->isReadable(), false);
    } finally { $guard->close(); }
});
