<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

use React\Http\Message\ServerRequest;
use TwoFactorAgent\Auth;
use TwoFactorAgent\Config;
use TwoFactorAgent\HttpServer;
use function React\Promise\reject;
use function React\Promise\resolve;

function transportConfig(array $overrides = []): Config
{
    return new Config($overrides + [
        'agentId' => 'dc1',
        'domainController' => 'dc1.example.local',
        'allowedIPs' => ['192.0.2.10'],
        'apiSecretHex' => str_repeat('0123456789abcdef', 4),
    ]);
}

function transportRequest(Config $config, string $path = '/v1/status', string $body = '{}', string $key = 'mobile', string $peer = '192.0.2.10', ?int $timestamp = null, ?string $nonce = null): ServerRequest
{
    $timestamp ??= time();
    $nonce ??= bin2hex(random_bytes(16));
    $secret = hex2bin($config->get('apiSecretHex'));
    return new ServerRequest('POST', 'https://dc1.example.local:8443' . $path, [
        'Content-Type' => 'application/json',
        'X-2FA-Key-Id' => $key,
        'X-2FA-Timestamp' => (string) $timestamp,
        'X-2FA-Nonce' => $nonce,
        'X-2FA-Signature' => Auth::requestSignature($secret, 'POST', $path, $config->get('agentId'), (string) $timestamp, $nonce, $body),
    ], $body, '1.1', ['REMOTE_ADDR' => $peer]);
}

function transportThrows(callable $action, ?int $status = null): void
{
    try {
        $action();
    } catch (Throwable $error) {
        if ($status !== null) {
            eq($error->getCode(), $status);
        }
        return;
    }
    throw new RuntimeException('Expected an exception.');
}

test('configuration rejects placeholder secrets, obsolete admin secrets, non-IP allowlists and unknown fields', function (): void {
    transportThrows(fn () => transportConfig(['apiSecretHex' => str_repeat('0', 64)]));
    transportThrows(fn () => transportConfig(['adminSecretHex' => str_repeat('0123456789abcdef', 4)]));
    transportThrows(fn () => transportConfig(['allowedIPs' => ['192.0.2.0/24']]));
    transportThrows(fn () => transportConfig(['allowedIPs' => ['mobile.example.local']]));
    transportThrows(fn () => transportConfig(['startEnabled' => 'true']));
    transportThrows(fn () => transportConfig(['unknownField' => true]));
});

test('configuration normalizes mapped addresses and accepts a Windows UTF8 BOM', function (): void {
    $config = transportConfig(['allowedIPs' => ['::ffff:192.0.2.10'], 'bindAddress' => '0:0:0:0:0:0:0:1']);
    eq($config->get('allowedIPs'), ['192.0.2.10']);
    eq($config->get('bindAddress'), '::1');
    $path = tempnam(sys_get_temp_dir(), '2fa-config-test-');
    try {
        file_put_contents($path, "\xef\xbb\xbf" . json_encode([
            'agentId' => 'dc1', 'domainController' => 'dc1.example.local', 'allowedIPs' => ['192.0.2.10'],
            'apiSecretHex' => str_repeat('0123456789abcdef', 4),
        ], JSON_THROW_ON_ERROR));
        eq(Config::load($path)->get('agentId'), 'dc1');
    } finally {
        unlink($path);
    }
});

test('authentication accepts the exact IP and rejects tampering and wrong IP', function (): void {
    $config = transportConfig();
    $auth = new Auth($config, static fn (): int => 1000);
    $request = transportRequest($config, timestamp: 1000);
    eq($auth->authenticate($request, '::ffff:192.0.2.10', '{}')['keyId'], 'mobile');
    transportThrows(fn () => (new Auth($config, static fn (): int => 1000))->authenticate($request, '192.0.2.11', '{}'), 403);
    transportThrows(fn () => (new Auth($config, static fn (): int => 1000))->authenticate($request, '192.0.2.10', '{"changed":true}'), 401);
});

test('authentication enforces timestamps, single signature headers and nonce replay protection', function (): void {
    $config = transportConfig();
    $auth = new Auth($config, static fn (): int => 1000);
    $request = transportRequest($config, timestamp: 1000);
    $auth->authenticate($request, '192.0.2.10', '{}');
    transportThrows(fn () => $auth->authenticate($request, '192.0.2.10', '{}'), 409);
    transportThrows(fn () => $auth->authenticate(transportRequest($config, timestamp: 969), '192.0.2.10', '{}'), 401);
    transportThrows(fn () => $auth->authenticate(transportRequest($config, timestamp: 1031), '192.0.2.10', '{}'), 401);
    $duplicate = transportRequest($config, timestamp: 1000)->withHeader('X-2FA-Signature', [str_repeat('a', 64), str_repeat('b', 64)]);
    transportThrows(fn () => $auth->authenticate($duplicate, '192.0.2.10', '{}'), 401);
});

test('signatures are bound to an agent and the administrative HTTP key is rejected', function (): void {
    $config = transportConfig();
    $request = transportRequest($config, timestamp: 1000);
    transportThrows(fn () => (new Auth(transportConfig(['agentId' => 'dc2']), static fn (): int => 1000))->authenticate($request, '192.0.2.10', '{}'), 401);
    foreach (['192.0.2.10', '127.0.0.1', '::1'] as $ip) {
        $auth = new Auth($config, static fn (): int => 1000);
        transportThrows(fn () => $auth->authenticate(transportRequest($config, key: 'admin', peer: $ip, timestamp: 1000), $ip, '{}'), 401);
    }
});

test('administrative routes are absent over HTTP including loopback and never dispatch', function (): void {
    $config = transportConfig(['allowedIPs' => ['192.0.2.10', '127.0.0.1', '::1']]);
    $calls = 0;
    $server = new HttpServer($config, function () use (&$calls) { ++$calls; return resolve([]); });
    foreach (['192.0.2.10', '127.0.0.1', '::1'] as $ip) {
        foreach (['enable', 'disable', 'ensure-bypass'] as $command) {
            eq(awaitResult($server->handle(transportRequest($config, '/v1/admin/' . $command, '{"dryRun":false}', peer: $ip)))->getStatusCode(), 404);
            eq(awaitResult($server->handle(transportRequest($config, '/local:' . $command, '{"dryRun":false}', peer: $ip)))->getStatusCode(), 404);
        }
    }
    eq($calls, 0);
});

test('HTTP success is signed and forwarded IP headers never authorize a peer', function (): void {
    $config = transportConfig();
    $calls = 0;
    $server = new HttpServer($config, function (string $path, array $payload) use (&$calls) {
        ++$calls;
        return resolve(['ready' => true]);
    });
    $request = transportRequest($config);
    $response = awaitResult($server->handle($request));
    eq($response->getStatusCode(), 200);
    eq($calls, 1);
    $body = (string) $response->getBody();
    eq(json_decode($body, true), ['ok' => true, 'result' => ['ready' => true]]);
    eq($response->getHeaderLine('X-2FA-Response-Signature'), Auth::responseSignature(hex2bin($config->get('apiSecretHex')), 'dc1', $request->getHeaderLine('X-2FA-Nonce'), 200, $body));
    $forgedPeer = transportRequest($config, peer: '192.0.2.77')->withHeader('X-Forwarded-For', '192.0.2.10');
    eq(awaitResult($server->handle($forgedPeer))->getStatusCode(), 403);
    eq($calls, 1);
});

test('HTTP rejects malformed, array, oversized and tampered JSON before dispatch', function (): void {
    $config = transportConfig();
    $calls = 0;
    $server = new HttpServer($config, function () use (&$calls) {
        ++$calls;
        return resolve([]);
    });
    foreach (['{', '[]', 'null'] as $body) {
        eq(awaitResult($server->handle(transportRequest($config, body: $body)))->getStatusCode(), 400);
    }
    eq(awaitResult($server->handle(transportRequest($config, body: '{"x":"' . str_repeat('x', 16384) . '"}')))->getStatusCode(), 413);
    $request = transportRequest($config)->withHeader('X-2FA-Signature', str_repeat('0', 64));
    eq(awaitResult($server->handle($request))->getStatusCode(), 401);
    eq($calls, 0);
});

test('HTTP rejects unsupported content types, queries and unknown routes', function (): void {
    $config = transportConfig();
    $server = new HttpServer($config, static fn () => resolve([]));
    eq(awaitResult($server->handle(transportRequest($config)->withHeader('Content-Type', 'text/plain')))->getStatusCode(), 415);
    eq(awaitResult($server->handle(transportRequest($config, '/unknown')))->getStatusCode(), 404);
    $request = transportRequest($config);
    eq(awaitResult($server->handle($request->withUri($request->getUri()->withQuery('x=1'))))->getStatusCode(), 400);
    eq(awaitResult($server->handle(transportRequest($config)->withMethod('GET')))->getStatusCode(), 405);
});

test('HTTP errors preserve response authentication and never expose exception details', function (): void {
    $config = transportConfig();
    $server = new HttpServer($config, static fn () => reject(new RuntimeException('PRIVATE_DIRECTORY_DIAGNOSTIC', 503)));
    $request = transportRequest($config);
    $response = awaitResult($server->handle($request));
    $body = (string) $response->getBody();
    eq($response->getStatusCode(), 503);
    eq(str_contains($body, 'PRIVATE_DIRECTORY_DIAGNOSTIC'), false);
    eq($response->getHeaderLine('X-2FA-Response-Signature'), Auth::responseSignature(hex2bin($config->get('apiSecretHex')), 'dc1', $request->getHeaderLine('X-2FA-Nonce'), 503, $body));
});

test('IPv6 socket addresses with brackets are normalized before source-IP authentication', function (): void {
    $config = transportConfig(['allowedIPs' => ['::1', '192.0.2.10']]);
    foreach (['[::1]', '[::ffff:192.0.2.10]'] as $peer) {
        $auth = new Auth($config);
        eq($auth->authenticate(transportRequest($config, peer: $peer), $peer, '{}')['keyId'], 'mobile');
    }
    transportThrows(fn () => (new Auth($config))->authenticate(transportRequest($config), '[::2]', '{}'), 403);
});

test('incomplete and oversized streaming bodies never reach the directory dispatcher', function (): void {
    $config = transportConfig();
    $calls = 0;
    $server = new HttpServer($config, function () use (&$calls) { ++$calls; return resolve([]); });
    $buffer = new ReflectionMethod(HttpServer::class, 'bufferRequest');
    foreach (['oversized', 'incomplete'] as $mode) {
        $stream = new React\Stream\ThroughStream();
        $request = transportRequest($config)->withBody(new React\Http\Io\HttpBodyStream($stream, null));
        $response = $buffer->invoke($server, $request, [$server, 'handle']);
        if ($mode === 'oversized') {
            // No final chunk/end event: the size cap must reject immediately.
            $stream->write(str_repeat('x', 16385));
            eq(awaitResult($response)->getStatusCode(), 413);
        } else {
            $stream->write('{');
            $stream->close();
            eq(awaitResult($response)->getStatusCode(), 400);
        }
    }
    eq($calls, 0);
});

test('complete streamed body preserves byte-exact signing and closes its HTTP connection', function (): void {
    $config = transportConfig();
    $calls = 0;
    $server = new HttpServer($config, function () use (&$calls) { ++$calls; return resolve(['ready' => true]); });
    $stream = new React\Stream\ThroughStream();
    $request = transportRequest($config)->withBody(new React\Http\Io\HttpBodyStream($stream, 2));
    $response = (new ReflectionMethod(HttpServer::class, 'bufferRequest'))->invoke($server, $request, [$server, 'handle']);
    $stream->write('{');
    $stream->end('}');
    $result = awaitResult($response);
    eq($result->getStatusCode(), 200);
    eq($result->getHeaderLine('Connection'), 'close');
    eq($calls, 1);
});
