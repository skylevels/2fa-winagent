<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

final class Auth
{
    /** @var array<string,int> */
    private array $seen = [];
    private \Closure $clock;

    public function __construct(private readonly Config $config, ?callable $clock = null)
    {
        $this->clock = $clock === null ? static fn (): int => time() : \Closure::fromCallable($clock);
    }

    /** Returns authenticated signing context; do not log its contents. */
    public function authenticate(ServerRequestInterface $request, string $peerIp, string $body): array
    {
        $keyId = $this->singleHeader($request, 'X-2FA-Key-Id');
        $ip = Config::normalizeIp($peerIp);
        $path = $request->getUri()->getPath();
        if ($keyId !== 'mobile') {
            throw new RuntimeException('Unauthorized request.', 401);
        }
        if (!in_array($ip, $this->config->get('allowedIPs'), true)) {
            throw new RuntimeException('Unauthorized request.', 403);
        }
        $secret = hex2bin($this->config->get('apiSecretHex'));
        $timestamp = $this->singleHeader($request, 'X-2FA-Timestamp');
        $nonce = $this->singleHeader($request, 'X-2FA-Nonce');
        $signature = $this->singleHeader($request, 'X-2FA-Signature');
        if (!preg_match('/\A[1-9][0-9]{0,10}\z/D', $timestamp)
            || !preg_match('/\A[0-9a-f]{32}\z/D', $nonce)
            || !preg_match('/\A[0-9a-f]{64}\z/D', $signature)) {
            throw new RuntimeException('Unauthorized request.', 401);
        }
        $now = ($this->clock)();
        $skew = $this->config->get('requestSkewSeconds');
        if (abs($now - (int) $timestamp) > $skew) {
            throw new RuntimeException('Request timestamp is outside the permitted window.', 401);
        }
        $expected = self::requestSignature($secret, $request->getMethod(), $path, $this->config->get('agentId'), $timestamp, $nonce, $body);
        if (!hash_equals($expected, $signature)) {
            throw new RuntimeException('Unauthorized request.', 401);
        }
        foreach ($this->seen as $key => $expiresAt) {
            if ($expiresAt < $now) {
                unset($this->seen[$key]);
            }
        }
        $replayKey = $keyId . ':' . $nonce;
        if (isset($this->seen[$replayKey])) {
            throw new RuntimeException('Request nonce was already used.', 409);
        }
        if (count($this->seen) >= $this->config->get('maxRememberedRequests')) {
            throw new RuntimeException('Replay protection capacity reached. Retry later.', 503);
        }
        $this->seen[$replayKey] = (int) $timestamp + $skew;
        return ['keyId' => $keyId, 'secret' => $secret, 'nonce' => $nonce];
    }

    public static function requestSignature(string $secret, string $method, string $path, string $agentId, string $timestamp, string $nonce, string $body): string
    {
        return hash_hmac('sha256', implode("\n", [$method, $path, $agentId, $timestamp, $nonce, hash('sha256', $body)]), $secret);
    }

    public static function responseSignature(string $secret, string $agentId, string $nonce, int $status, string $body): string
    {
        return hash_hmac('sha256', implode("\n", ['RESPONSE', $agentId, $nonce, (string) $status, hash('sha256', $body)]), $secret);
    }

    private function singleHeader(ServerRequestInterface $request, string $name): string
    {
        $values = $request->getHeader($name);
        if (count($values) !== 1) {
            throw new RuntimeException('Unauthorized request.', 401);
        }
        return $values[0];
    }
}
