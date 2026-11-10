<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use Psr\Http\Message\ServerRequestInterface;
use React\Http\HttpServer as ReactHttpServer;
use React\Http\Message\Response;
use React\Http\Io\BufferedBody;
use React\Http\Middleware\StreamingRequestMiddleware;
use React\Promise\Promise;
use React\Promise\PromiseInterface;
use React\Socket\SecureServer;
use React\Socket\ServerInterface;
use React\Socket\TcpServer;
use React\Stream\ReadableStreamInterface;
use RuntimeException;
use function React\Promise\resolve;

final class HttpServer
{
    private Auth $auth;
    private \Closure $dispatch;
    /** @var list<ServerInterface> */
    private array $sockets = [];
    private ?ReactHttpServer $server = null;
    private int $pending = 0;
    private ?IngressServer $ingress = null;
    private array $lastErrorLog = [];

    public function __construct(private readonly Config $config, callable $dispatch, private readonly ?AuditLogger $logger = null)
    {
        $this->auth = new Auth($config);
        $this->dispatch = \Closure::fromCallable($dispatch);
    }

    public function start(): string
    {
        $this->server = new ReactHttpServer(
            new StreamingRequestMiddleware(),
            function (ServerRequestInterface $request, callable $next): mixed {
                $ip = Config::normalizeIp((string) ($request->getServerParams()['REMOTE_ADDR'] ?? ''));
                if (!in_array($ip, $this->config->get('allowedIPs'), true)) {
                    $this->logTransportError('api_source_rejected', ['peer_ip' => $ip, 'http_status' => 403]);
                    return $this->errorResponse(new RuntimeException('Source is not allowed.', 403), null);
                }
                if ($this->pending >= $this->config->get('maxPendingRequests')) {
                    return $this->errorResponse(new RuntimeException('Too many requests.', 429), null);
                }
                ++$this->pending;
                try {
                    return resolve($next($request))->then(
                        function (mixed $response): mixed {
                            --$this->pending;
                            return $response;
                        },
                        function (\Throwable $error): Response {
                            --$this->pending;
                            return $this->errorResponse($error, null);
                        }
                    );
                } catch (\Throwable $error) {
                    --$this->pending;
                    return $this->errorResponse($error, null);
                }
            },
            fn (ServerRequestInterface $request, callable $next) => $this->bufferRequest($request, $next),
            fn (ServerRequestInterface $request) => $this->handle($request)
        );
        $this->server->on('error', function (): void {
            $this->logTransportError('http_connection_error');
        });
        $bind = $this->config->get('bindAddress');
        if (str_contains($bind, ':')) {
            $bind = '[' . $bind . ']';
        }
        $tls = TlsContext::fromConfig($this->config);
        $tcp = new TcpServer($bind . ':' . $this->config->get('port'));
        $this->ingress = new IngressServer($tcp, $this->config);
        $socket = new SecureServer($this->ingress, null, $tls);
        $socket->on('error', function (): void {
            $this->logTransportError('tls_connection_error');
        });
        $this->sockets[] = $socket;
        $this->server->listen($socket);
        return (string) $socket->getAddress();
    }

    public function stop(): void
    {
        foreach ($this->sockets as $socket) {
            $socket->close();
        }
        $this->sockets = [];
    }

    /** Reject oversize or incomplete streaming bodies before authenticating/dispatching. */
    private function bufferRequest(ServerRequestInterface $request, callable $next): mixed
    {
        $body = $request->getBody();
        if ($body->getSize() !== null && $body->getSize() > 16384) {
            return $this->errorResponse(new RuntimeException('Request body is too large.', 413), null);
        }
        $dispatch = function (ServerRequestInterface $buffered) use ($next): mixed {
            $params = $buffered->getServerParams();
            $this->ingress?->requestReceived((string) ($params['REMOTE_ADDR'] ?? ''), (int) ($params['REMOTE_PORT'] ?? 0),
                (string) ($params['SERVER_ADDR'] ?? ''), (int) ($params['SERVER_PORT'] ?? 0));
            return $next($buffered);
        };
        if (!$body instanceof ReadableStreamInterface || $body->getSize() === 0) {
            return $dispatch($request);
        }
        $detach = static function (): void {};
        return new Promise(function ($resolve) use ($body, $request, $dispatch, &$detach): void {
            $buffer = '';
            $onData = $onEnd = $onError = $onClose = null;
            $detach = static function () use ($body, &$onData, &$onEnd, &$onError, &$onClose): void {
                $body->removeListener('data', $onData);
                $body->removeListener('end', $onEnd);
                $body->removeListener('error', $onError);
                $body->removeListener('close', $onClose);
            };
            $onData = function (string $data) use (&$buffer, $resolve, $body, &$detach): void {
                if (strlen($buffer) + strlen($data) > 16384) {
                    $detach();
                    $buffer = '';
                    $resolve($this->errorResponse(new RuntimeException('Request body is too large.', 413), null));
                    $body->close();
                    return;
                }
                $buffer .= $data;
            };
            $onEnd = function () use (&$buffer, $resolve, $request, $dispatch, &$detach): void {
                $detach();
                try { $resolve($dispatch($request->withBody(new BufferedBody($buffer)))); }
                catch (\Throwable $error) { $resolve($this->errorResponse($error, null)); }
                $buffer = '';
            };
            $onError = $onClose = function () use (&$buffer, $resolve, &$detach): void {
                $detach();
                $buffer = '';
                $resolve($this->errorResponse(new RuntimeException('Request body was not completed.', 400), null));
            };
            $body->on('data', $onData);
            $body->on('end', $onEnd);
            $body->on('error', $onError);
            $body->on('close', $onClose);
        }, static function () use ($body, &$detach): void {
            $detach();
            $body->close();
            throw new RuntimeException('Request was cancelled.', 400);
        });
    }

    /** Bound diagnostics from unauthenticated traffic; operation audit is separate. */
    private function logTransportError(string $event, array $fields = []): void
    {
        $now = hrtime(true) / 1e9;
        if ($now - ($this->lastErrorLog[$event] ?? -INF) >= 1.0) {
            $this->lastErrorLog[$event] = $now;
            $this->logger?->record($event, $fields);
        }
    }

    public function handle(ServerRequestInterface $request): PromiseInterface
    {
        $context = null;
        try {
            $path = $request->getUri()->getPath();
            if ($request->getMethod() !== 'POST') {
                throw new RuntimeException('Use POST.', 405);
            }
            if ($request->getUri()->getQuery() !== '' || $request->getUri()->getFragment() !== '') {
                throw new RuntimeException('Query strings are not accepted.', 400);
            }
            $body = (string) $request->getBody();
            if (strlen($body) > 16384) {
                throw new RuntimeException('Request body is too large.', 413);
            }
            $params = $request->getServerParams();
            $context = $this->auth->authenticate($request, (string) ($params['REMOTE_ADDR'] ?? ''), $body);
            if (!in_array($path, ['/v1/grants', '/v1/revocations', '/v1/support/grants', '/v1/support/revocations', '/v1/status'], true)) {
                throw new RuntimeException('Unknown endpoint.', 404);
            }
            if (!preg_match('/\Aapplication\/json(?:\s*;\s*charset=utf-8)?\z/iD', $request->getHeaderLine('Content-Type'))) {
                throw new RuntimeException('Content-Type must be application/json.', 415);
            }
            $decoded = json_decode($body, false, 16, JSON_THROW_ON_ERROR);
            if (!$decoded instanceof \stdClass) {
                throw new RuntimeException('Request must contain a JSON object.', 400);
            }
            return resolve(($this->dispatch)($path, (array) $decoded))->then(
                fn (mixed $result): Response => $this->response(200, ['ok' => true, 'result' => $result], $context),
                fn (\Throwable $error): Response => $this->errorResponse($error, $context)
            );
        } catch (\JsonException) {
            return resolve($this->errorResponse(new RuntimeException('Invalid JSON request.', 400), $context));
        } catch (\Throwable $error) {
            return resolve($this->errorResponse($error, $context));
        }
    }

    private function errorResponse(\Throwable $error, ?array $context): Response
    {
        $status = (int) $error->getCode();
        if (!in_array($status, [400, 401, 403, 404, 405, 409, 413, 415, 422, 429, 500, 502, 503, 504], true)) {
            $status = 500;
        }
        $this->logTransportError('api_error', ['http_status' => $status, 'error_code' => 'http_' . $status]);
        $message = match ($status) {
            400 => 'Invalid request.',
            401 => 'Authentication failed.',
            403 => 'Operation is not permitted.',
            404 => 'Endpoint or user was not found.',
            405 => 'Use POST.',
            409 => 'Operation conflicts with current state or repeats a used nonce.',
            413 => 'Request body is too large.',
            415 => 'Content-Type must be application/json.',
            422 => 'Request values cannot be processed.',
            429 => 'Too many pending requests.',
            502 => 'Directory adapter returned an invalid response.',
            503 => 'Agent is not ready or directory operation failed.',
            504 => 'Directory operation timed out; its outcome may be uncertain.',
            default => 'Internal agent error.',
        };
        return $this->response($status, ['ok' => false, 'error' => ['code' => 'http_' . $status, 'message' => $message]], $context);
    }

    private function response(int $status, array $payload, ?array $context): Response
    {
        $body = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $headers = ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store', 'X-Content-Type-Options' => 'nosniff', 'Connection' => 'close'];
        if ($context !== null) {
            $headers['X-2FA-Agent-Id'] = $this->config->get('agentId');
            $headers['X-2FA-Response-Signature'] = Auth::responseSignature($context['secret'], $this->config->get('agentId'), $context['nonce'], $status, $body);
        }
        return new Response($status, $headers, $body);
    }
}
