<?php
declare(strict_types=1);
require_once dirname(__DIR__) . '/vendor/autoload.php';

$GLOBALS['test_count'] ??= 0;
$GLOBALS['test_failures'] ??= 0;
function test(string $name, callable $body): void
{
    ++$GLOBALS['test_count'];
    try { $body(); echo "PASS $name\n"; }
    catch (Throwable $e) { ++$GLOBALS['test_failures']; echo "FAIL $name: {$e->getMessage()}\n"; }
}
function eq(mixed $actual, mixed $expected): void
{
    if ($actual !== $expected) {
        throw new RuntimeException('Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}
function awaitResult(React\Promise\PromiseInterface $promise): mixed
{
    $done = false; $result = null; $error = null;
    $promise->then(function ($value) use (&$done, &$result): void { $done = true; $result = $value; },
        function (Throwable $e) use (&$done, &$error): void { $done = true; $error = $e; });
    if (!$done) { throw new RuntimeException('Test promise did not settle synchronously.'); }
    if ($error) { throw $error; }
    return $result;
}
function expectError(callable $operation, int $code): void
{
    try { $operation(); } catch (Throwable $e) { eq($e->getCode(), $code); return; }
    throw new RuntimeException('Expected error ' . $code);
}
function testConfig(array $overrides = []): TwoFactorAgent\Config
{
    return new TwoFactorAgent\Config($overrides + [
        'agentId' => 'dc1', 'allowedIPs' => ['192.0.2.10'],
        'apiSecretHex' => str_repeat('0123456789abcdef', 4),
        'domainController' => 'dc1.example.test',
    ]);
}
