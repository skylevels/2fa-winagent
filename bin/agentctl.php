#!/usr/bin/env php
<?php
declare(strict_types=1);

use TwoFactorAgent\LocalAdminServer;
use TwoFactorAgent\Config;

$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "Dependencies are missing. Run composer install in the agent directory.\n");
    exit(78);
}
require $autoload;

function usage(): never
{
    fwrite(STDERR, "Usage: php bin/agentctl.php --config PATH status|enable|disable|ensure-bypass [--apply]\n");
    exit(64);
}

if ($argc < 4 || $argc > 5 || $argv[1] !== '--config' || ($argc === 5 && $argv[4] !== '--apply')) {
    usage();
}
$command = $argv[3];
if (!in_array($command, ['status', 'enable', 'disable', 'ensure-bypass'], true)) {
    usage();
}
$apply = $argc === 5;
if ($command === 'ensure-bypass' && !$apply) {
    fwrite(STDERR, "Use ensure-bypass --apply to create the group explicitly.\n");
    exit(64);
}
if ($command === 'status' && $apply) {
    usage();
}

try {
    $config = Config::load($argv[2]);
    if (PHP_OS_FAMILY !== 'Windows') {
        throw new RuntimeException('Console administration is available only on the Windows server running the agent.');
    }
    $input = json_encode(['secretHex' => $config->get('apiSecretHex'), 'command' => $command,
        'dryRun' => $command === 'status' ? false : !$apply], JSON_THROW_ON_ERROR);
    $timeout = in_array($command, ['enable', 'disable'], true)
        ? $config->get('adminTimeoutSeconds') : $config->get('processTimeoutSeconds') + 10;
    $child = [$config->get('powershellPath'), '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
        dirname(__DIR__) . '/powershell/LocalAdmin.ps1', '-Mode', 'Client',
        '-PipeName', LocalAdminServer::pipeName($config->get('agentId')), '-TimeoutSeconds', (string) $timeout];
    $pipes = [];
    $process = @proc_open($child, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__), null,
        ['bypass_shell' => true, 'create_process_group' => true]);
    if (!is_resource($process)) {
        throw new RuntimeException('Unable to start the local console client.');
    }
    $written = fwrite($pipes[0], $input);
    fclose($pipes[0]);
    $deadline = hrtime(true) / 1e9 + $timeout + 15;
    $timedOut = $written !== strlen($input);
    do {
        $status = proc_get_status($process);
        if (!$status['running']) { break; }
        if ($timedOut || hrtime(true) / 1e9 >= $deadline) {
            $timedOut = true;
            @proc_terminate($process, 9);
        }
        usleep(50000);
    } while (true);
    $result = stream_get_contents($pipes[1], 3001);
    $stderr = stream_get_contents($pipes[2], 3001);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    if ($timedOut || $result === false || strlen($result) > 2800 || $stderr !== '') {
        throw new RuntimeException('No valid local console response. The operation may continue; check status before repeating it.');
    }
    $decoded = json_decode($result, true, 32, JSON_THROW_ON_ERROR);
    fwrite(STDOUT, json_encode($decoded, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    $resultData = $decoded['result'] ?? [];
    $partial = ($resultData['status'] ?? '') === 'partial'
        || (($resultData['status'] ?? '') === 'group_ready' && ($resultData['ready'] ?? false) !== true)
        || (($resultData['summary']['failed'] ?? 0) > 0);
    exit($status['exitcode'] === 0 && ($decoded['ok'] ?? false) === true && !$partial ? 0 : 1);
} catch (Throwable $error) {
    fwrite(STDERR, $error->getMessage() . "\n");
    exit(1);
}
