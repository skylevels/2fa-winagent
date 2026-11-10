#!/usr/bin/env php
<?php
declare(strict_types=1);

use React\EventLoop\Loop;
use TwoFactorAgent\Config;
use TwoFactorAgent\AuditLogger;
use TwoFactorAgent\GrantManager;
use TwoFactorAgent\HttpServer;
use TwoFactorAgent\LocalAdminServer;
use TwoFactorAgent\PowerShellGateway;

$autoload = dirname(__DIR__) . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "Dependencies are missing. Run composer install in the agent directory.\n");
    exit(78);
}
require $autoload;

if ($argc !== 3 || $argv[1] !== '--config') {
    fwrite(STDERR, "Usage: php bin/agent.php --config C:\\path\\config.json\n");
    exit(64);
}

$logger = null;
$local = null;
try {
    $config = Config::load($argv[2]);
    $logger = new AuditLogger($config);
    register_shutdown_function(static function () use ($logger, &$local): void {
        $local?->stop();
        $error = error_get_last();
        $fatal = $error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true);
        $logger->record($fatal ? 'agent_crashed' : 'agent_stopped', $fatal ? ['error_code' => 'php_fatal'] : []);
    });
    $gateway = new PowerShellGateway($config);
    $manager = new GrantManager($config, $gateway, null, null, $logger);
    $server = new HttpServer($config, [$manager, 'handle'], $logger);
    $local = new LocalAdminServer($config, $manager, $logger);
    $manager->initialize()->then(
        function () use ($manager, $server, $local, $config, $logger): void {
            try {
                $address = str_replace('tls://', 'https://', $server->start());
                $local->start();
                $logger->record('agent_started', ['listen' => $address, 'enabled' => $config->get('startEnabled')]);
                Loop::addPeriodicTimer(1.0, static function () use ($manager): void {
                    $manager->tick();
                });
                fwrite(STDERR, json_encode(['event' => 'agent_started', 'agentId' => $config->get('agentId'), 'listen' => $address], JSON_UNESCAPED_SLASHES) . "\n");
            } catch (\Throwable) {
                $server->stop();
                $local->stop();
                $logger->record('agent_start_failed', ['error_code' => 'listener_unavailable']);
                fwrite(STDERR, "Unable to start HTTPS or local administration. Check TLS certificate, private key, port and Windows pipe access.\n");
                Loop::stop();
                exit(1);
            }
        },
        static function () use ($logger): void {
            $logger->record('agent_start_failed', ['error_code' => 'initialization_failed']);
            fwrite(STDERR, "Agent initialization failed. Check the configuration and directory adapter.\n");
            Loop::stop();
            exit(1);
        }
    );
    Loop::run();
} catch (\Throwable $error) {
    $logger?->record('agent_start_failed', ['error_code' => 'configuration_or_runtime_error']);
    // Configuration errors contain field names only; do not dump exception traces or secrets.
    fwrite(STDERR, $error instanceof \InvalidArgumentException ? $error->getMessage() . "\n" : "Agent startup failed.\n");
    exit(1);
}
