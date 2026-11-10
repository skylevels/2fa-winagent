<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use InvalidArgumentException;
use JsonException;

final class Config
{
    private array $values;

    public function __construct(array $values)
    {
        $defaults = [
            'bindAddress' => '0.0.0.0',
            'port' => 8443,
            'stub' => '2FA-BLOCK',
            'bypassGroup' => '2fabypass',
            'powershellPath' => 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            'requestSkewSeconds' => 30,
            'grantDurationSeconds' => 300,
            'supportDurationSeconds' => 60,
            'processTimeoutSeconds' => 30,
            'queueWaitTimeoutSeconds' => 2,
            'requestReceiveTimeoutSeconds' => 5,
            'maxConnections' => 100,
            'adminTimeoutSeconds' => 3600,
            'startEnabled' => true,
            'logDirectory' => 'C:\\2fa\\logs',
            'tlsCertificateFile' => 'C:\\2fa\\agent\\tls\\agent.crt.pem',
            'tlsPrivateKeyFile' => 'C:\\2fa\\agent\\tls\\agent.key.pem',
            'maxPendingRequests' => 100,
            'maxActiveGrants' => 10000,
            'maxRememberedRequests' => 20000,
        ];
        $known = array_merge(array_keys($defaults), ['agentId', 'allowedIPs', 'apiSecretHex', 'domainController']);
        foreach (array_keys($values) as $key) {
            if (!in_array($key, $known, true)) {
                throw new InvalidArgumentException('Unknown configuration field: ' . $key);
            }
        }
        $values += $defaults;
        foreach (['agentId', 'allowedIPs', 'apiSecretHex', 'domainController'] as $required) {
            if (!array_key_exists($required, $values)) {
                throw new InvalidArgumentException('Missing configuration field: ' . $required);
            }
        }
        $this->stringPattern($values, 'agentId', '/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z/D');
        $this->stringPattern($values, 'domainController', '/\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}\z/D');
        $this->stringPattern($values, 'stub', '/\A(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?\z/D');
        $this->stringPattern($values, 'bypassGroup', '/\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z/D');
        foreach (['apiSecretHex'] as $key) {
            $this->stringPattern($values, $key, '/\A[0-9a-fA-F]{64}\z/D');
            $values[$key] = strtolower($values[$key]);
            if (count(array_unique(str_split($values[$key]))) < 8) {
                throw new InvalidArgumentException($key . ' must be randomly generated, not a placeholder.');
            }
        }
        if (!is_string($values['bindAddress']) || filter_var($values['bindAddress'], FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('bindAddress must be an IP address.');
        }
        $values['bindAddress'] = self::normalizeIp($values['bindAddress']);
        if (!is_array($values['allowedIPs']) || !array_is_list($values['allowedIPs']) || count($values['allowedIPs']) < 1 || count($values['allowedIPs']) > 64) {
            throw new InvalidArgumentException('allowedIPs must contain between 1 and 64 exact IP addresses.');
        }
        $ips = [];
        foreach ($values['allowedIPs'] as $ip) {
            if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
                throw new InvalidArgumentException('allowedIPs accepts exact IP addresses only, not hostnames or networks.');
            }
            $ips[] = self::normalizeIp($ip);
        }
        $values['allowedIPs'] = array_values(array_unique($ips));
        foreach ([
            'port' => [1, 65535],
            'requestSkewSeconds' => [1, 300],
            'grantDurationSeconds' => [30, 600],
            'supportDurationSeconds' => [30, 180],
            'processTimeoutSeconds' => [1, 60],
            'queueWaitTimeoutSeconds' => [1, 30],
            'requestReceiveTimeoutSeconds' => [1, 30],
            'maxConnections' => [1, 1000],
            'adminTimeoutSeconds' => [60, 86400],
            'maxPendingRequests' => [1, 10000],
            'maxActiveGrants' => [1, 1000000],
            'maxRememberedRequests' => [100, 1000000],
        ] as $key => [$min, $max]) {
            if (!is_int($values[$key]) || $values[$key] < $min || $values[$key] > $max) {
                throw new InvalidArgumentException($key . ' must be an integer between ' . $min . ' and ' . $max . '.');
            }
        }
        if (!is_bool($values['startEnabled'])) {
            throw new InvalidArgumentException('startEnabled must be a boolean.');
        }
        if (!is_string($values['logDirectory']) || preg_match('/[\x00-\x1f\x7f]/', $values['logDirectory'])
            || !preg_match('/\A(?:[A-Za-z]:[\\\\\/][^\\\\\/]|\/[^\/])/', $values['logDirectory'])) {
            throw new InvalidArgumentException('logDirectory must be an absolute local directory path, not a drive root or network share.');
        }
        foreach (['tlsCertificateFile', 'tlsPrivateKeyFile'] as $key) {
            if (!is_string($values[$key]) || preg_match('/[\x00-\x1f\x7f]/', $values[$key])
                || !preg_match('/\A(?:[A-Za-z]:[\\\\\/][^\\\\\/]|\/[^\/])/', $values[$key])) {
                throw new InvalidArgumentException($key . ' must be an absolute local file path.');
            }
        }
        if (!is_string($values['powershellPath']) || str_contains($values['powershellPath'], "\0") || !preg_match('/\A(?:[A-Za-z]:[\\\\\/]|\/)/', $values['powershellPath'])) {
            throw new InvalidArgumentException('powershellPath must be an absolute executable path.');
        }
        $values['stub'] = strtoupper($values['stub']);
        $this->values = $values;
    }

    public static function load(string $path): self
    {
        if (!is_file($path) || !is_readable($path) || filesize($path) > 65536) {
            throw new InvalidArgumentException('Configuration file is missing, unreadable, or too large.');
        }
        try {
            $json = (string) file_get_contents($path);
            if (str_starts_with($json, "\xef\xbb\xbf")) {
                $json = substr($json, 3);
            }
            $decoded = json_decode($json, false, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidArgumentException('Configuration file contains invalid JSON.');
        }
        if (!$decoded instanceof \stdClass) {
            throw new InvalidArgumentException('Configuration must be a JSON object.');
        }
        return new self((array) $decoded);
    }

    public function get(string $key): mixed
    {
        if (!array_key_exists($key, $this->values)) {
            throw new InvalidArgumentException('Unknown configuration field: ' . $key);
        }
        return $this->values[$key];
    }

    public function directoryConfig(): array
    {
        return array_intersect_key($this->values, array_flip(['domainController', 'stub', 'bypassGroup']));
    }

    public static function normalizeIp(string $ip): string
    {
        // React's socket URI parser preserves brackets around IPv6 peers.
        if (str_starts_with($ip, '[') && str_ends_with($ip, ']')) {
            $ip = substr($ip, 1, -1);
        }
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return '';
        }
        if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $packed = substr($packed, 12);
        }
        return (string) inet_ntop($packed);
    }

    private function stringPattern(array $values, string $key, string $pattern): void
    {
        if (!is_string($values[$key]) || preg_match($pattern, $values[$key]) !== 1) {
            throw new InvalidArgumentException('Invalid configuration field: ' . $key);
        }
    }
}
