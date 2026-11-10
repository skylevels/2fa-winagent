<?php
declare(strict_types=1);

namespace TwoFactorAgent;

use RuntimeException;

final class TlsContext
{
    /** Validate before listening; React otherwise discovers bad credentials only at handshake. */
    public static function fromConfig(Config $config): array
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('PHP OpenSSL is required for HTTPS.');
        }
        $certificatePath = $config->get('tlsCertificateFile');
        $keyPath = $config->get('tlsPrivateKeyFile');
        foreach ([$certificatePath, $keyPath] as $path) {
            if (!is_file($path) || !is_readable($path) || is_link($path) || filesize($path) > 1048576) {
                throw new RuntimeException('TLS certificate or private key is unavailable.');
            }
        }
        $certificate = @openssl_x509_read((string) file_get_contents($certificatePath));
        $key = @openssl_pkey_get_private((string) file_get_contents($keyPath), '');
        if ($certificate === false || $key === false || !@openssl_x509_check_private_key($certificate, $key)) {
            throw new RuntimeException('TLS certificate and private key are invalid or do not match.');
        }
        $details = openssl_x509_parse($certificate);
        $now = time();
        if ($details === false || ($details['validFrom_time_t'] ?? PHP_INT_MAX) > $now
            || ($details['validTo_time_t'] ?? 0) <= $now) {
            throw new RuntimeException('TLS certificate is outside its validity period.');
        }
        $names = array_map('trim', explode(',', strtolower($details['extensions']['subjectAltName'] ?? '')));
        if (!in_array('dns:' . strtolower($config->get('domainController')), $names, true)) {
            throw new RuntimeException('TLS certificate must name this domain controller in its DNS SAN.');
        }
        $usages = array_map('trim', explode(',', $details['extensions']['extendedKeyUsage'] ?? ''));
        if (!in_array('TLS Web Server Authentication', $usages, true) && !in_array('1.3.6.1.5.5.7.3.1', $usages, true)) {
            throw new RuntimeException('TLS certificate must allow Server Authentication.');
        }
        if (str_contains($details['extensions']['basicConstraints'] ?? '', 'CA:TRUE')) {
            throw new RuntimeException('A CA certificate cannot be used as the API server certificate.');
        }
        return [
            'local_cert' => $certificatePath,
            'local_pk' => $keyPath,
            'passphrase' => '',
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_SERVER
                | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER') ? STREAM_CRYPTO_METHOD_TLSv1_3_SERVER : 0),
            // Client identity is authenticated by the source IP and signed request.
            'verify_peer' => false,
            'disable_compression' => true,
        ];
    }
}
