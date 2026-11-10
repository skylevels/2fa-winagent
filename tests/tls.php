<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';

use TwoFactorAgent\TlsContext;

function withTlsFixture(callable $test, string $purpose = 'serverAuth'): void
{
    $directory = sys_get_temp_dir() . '/2fa-tls-' . bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    try {
        $ini = $directory . '/openssl.cnf';
        file_put_contents($ini, "[req]\ndistinguished_name=dn\n[dn]\n[test_server]\nsubjectAltName=DNS:dc1.example.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={$purpose}\n");
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'config' => $ini]);
        $csr = openssl_csr_new(['commonName' => 'dc1.example.test'], $key, ['config' => $ini, 'digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($csr, null, $key, 1, ['config' => $ini, 'x509_extensions' => 'test_server', 'digest_alg' => 'sha256']);
        openssl_x509_export_to_file($certificate, $directory . '/certificate.pem');
        openssl_pkey_export_to_file($key, $directory . '/private.pem', null, ['config' => $ini]);
        $config = testConfig(['tlsCertificateFile' => $directory . '/certificate.pem', 'tlsPrivateKeyFile' => $directory . '/private.pem']);
        $test($config, $directory);
    } finally {
        foreach (glob($directory . '/*') ?: [] as $file) { unlink($file); }
        rmdir($directory);
    }
}

test('HTTPS uses matching server certificate with the DC DNS SAN and TLS 1.2 or newer', function (): void {
    withTlsFixture(function ($config): void {
        $tls = TlsContext::fromConfig($config);
        eq($tls['local_cert'], $config->get('tlsCertificateFile'));
        eq($tls['local_pk'], $config->get('tlsPrivateKeyFile'));
        eq($config->get('port'), 8443);
        eq(($tls['crypto_method'] & STREAM_CRYPTO_METHOD_TLSv1_2_SERVER) !== 0, true);
        eq(($tls['crypto_method'] & STREAM_CRYPTO_METHOD_TLSv1_0_SERVER) !== 0, false);
        eq(($tls['crypto_method'] & STREAM_CRYPTO_METHOD_TLSv1_1_SERVER) !== 0, false);
    });
});

test('HTTPS fails before listening for missing credentials or a certificate for another host', function (): void {
    withTlsFixture(function ($config, string $directory): void {
        transportThrows(fn () => TlsContext::fromConfig(testConfig([
            'domainController' => 'dc2.example.test', 'tlsCertificateFile' => $config->get('tlsCertificateFile'),
            'tlsPrivateKeyFile' => $config->get('tlsPrivateKeyFile'),
        ])));
        unlink($directory . '/private.pem');
        transportThrows(fn () => TlsContext::fromConfig($config));
    });
});

test('HTTPS rejects mismatched keys without exposing key material', function (): void {
    withTlsFixture(function ($config, string $directory): void {
        $otherKey = openssl_pkey_new(['private_key_bits' => 2048, 'config' => $directory . '/openssl.cnf']);
        openssl_pkey_export_to_file($otherKey, $directory . '/private.pem', null, ['config' => $directory . '/openssl.cnf']);
        try { TlsContext::fromConfig($config); }
        catch (RuntimeException $error) { eq(str_contains($error->getMessage(), 'PRIVATE KEY'), false); return; }
        throw new RuntimeException('Expected rejection of mismatched key.');
    });
});

test('TLS file configuration rejects relative paths and network shares', function (): void {
    foreach (['tlsCertificateFile', 'tlsPrivateKeyFile'] as $field) {
        foreach (['agent.pem', '\\\\server\\share\\agent.pem', "C:\\agent\n.pem"] as $path) {
            transportThrows(fn () => testConfig([$field => $path]));
        }
    }
});

test('TLS purpose validation requires the exact server-authentication OID', function (): void {
    withTlsFixture(function ($config): void {
        transportThrows(fn () => TlsContext::fromConfig($config));
    }, '1.3.6.1.5.5.7.3.100');
});
