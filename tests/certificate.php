<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
require_once dirname(__DIR__) . '/bin/export-certificate.php';

function certificateFixture(string $directory, string $dnsName = 'dosifey.elemer.org', int $days = 3650, string $eku = 'serverAuth'): array
{
    static $key;
    $key ??= openssl_pkey_new(['private_key_bits' => 3072, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    $id = bin2hex(random_bytes(4));
    $configuration = $directory . '/' . $id . '.cnf';
    file_put_contents($configuration, "[req]\ndistinguished_name=dn\n[dn]\n[v3_req]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=$eku\nsubjectAltName=DNS:$dnsName\n");
    $csr = openssl_csr_new(['commonName' => $dnsName], $key, ['config' => $configuration, 'digest_alg' => 'sha256', 'req_extensions' => 'v3_req']);
    $certificate = openssl_csr_sign($csr, null, $key, $days, ['config' => $configuration, 'digest_alg' => 'sha256', 'x509_extensions' => 'v3_req']);
    $password = bin2hex(random_bytes(32));
    $pfxPath = $directory . '/' . $id . '.pfx';
    if (!openssl_pkcs12_export_to_file($certificate, $pfxPath, $key, $password)) { throw new RuntimeException('Unable to create PFX test data.'); }
    $output = $directory . '/' . $id;
    mkdir($output, 0700);
    return ['pfxPath' => $pfxPath, 'password' => $password, 'outputDirectory' => $output, 'dnsName' => 'dosifey.elemer.org', 'expectedValiditySeconds' => 3650 * 86400];
}

function certificateTest(callable $body): void
{
    $directory = sys_get_temp_dir() . '/2fa-certificate-test-' . bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    try { $body($directory); }
    finally {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($directory);
    }
}

test('certificate export preserves the matching key and ten-year server certificate', fn () => certificateTest(function (string $directory): void {
    $request = certificateFixture($directory);
    $result = exportAgentCertificate($request);
    eq($result['ok'], true);
    eq($result['dns_name'], 'dosifey.elemer.org');
    $certificate = file_get_contents($request['outputDirectory'] . '/agent.crt.pem');
    $key = file_get_contents($request['outputDirectory'] . '/agent.key.pem');
    eq(openssl_x509_check_private_key($certificate, $key), true);
    eq(str_contains(json_encode($result), 'PRIVATE KEY'), false);
}));

test('certificate export rejects a different SAN before writing private keys', fn () => certificateTest(function (string $directory): void {
    $request = certificateFixture($directory, 'pimen.elemer.org');
    expectError(fn () => exportAgentCertificate($request), 0);
    eq(glob($request['outputDirectory'] . '/*'), []);
}));

test('certificate export rejects a short validity and non-server EKU', fn () => certificateTest(function (string $directory): void {
    foreach ([certificateFixture($directory, days: 365), certificateFixture($directory, eku: 'clientAuth')] as $request) {
        expectError(fn () => exportAgentCertificate($request), 0);
        eq(glob($request['outputDirectory'] . '/*'), []);
    }
}));

test('certificate export refuses existing output without modifying it', fn () => certificateTest(function (string $directory): void {
    $request = certificateFixture($directory);
    file_put_contents($request['outputDirectory'] . '/agent.key.pem', 'existing key');
    expectError(fn () => exportAgentCertificate($request), 0);
    eq(file_get_contents($request['outputDirectory'] . '/agent.key.pem'), 'existing key');
    eq(is_file($request['outputDirectory'] . '/agent.crt.pem'), false);
}));

test('certificate export rejects a wrong PFX password without creating output', fn () => certificateTest(function (string $directory): void {
    $request = certificateFixture($directory);
    $request['password'] = str_repeat('f', 64);
    expectError(fn () => exportAgentCertificate($request), 0);
    eq(glob($request['outputDirectory'] . '/*'), []);
}));
