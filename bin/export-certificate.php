#!/usr/bin/env php
<?php
declare(strict_types=1);

// Called only by the elevated enrollment script. Passwords arrive through stdin,
// never the process command line. The caller protects the staging directory.
function exportAgentCertificate(array $request): array
{
    foreach (['pfxPath', 'password', 'outputDirectory', 'dnsName'] as $name) {
        if (!isset($request[$name]) || !is_string($request[$name]) || str_contains($request[$name], "\0")) {
            throw new RuntimeException('Invalid certificate export input.');
        }
    }
    if (!preg_match('/\A[0-9a-f]{64}\z/D', $request['password'])
        || !preg_match('/\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}\z/D', $request['dnsName'])) {
        throw new RuntimeException('Invalid certificate export input.');
    }
    $directory = realpath($request['outputDirectory']);
    if ($directory === false || !is_dir($directory) || is_link($request['outputDirectory'])
        || !is_file($request['pfxPath']) || is_link($request['pfxPath']) || filesize($request['pfxPath']) > 1048576) {
        throw new RuntimeException('Certificate export files are unavailable.');
    }
    $parts = [];
    if (!@openssl_pkcs12_read((string) file_get_contents($request['pfxPath']), $parts, $request['password'])) {
        throw new RuntimeException('Unable to decrypt the temporary certificate export.');
    }
    $certificate = @openssl_x509_read($parts['cert'] ?? '');
    $privateKey = @openssl_pkey_get_private($parts['pkey'] ?? '');
    if ($certificate === false || $privateKey === false || !@openssl_x509_check_private_key($certificate, $privateKey)) {
        throw new RuntimeException('The certificate and private key do not match.');
    }
    $details = openssl_x509_parse($certificate, false);
    $names = array_map('trim', explode(',', strtolower($details['extensions']['subjectAltName'] ?? '')));
    if (!in_array('dns:' . strtolower($request['dnsName']), $names, true)) {
        throw new RuntimeException('The certificate SAN does not contain this domain controller.');
    }
    $purposes = array_map('trim', explode(',', $details['extensions']['extendedKeyUsage'] ?? ''));
    if (!in_array('TLS Web Server Authentication', $purposes, true) && !in_array('1.3.6.1.5.5.7.3.1', $purposes, true)) {
        throw new RuntimeException('The certificate does not permit TLS server authentication.');
    }
    $now = time();
    $notBefore = (int) ($details['validFrom_time_t'] ?? 0);
    $notAfter = (int) ($details['validTo_time_t'] ?? 0);
    $expectedSeconds = $request['expectedValiditySeconds'] ?? null;
    if (!is_int($expectedSeconds) || $expectedSeconds < 3650 * 86400 || $expectedSeconds > 3653 * 86400) {
        throw new RuntimeException('An expected ten-year template interval is required.');
    }
    $minimum = $notBefore + $expectedSeconds - 86400;
    if ($notBefore > $now + 300 || $notAfter <= $now || $notAfter < $minimum) {
        throw new RuntimeException('The certificate is not current or its validity is shorter than ten years.');
    }
    $keyDetails = openssl_pkey_get_details($privateKey);
    if ($keyDetails === false || $keyDetails['type'] !== OPENSSL_KEYTYPE_RSA || $keyDetails['bits'] < 3072) {
        throw new RuntimeException('The certificate requires an RSA key of at least 3072 bits.');
    }
    $written = [];
    try {
        foreach (['agent.crt.pem' => $parts['cert'], 'agent.key.pem' => $parts['pkey']] as $name => $content) {
            $path = $directory . DIRECTORY_SEPARATOR . $name;
            $handle = @fopen($path, 'xb');
            if ($handle === false) { throw new RuntimeException('Refusing to overwrite existing certificate files.'); }
            $written[] = $path;
            try {
                if (fwrite($handle, $content) !== strlen($content) || !fflush($handle)) {
                    throw new RuntimeException('Certificate export could not be written completely.');
                }
            } finally { fclose($handle); }
        }
    } catch (Throwable $error) {
        foreach ($written as $path) { @unlink($path); }
        throw $error;
    }
    return ['ok' => true, 'thumbprint' => strtoupper(openssl_x509_fingerprint($certificate, 'sha1')),
        'dns_name' => strtolower($request['dnsName']), 'not_before' => gmdate('c', $notBefore), 'not_after' => gmdate('c', $notAfter)];
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        if (PHP_VERSION_ID < 80200 || !extension_loaded('openssl')) { throw new RuntimeException('PHP 8.2 or newer with OpenSSL is required.'); }
        if ($argc === 2 && $argv[1] === '--check') { exit(0); }
        if ($argc !== 1) { throw new RuntimeException('Invalid certificate export input.'); }
        $input = stream_get_contents(STDIN, 8193);
        if ($input === false || strlen($input) > 8192) { throw new RuntimeException('Invalid certificate export input.'); }
        $request = json_decode($input, true, 8, JSON_THROW_ON_ERROR);
        if (!is_array($request)) { throw new RuntimeException('Invalid certificate export input.'); }
        fwrite(STDOUT, json_encode(exportAgentCertificate($request), JSON_THROW_ON_ERROR) . "\n");
    } catch (Throwable $error) {
        // No stack traces, raw input, private keys or OpenSSL error queues.
        fwrite(STDERR, $error instanceof RuntimeException ? $error->getMessage() . "\n" : "Certificate export failed.\n");
        exit(1);
    }
}
