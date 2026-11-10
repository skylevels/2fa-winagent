#!/usr/bin/env python3
"""Local HTTPS integration checks, separate from the PHP unit test runner.

Requires Python 3, OpenSSL CLI and PHP with the installed Composer dependencies.
Example: python3 tests/https_ingress.py --php /path/to/php
Uses ephemeral loopback ports, a temporary certificate and a random test key.
The directory adapter is replaced with a delayed response; no AD calls occur.
"""

import argparse
import errno
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time


SERVER_NAME = "dc1.example.test"
PROJECT = Path(__file__).resolve().parents[1]
PHP_FIXTURE = r"""<?php
require $argv[2];
$config = TwoFactorAgent\Config::load($argv[1]);
$server = new TwoFactorAgent\HttpServer($config, static function ($path, $payload) {
    $deferred = new React\Promise\Deferred();
    React\EventLoop\Loop::addTimer(1.2, static fn () => $deferred->resolve(['path' => $path]));
    return $deferred->promise();
});
$server->start();
fwrite(STDOUT, "READY\n");
fflush(STDOUT);
React\EventLoop\Loop::run();
"""


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def available_port(host, family):
    with socket.socket(family) as probe:
        probe.bind((host, 0))
        return probe.getsockname()[1]


def closed(connection):
    try:
        return connection.recv(4096) == b""
    except (ConnectionResetError, ssl.SSLEOFError):
        return True


def run_checks(php, directory, host, family, port, secret, context):
    config = {
        "agentId": "audit", "allowedIPs": [host], "bindAddress": host,
        "port": port, "domainController": SERVER_NAME, "apiSecretHex": secret,
        "tlsCertificateFile": str(directory / "cert.pem"),
        "tlsPrivateKeyFile": str(directory / "key.pem"),
        "requestReceiveTimeoutSeconds": 1, "maxConnections": 2,
    }
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    process = subprocess.Popen(
        [php, str(directory / "server.php"), str(config_path), str(PROJECT / "vendor/autoload.php")],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        ready = queue.Queue()
        threading.Thread(target=lambda: ready.put(process.stdout.readline()), daemon=True).start()
        try:
            check(ready.get(timeout=10) == "READY\n", "PHP HTTPS listener did not start")
        except queue.Empty as error:
            raise RuntimeError("PHP HTTPS listener startup exceeded 10 seconds") from error

        def raw():
            connection = socket.socket(family)
            connection.settimeout(3)
            try:
                connection.connect((host, port))
            except Exception:
                connection.close()
                raise
            return connection

        def tls():
            connection = raw()
            try:
                return context.wrap_socket(connection, server_hostname=SERVER_NAME)
            except Exception:
                connection.close()
                raise

        if family == socket.AF_INET:
            with socket.socket() as connection:
                connection.settimeout(1)
                connection.bind(("127.0.0.2", 0))
                connection.connect((host, port))
                check(closed(connection), "Untrusted source IP reached TLS")

            with raw() as first, raw() as second:
                with raw() as excess:
                    check(closed(excess), "Connection capacity did not reject the third peer")
                started = time.monotonic()
                check(closed(first) and closed(second), "Stalled TLS connections remained open")
                check(time.monotonic() - started < 1.8, "TLS receive deadline was not enforced")

            with tls() as connection:
                started = time.monotonic()
                connection.sendall(f"POST /v1/status HTTP/1.1\r\nHost: {SERVER_NAME}\r\n".encode())
                check(closed(connection), "Incomplete headers remained open")
                check(time.monotonic() - started < 1.8, "Header receive deadline was not enforced")

            with tls() as connection:
                connection.sendall(
                    (f"POST /v1/status HTTP/1.1\r\nHost: {SERVER_NAME}\r\n"
                     "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4001\r\n").encode()
                    + b"x" * 16385 + b"\r\n"
                )
                started = time.monotonic()
                response = http.client.HTTPResponse(connection)
                response.begin()
                response.read()
                check(response.status == 413, "Oversize chunked body was not rejected")
                check(time.monotonic() - started < 0.8, "Oversize rejection waited for the final chunk")

            with tls() as connection:
                started = time.monotonic()
                connection.sendall(
                    (f"POST /v1/status HTTP/1.1\r\nHost: {SERVER_NAME}\r\n"
                     "Content-Type: application/json\r\nContent-Length: 10\r\n\r\n{").encode()
                )
                check(closed(connection), "Incomplete body remained open")
                check(time.monotonic() - started < 1.8, "Body receive deadline was not enforced")

        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        body = b"{}"
        signature = hmac.new(bytes.fromhex(secret), "\n".join([
            "POST", "/v1/status", "audit", timestamp, nonce, hashlib.sha256(body).hexdigest(),
        ]).encode(), hashlib.sha256).hexdigest()
        request = (
            f"POST /v1/status HTTP/1.1\r\nHost: {SERVER_NAME}\r\n"
            "Content-Type: application/json\r\nContent-Length: 2\r\nX-2FA-Key-Id: mobile\r\n"
            f"X-2FA-Timestamp: {timestamp}\r\nX-2FA-Nonce: {nonce}\r\n"
            f"X-2FA-Signature: {signature}\r\n\r\n"
        ).encode() + body
        with tls() as connection:
            started = time.monotonic()
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            result = response.read()
            check(response.status == 200, "Valid signed request did not succeed")
            check(response.getheader("Connection") == "close", "Connection was retained after the response")
            check(time.monotonic() - started > 1.0, "Processing did not cross the receive deadline")
            expected = hmac.new(bytes.fromhex(secret), "\n".join([
                "RESPONSE", "audit", nonce, "200", hashlib.sha256(result).hexdigest(),
            ]).encode(), hashlib.sha256).hexdigest()
            check(hmac.compare_digest(response.getheader("X-2FA-Response-Signature", ""), expected),
                  "Response HMAC did not match")
        label = "IPv4 HTTPS ingress/authentication/deadlines" if family == socket.AF_INET else "IPv6 HTTPS authentication/deadline boundary"
        print("PASS " + label)
    finally:
        process.terminate()
        try:
            output, errors = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, errors = process.communicate(timeout=5)
        if errors or output:
            print((errors + output).strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--php", default=os.environ.get("PHP_BINARY", "php"), help="PHP CLI executable (or PHP_BINARY)")
    parser.add_argument("--openssl", default="openssl", help="OpenSSL CLI executable")
    args = parser.parse_args()
    if not (PROJECT / "vendor/autoload.php").is_file():
        parser.error("Composer dependencies are missing: install them in windows-agent first")
    with tempfile.TemporaryDirectory(prefix="2fa-https-test-") as temporary:
        directory = Path(temporary)
        subprocess.run([
            args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", f"/CN={SERVER_NAME}", "-addext", f"subjectAltName=DNS:{SERVER_NAME}",
            "-addext", "extendedKeyUsage=serverAuth", "-addext", "basicConstraints=critical,CA:FALSE",
            "-keyout", str(directory / "key.pem"), "-out", str(directory / "cert.pem"),
        ], check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (directory / "server.php").write_text(PHP_FIXTURE, encoding="utf-8")
        secret = secrets.token_hex(32)
        context = ssl.create_default_context(cafile=str(directory / "cert.pem"))
        run_checks(args.php, directory, "127.0.0.1", socket.AF_INET,
                   available_port("127.0.0.1", socket.AF_INET), secret, context)
        if not socket.has_ipv6:
            print("SKIP IPv6: this Python runtime has no IPv6 support")
            return
        try:
            port = available_port("::1", socket.AF_INET6)
        except OSError as error:
            if error.errno not in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT, errno.ENODEV):
                raise
            print(f"SKIP IPv6: loopback ::1 is unavailable ({error})")
            return
        run_checks(args.php, directory, "::1", socket.AF_INET6, port, secret, context)


if __name__ == "__main__":
    main()
