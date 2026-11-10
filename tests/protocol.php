<?php
declare(strict_types=1);
require_once __DIR__ . '/bootstrap.php';
use TwoFactorAgent\Auth;

test('HMAC request and response match independently generated protocol vector', function (): void {
    $v=json_decode(file_get_contents(dirname(__DIR__).'/docs/hmac-test-vector.json'),true,32,JSON_THROW_ON_ERROR);
    $secret=hex2bin($v['key_hex']);
    eq(Auth::requestSignature($secret,$v['method'],$v['path'],$v['agent_id'],$v['timestamp'],$v['nonce'],$v['body']),$v['request_signature']);
    eq(Auth::responseSignature($secret,$v['agent_id'],$v['nonce'],$v['response_status'],$v['response_body']),$v['response_signature']);
});
