<?php
// Receives the Biometrics webhook and verifies the signature (PHP 8 + ext-openssl).
// Run: php -S 0.0.0.0:3000 php.php   |   CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
function header_value(string $name): ?string {
    return $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $name))] ?? null;
}

$rawBody = file_get_contents('php://input'); // RAW body
$id = header_value('x-webhook-id');
$timestamp = header_value('x-webhook-timestamp');
$keyId = header_value('x-webhook-key-id');
$signature = header_value('x-webhook-signature');
$publicKeys = json_decode(getenv('CATALISA_WEBHOOK_KEYS'), true);

$valid = $id && $timestamp && $keyId && $signature
    && abs(time() - strtotime($timestamp)) <= 300           // replay tolerance
    && isset($publicKeys[$keyId])                            // key selected by key id
    && str_starts_with($signature, 'v1=')
    && openssl_verify("$id\n$timestamp\n$rawBody", base64_decode(substr($signature, 3)), $publicKeys[$keyId], OPENSSL_ALGO_SHA256) === 1;

if (!$valid) {
    http_response_code(400);
    exit('invalid signature');
}
$event = json_decode($rawBody, true);
// Idempotency: use $event['id'] (stable), not the x-webhook-id header.
if ($event['type'] === 'biometrics.session.completed') {
    error_log("session {$event['data']['sessionId']} → {$event['data']['outcome']}");
}
echo 'ok';
