<?php
// Minimal server that receives the Biometrics webhook and verifies the signature.
// Run: php -S 0.0.0.0:3000 php.php
// CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
require __DIR__ . '/vendor/autoload.php';

use Catalisa\Biometrics\WebhookVerificationException;
use Catalisa\Biometrics\WebhookVerifier;

$verifier = new WebhookVerifier(json_decode(getenv('CATALISA_WEBHOOK_KEYS'), true)); // tolerance: 300 s

$rawBody = file_get_contents('php://input'); // RAW body: re-encoding it breaks the signature

try {
    $event = $verifier->verify($_SERVER, $rawBody);
} catch (WebhookVerificationException $e) {
    error_log('webhook rejected: ' . $e->failure);
    http_response_code(400);
    exit('invalid signature');
}

// $event['id'] is stable: use it for idempotency, a delivery can repeat
if ($event['type'] === 'biometrics.session.completed') {
    error_log("session {$event['data']['sessionId']} → {$event['data']['outcome']}");
}

http_response_code(200); // answer fast; do the work afterwards
echo 'ok';
