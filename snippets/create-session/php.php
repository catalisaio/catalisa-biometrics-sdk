<?php
// Creates a liveness session (PHP 8 + ext-curl).
$baseUrl = getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1';

$ch = curl_init("$baseUrl/sessions");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        'X-API-Key: ' . getenv('CATALISA_API_KEY'),
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'flow' => 'LIVENESS_ONLY',
        'purpose' => 'abertura de conta',
        'metadata' => ['orderId' => '123'],
    ]),
]);
$body = json_decode(curl_exec($ch), true);
$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

if ($status !== 201) {
    fwrite(STDERR, "Error $status: " . ($body['details']['code'] ?? $body['error'] ?? '') . "\n");
    exit(1);
}
echo 'sessionId: ' . $body['data']['sessionId'] . PHP_EOL;
echo 'captureUrl: ' . $body['data']['handoff']['captureUrl'] . PHP_EOL;
