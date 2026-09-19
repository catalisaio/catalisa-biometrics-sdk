<?php
// Handles 402 (subaccount quota) and 403 (suspended subaccount) when creating a session.
$baseUrl = getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1';

$ch = curl_init("$baseUrl/sessions");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        'X-API-Key: ' . getenv('CATALISA_API_KEY'),
        'X-Subaccount-Id: ' . getenv('CATALISA_SUBACCOUNT_ID'),
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode(['flow' => 'LIVENESS_ONLY', 'purpose' => 'abertura de conta']),
]);
$body = json_decode(curl_exec($ch), true);
$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
$code = $body['details']['code'] ?? $body['error'] ?? '';

if ($status === 201) {
    echo "ok: {$body['data']['handoff']['captureUrl']}\n";
} elseif ($status === 402 && $code === 'QUOTA_EXCEEDED') {
    echo "blocked: QUOTA_EXCEEDED — monthly quota used ({$body['details']['used']}/{$body['details']['monthlyQuota']})\n";
} elseif ($status === 403 && $code === 'SUBACCOUNT_SUSPENDED') {
    echo "blocked: SUBACCOUNT_SUSPENDED — subaccount suspended\n";
} else {
    fwrite(STDERR, "error $status: $code\n");
    exit(1);
}
