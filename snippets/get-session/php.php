<?php
// Reads the session envelope (PHP 8 + ext-curl).
$baseUrl = getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1';

$ch = curl_init("$baseUrl/sessions/" . rawurlencode(getenv('SESSION_ID')));
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ['X-API-Key: ' . getenv('CATALISA_API_KEY')],
]);
$body = json_decode(curl_exec($ch), true);
$status = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

if ($status !== 200) {
    fwrite(STDERR, "Error $status: " . ($body['error'] ?? '') . "\n");
    exit(1);
}
$session = $body['data'];
echo "status: {$session['status']}\n";
if ($session['decision']) {
    echo "decision: {$session['decision']['outcome']}\n";
    foreach ($session['checks'] as $c) {
        echo " - {$c['kind']}: {$c['status']} (score {$c['score']} / threshold {$c['threshold']})\n";
    }
}
