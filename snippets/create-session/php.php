<?php
// composer require catalisa/biometrics
require __DIR__ . '/vendor/autoload.php';

use Catalisa\Biometrics\Client;

$bio = new Client(
    apiKey: getenv('CATALISA_API_KEY'),
    baseUrl: getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1',
);

$session = $bio->createSession([
    'flow' => 'LIVENESS_ONLY',
    'purpose' => 'abertura de conta',
    'metadata' => ['orderId' => '123'],
]);

echo 'sessionId: ' . $session['sessionId'] . PHP_EOL;
echo 'captureUrl: ' . $session['handoff']['captureUrl'] . PHP_EOL; // send the person here
