<?php
require __DIR__ . '/vendor/autoload.php';

use Catalisa\Biometrics\BiometricsException;
use Catalisa\Biometrics\Client;

$bio = new Client(
    apiKey: getenv('CATALISA_API_KEY'),
    baseUrl: getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1',
);

try {
    $session = $bio->getSession(getenv('SESSION_ID'));
    echo 'status: ' . $session['status'] . PHP_EOL;
    if ($session['decision'] ?? null) {
        echo 'decision: ' . $session['decision']['outcome'] . ' '
            . (implode(', ', $session['decision']['reasons']) ?: '(no reasons)') . PHP_EOL;
        foreach ($session['checks'] as $check) {
            printf(" - %s: %s (score %s / threshold %s)\n",
                $check['kind'], $check['status'], $check['score'], $check['threshold']);
        }
    }
} catch (BiometricsException $e) {
    if ($e->status === 404) {
        echo 'Session not found (or owned by another organization)' . PHP_EOL;
    } else {
        throw $e;
    }
}
