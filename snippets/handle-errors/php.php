<?php
require __DIR__ . '/vendor/autoload.php';

use Catalisa\Biometrics\BiometricsException;
use Catalisa\Biometrics\Client;

$bio = new Client(
    apiKey: getenv('CATALISA_API_KEY'),
    baseUrl: getenv('CATALISA_BIOMETRICS_URL') ?: 'https://api.biometrics.catalisa.app/v1',
    // organization key acting on behalf of the subaccount
    subaccountId: getenv('CATALISA_SUBACCOUNT_ID') ?: null,
);

try {
    $session = $bio->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'abertura de conta']);
    echo 'ok: ' . $session['handoff']['captureUrl'] . PHP_EOL;
} catch (BiometricsException $e) {
    if ($e->isQuotaExceeded()) {          // 402
        printf("blocked: %s — monthly quota used (%d/%d)\n",
            $e->errorCode, $e->details['used'], $e->details['monthlyQuota']);
    } elseif ($e->isSubaccountSuspended()) { // 403
        printf("blocked: %s — subaccount suspended\n", $e->errorCode);
    } elseif ($e->status === 429) {          // the SDK already retried
        printf("rate limited; retry in %d s\n", $e->retryAfter ?? 1);
    } else {
        fwrite(STDERR, sprintf("error %d: %s (requestId %s)\n", $e->status, $e->errorCode, $e->requestId ?? '-'));
        exit(1);
    }
}
