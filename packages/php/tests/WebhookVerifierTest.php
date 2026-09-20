<?php

declare(strict_types=1);

namespace Catalisa\Biometrics\Tests;

use Catalisa\Biometrics\Evidence;
use Catalisa\Biometrics\WebhookVerificationException;
use Catalisa\Biometrics\WebhookVerifier;
use PHPUnit\Framework\TestCase;

/**
 * The vectors are shared by every SDK in this repository and were produced by the
 * building block's own signing code, so "it passes here" means the same thing in
 * each language.
 */
final class WebhookVerifierTest extends TestCase
{
    /** @return array<string,mixed> */
    private function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../vectors/vectors.json'), true);
    }

    private function verifierAt(array $webhook, ?string $when = null, int $tolerance = 300): WebhookVerifier
    {
        return new WebhookVerifier(
            $webhook['keys'],
            $tolerance,
            new \DateTimeImmutable($when ?? $webhook['now']),
        );
    }

    public function testAcceptsAGenuineDelivery(): void
    {
        $webhook = $this->vectors()['webhook'];

        $event = $this->verifierAt($webhook)->verify($webhook['headers'], $webhook['body']);

        self::assertNotEmpty($event['id']);
        self::assertSame('biometrics.session.completed', $event['type']);
    }

    public function testReadsHeadersInPhpServerShape(): void
    {
        // $_SERVER hands them over as HTTP_X_WEBHOOK_ID; a framework as x-webhook-id.
        $webhook = $this->vectors()['webhook'];
        $serverStyle = [];
        foreach ($webhook['headers'] as $name => $value) {
            $serverStyle['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        $event = $this->verifierAt($webhook)->verify($serverStyle, $webhook['body']);

        self::assertNotEmpty($event['id']);
    }

    public function testRejectsATamperedBody(): void
    {
        $webhook = $this->vectors()['webhook'];

        try {
            $this->verifierAt($webhook)->verify($webhook['headers'], $webhook['tamperedBody']);
            self::fail('a changed byte must fail the signature');
        } catch (WebhookVerificationException $e) {
            self::assertSame(WebhookVerifier::INVALID_SIGNATURE, $e->failure);
        }
    }

    public function testRejectsAnOldDelivery(): void
    {
        // The engine does not refuse old deliveries — the receiver does, or a
        // captured delivery could be replayed forever.
        $webhook = $this->vectors()['webhook'];
        $tenMinutesLater = (new \DateTimeImmutable($webhook['headers']['x-webhook-timestamp']))
            ->modify('+10 minutes')->format(DATE_ATOM);

        try {
            $this->verifierAt($webhook, $tenMinutesLater)->verify($webhook['headers'], $webhook['body']);
            self::fail('outside the tolerance it must be refused');
        } catch (WebhookVerificationException $e) {
            self::assertSame(WebhookVerifier::TIMESTAMP_OUT_OF_TOLERANCE, $e->failure);
        }

        $event = $this->verifierAt($webhook, $tenMinutesLater, 3600)->verify($webhook['headers'], $webhook['body']);
        self::assertNotEmpty($event['id']);
    }

    public function testRejectsMissingHeadersAndUnknownKey(): void
    {
        $webhook = $this->vectors()['webhook'];
        $verifier = $this->verifierAt($webhook);

        try {
            $verifier->verify([], $webhook['body']);
            self::fail('no headers, no verification');
        } catch (WebhookVerificationException $e) {
            self::assertSame(WebhookVerifier::MISSING_HEADERS, $e->failure);
        }

        $unknown = $webhook['headers'];
        $unknown['x-webhook-key-id'] = 'whk_not_mine';
        try {
            $verifier->verify($unknown, $webhook['body']);
            self::fail('an unknown key id must be refused');
        } catch (WebhookVerificationException $e) {
            self::assertSame(WebhookVerifier::UNKNOWN_KEY_ID, $e->failure);
        }

        $oldVersion = $webhook['headers'];
        $oldVersion['x-webhook-signature'] = 'v2=abc';
        try {
            $verifier->verify($oldVersion, $webhook['body']);
            self::fail('another signature version must be refused');
        } catch (WebhookVerificationException $e) {
            self::assertSame(WebhookVerifier::UNSUPPORTED_SIGNATURE_VERSION, $e->failure);
        }
    }

    public function testVerifiesEvidenceOffline(): void
    {
        $evidence = $this->vectors()['evidence'];
        $keys = $evidence['evidenceKeysResponse']['data'];
        $signature = $evidence['evidence']['signature'];

        $out = Evidence::verify($evidence['sessionId'], $evidence['attempt'], $evidence['evidence']['bundleHash'], $signature, $keys);
        self::assertTrue($out['valid']);
        self::assertFalse($out['unknownKey']);

        // Any change to what was signed breaks it — that is the whole point.
        $other = Evidence::verify($evidence['sessionId'], $evidence['attempt'] + 1, $evidence['evidence']['bundleHash'], $signature, $keys);
        self::assertFalse($other['valid']);

        $unknown = Evidence::verify($evidence['sessionId'], $evidence['attempt'], $evidence['evidence']['bundleHash'], ['alg' => 'Ed25519', 'keyId' => 'ev-unknown', 'value' => $signature['value'], 'signedAt' => $signature['signedAt']], $keys);
        self::assertTrue($unknown['unknownKey']);
        self::assertFalse($unknown['valid']);
    }
}
