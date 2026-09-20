<?php

declare(strict_types=1);

namespace Catalisa\Biometrics\Tests;

use Catalisa\Biometrics\BiometricsException;
use Catalisa\Biometrics\Client;
use PHPUnit\Framework\TestCase;

final class ClientTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $requests = [];

    /**
     * @param array<int,array{status:int,headers?:array<string,string>,body:string}> $answers
     */
    private function client(array $answers, array $options = []): Client
    {
        $this->requests = [];
        $transport = function (array $request) use (&$answers): array {
            $this->requests[] = $request;
            $answer = array_shift($answers) ?? ['status' => 500, 'body' => '{"error":"INTERNAL"}'];

            return ['status' => $answer['status'], 'headers' => $answer['headers'] ?? [], 'body' => $answer['body']];
        };

        return new Client(
            apiKey: $options['apiKey'] ?? 'bio_test_key',
            baseUrl: 'https://api.example/v1',
            subaccountId: $options['subaccountId'] ?? null,
            maxRetries: $options['maxRetries'] ?? 2,
            transport: $transport,
        );
    }

    public function testACredentialIsRequired(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Client(apiKey: '');
    }

    public function testCreateSessionSendsTheKeyAndReturnsTheEnvelope(): void
    {
        $client = $this->client([[
            'status' => 201,
            'body' => '{"data":{"sessionId":"s1","status":"SESSION_OPEN","environment":"test","provider":"MOCK","handoff":{"captureUrl":"https://capture/x"}}}',
        ]], ['subaccountId' => 'sub-1']);

        $session = $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'abertura de conta'], 'idem-1');

        $request = $this->requests[0];
        self::assertSame('https://api.example/v1/sessions', $request['url']);
        self::assertSame('bio_test_key', $request['headers']['X-API-Key']);
        self::assertSame('sub-1', $request['headers']['X-Subaccount-Id']);
        self::assertSame('idem-1', $request['headers']['Idempotency-Key']);
        self::assertSame('LIVENESS_ONLY', json_decode($request['body'], true)['flow']);
        self::assertSame('s1', $session['sessionId']);
        self::assertSame('test', $session['environment']);
        self::assertSame('https://capture/x', $session['handoff']['captureUrl']);
    }

    public function testQuotaAndSuspensionKeepTheirCodeAndNumbers(): void
    {
        $client = $this->client([[
            'status' => 402,
            'body' => '{"error":"PAYMENT_REQUIRED","message":"cota","details":{"code":"QUOTA_EXCEEDED","used":100,"monthlyQuota":100}}',
        ]]);

        try {
            $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'x']);
            self::fail('the allowance being gone must throw');
        } catch (BiometricsException $e) {
            self::assertTrue($e->isQuotaExceeded());
            self::assertSame(100, $e->details['used']);
            self::assertFalse($e->isSubaccountSuspended());
        }

        $client = $this->client([[
            'status' => 403,
            'body' => '{"error":"FORBIDDEN","message":"suspensa","details":{"code":"SUBACCOUNT_SUSPENDED","reason":"inadimplência"}}',
        ]]);
        try {
            $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'x']);
            self::fail('a suspended subaccount must throw');
        } catch (BiometricsException $e) {
            self::assertTrue($e->isSubaccountSuspended());
            self::assertSame('inadimplência', $e->details['reason']);
        }
    }

    public function testAnHtmlErrorPageStillYieldsAUsableCode(): void
    {
        // A proxy in front of the API can answer HTML. The caller still needs a code.
        $client = $this->client([['status' => 502, 'body' => '<html>502</html>']], ['maxRetries' => 0]);

        try {
            $client->getSession('s1');
            self::fail('a 502 must throw');
        } catch (BiometricsException $e) {
            self::assertSame('INTERNAL', $e->errorCode);
            self::assertTrue($e->isTransient());
        }
    }

    public function testReadsRetryButSessionCreationDoesNot(): void
    {
        $client = $this->client([
            ['status' => 500, 'body' => '{"error":"INTERNAL"}'],
            ['status' => 200, 'body' => '{"data":{"sessionId":"s1","status":"APPROVED"}}'],
        ]);
        $session = $client->getSession('s1');
        self::assertSame('APPROVED', $session['status']);
        self::assertCount(2, $this->requests);

        // Creating twice would open two sessions and spend the allowance twice.
        $client = $this->client([
            ['status' => 500, 'body' => '{"error":"INTERNAL"}'],
            ['status' => 201, 'body' => '{"data":{"sessionId":"s2"}}'],
        ]);
        try {
            $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'x']);
            self::fail('a 500 on creation must surface');
        } catch (BiometricsException $e) {
            self::assertSame(500, $e->status);
        }
        self::assertCount(1, $this->requests);
    }

    public function testRateLimitIsRetriedEvenOnCreation(): void
    {
        // The rate limiter refuses before the handler runs: nothing was done.
        $client = $this->client([
            ['status' => 429, 'headers' => ['retry-after' => '0'], 'body' => '{"error":"RATE_LIMITED"}'],
            ['status' => 201, 'body' => '{"data":{"sessionId":"s3"}}'],
        ]);

        $session = $client->createSession(['flow' => 'LIVENESS_ONLY', 'purpose' => 'x']);

        self::assertSame('s3', $session['sessionId']);
        self::assertCount(2, $this->requests);
    }

    public function testListSendsPaginationAndFilters(): void
    {
        $client = $this->client([['status' => 200, 'body' => '{"data":[],"meta":{"total":0}}']]);

        $client->listSessions(['page' => 2, 'pageSize' => 50, 'status' => 'APPROVED', 'environment' => 'test']);

        $url = $this->requests[0]['url'];
        self::assertStringContainsString('page%5Bnumber%5D=2', $url);
        self::assertStringContainsString('page%5Bsize%5D=50', $url);
        self::assertStringContainsString('status=APPROVED', $url);
        self::assertStringContainsString('environment=test', $url);
    }

    public function testSubmitCaptureUsesTheCaptureTokenNotTheApiKey(): void
    {
        $client = $this->client([['status' => 200, 'body' => '{"data":{"sessionId":"s1","status":"RETRY_ALLOWED","reasons":["quality.too_dark"]}}']]);

        $out = $client->submitCapture('s1', 'capture-token', 'webm-bytes', 'video/webm', 'challenge.webm', [
            'channel' => 'SDK',
            'telemetry' => ['fps' => 30],
        ]);

        $request = $this->requests[0];
        self::assertSame('Bearer capture-token', $request['headers']['Authorization']);
        self::assertArrayNotHasKey('X-API-Key', $request['headers']);
        self::assertStringStartsWith('multipart/form-data; boundary=', $request['headers']['Content-Type']);
        self::assertStringContainsString('webm-bytes', $request['body']);
        self::assertStringContainsString('name="channel"', $request['body']);
        self::assertStringContainsString('{"fps":30}', $request['body']);
        self::assertSame('RETRY_ALLOWED', $out['status']);
    }

    public function testSubmitCaptureRefusesAnEmptyVideoBeforeTheNetwork(): void
    {
        $client = $this->client([]);

        $this->expectException(BiometricsException::class);
        $client->submitCapture('s1', 'tok', '');
        self::assertCount(0, $this->requests);
    }
}
