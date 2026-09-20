<?php

declare(strict_types=1);

namespace Catalisa\Biometrics;

/**
 * Catalisa Biometrics client.
 *
 * The flow never trusts the browser:
 *
 *   1. your server creates a session and gets handoff.captureUrl;
 *   2. the person opens that URL (tab, iframe or WebView) and does the challenge;
 *   3. the decision reaches your server through the webhook, or through getSession().
 *
 * The capture page never shows the result to the person in front of the camera,
 * on purpose: it would be a fraud oracle. Never decide anything from front-end
 * events.
 */
final class Client
{
    public const DEFAULT_BASE_URL = 'https://api.biometrics.catalisa.app/v1';
    public const VERSION = '0.1.0';

    private string $baseUrl;
    private string $userAgent;

    /**
     * @param string        $apiKey       key from the console; a test key runs the sandbox
     * @param string|null   $accessToken  an IAM JWT instead of an API key
     * @param string|null   $subaccountId act on behalf of a subaccount (organization key only)
     * @param float         $timeout      seconds per attempt
     * @param int           $maxRetries   reads and 429 only
     * @param callable|null $transport    fn(array $request): array{status:int,headers:array,body:string} — for tests
     */
    public function __construct(
        private readonly string $apiKey,
        ?string $baseUrl = null,
        private readonly ?string $accessToken = null,
        private readonly ?string $subaccountId = null,
        private readonly float $timeout = 30.0,
        private readonly int $maxRetries = 2,
        private $transport = null,
    ) {
        if ($apiKey === '' && ($accessToken === null || $accessToken === '')) {
            throw new \InvalidArgumentException('Catalisa Biometrics: an API key (or an access token) is required');
        }
        $this->baseUrl = rtrim($baseUrl ?? self::DEFAULT_BASE_URL, '/');
        $this->userAgent = 'catalisa-biometrics-php/' . self::VERSION;
    }

    /**
     * Opens a session. The answer carries `handoff.captureUrl`, where the person goes.
     *
     * Never retried on a 5xx or a network failure: the server does not
     * deduplicate by Idempotency-Key yet, and a retry could open two sessions
     * (and spend the allowance twice).
     *
     * @param array<string,mixed> $input flow and purpose are required
     */
    public function createSession(array $input, ?string $idempotencyKey = null): array
    {
        $headers = $idempotencyKey !== null ? ['Idempotency-Key' => $idempotencyKey] : [];

        return $this->request('POST', '/sessions', body: $input, headers: $headers)['data'] ?? [];
    }

    /** Reads a session. One from another subaccount — or the other environment — is a 404. */
    public function getSession(string $sessionId): array
    {
        return $this->request('GET', '/sessions/' . rawurlencode($sessionId), idempotent: true)['data'] ?? [];
    }

    /**
     * Lists sessions, newest first.
     *
     * @param array<string,mixed> $filters page, pageSize, status, flow, customerId,
     *                                     subjectCpf, from, to, subaccountId, environment
     */
    public function listSessions(array $filters = []): array
    {
        $query = [];
        foreach (['status', 'flow', 'customerId', 'subjectCpf', 'from', 'to', 'subaccountId', 'environment'] as $key) {
            if (($filters[$key] ?? null) !== null && $filters[$key] !== '') {
                $query[$key] = (string) $filters[$key];
            }
        }
        if (($filters['page'] ?? null) !== null) {
            $query['page[number]'] = (string) $filters['page'];
        }
        if (($filters['pageSize'] ?? null) !== null) {
            $query['page[size]'] = (string) $filters['pageSize'];
        }

        return $this->request('GET', '/sessions', query: $query, idempotent: true);
    }

    /** Closes a session that has not settled. The allowance slot comes back. */
    public function cancelSession(string $sessionId): array
    {
        return $this->request('POST', '/sessions/' . rawurlencode($sessionId) . '/cancel')['data'] ?? [];
    }

    /** Signed evidence plus short-lived download links for the artifacts. */
    public function sessionEvidence(string $sessionId): array
    {
        return $this->request('GET', '/sessions/' . rawurlencode($sessionId) . '/evidence', idempotent: true)['data'] ?? [];
    }

    /**
     * Asks the API to check the evidence signature. Handy, but it trusts the same
     * party that signed it: for an audit, verify offline with Evidence::verify().
     */
    public function verifyEvidenceOnServer(string $sessionId): array
    {
        return $this->request('GET', '/sessions/' . rawurlencode($sessionId) . '/evidence/verify', idempotent: true)['data'] ?? [];
    }

    /** Published signing keys, retired ones included, so old evidence still verifies. */
    public function evidenceKeys(): array
    {
        return $this->request('GET', '/evidence-keys', idempotent: true)['data'] ?? [];
    }

    /**
     * Uploads a capture your own app recorded, authenticating with the session's
     * captureToken — the account key never leaves your server. Only video/webm and
     * video/mp4 are accepted, up to 16 MiB and 24 seconds.
     *
     * Prefer the hosted page when you can: it already runs the quality checks that
     * keep a useless recording from spending an attempt.
     *
     * @param array<string,mixed> $extra telemetry (array), channel (HOSTED|IFRAME|WIDGET|SDK), capturedAt (ISO 8601)
     */
    public function submitCapture(
        string $sessionId,
        string $captureToken,
        string $video,
        string $videoMime = 'video/webm',
        string $videoFilename = 'challenge.webm',
        array $extra = [],
    ): array {
        if ($captureToken === '') {
            throw new BiometricsException(0, 'UNAUTHORIZED', 'captureToken is required');
        }
        if ($video === '') {
            throw new BiometricsException(0, 'VALIDATION', 'the video is empty');
        }

        $boundary = '----catalisa' . bin2hex(random_bytes(8));
        $parts = '';
        $parts .= "--{$boundary}\r\n";
        $parts .= "Content-Disposition: form-data; name=\"video\"; filename=\"{$videoFilename}\"\r\n";
        $parts .= "Content-Type: {$videoMime}\r\n\r\n{$video}\r\n";
        foreach (['telemetry' => $extra['telemetry'] ?? null, 'channel' => $extra['channel'] ?? null, 'capturedAt' => $extra['capturedAt'] ?? null] as $name => $value) {
            if ($value === null) {
                continue;
            }
            $encoded = is_array($value) ? json_encode($value, JSON_THROW_ON_ERROR) : (string) $value;
            $parts .= "--{$boundary}\r\nContent-Disposition: form-data; name=\"{$name}\"\r\n\r\n{$encoded}\r\n";
        }
        $parts .= "--{$boundary}--\r\n";

        $answer = $this->send([
            'method' => 'POST',
            'url' => $this->baseUrl . '/sessions/' . rawurlencode($sessionId) . '/captures',
            // The capture token authenticates on its own; the API key is not sent.
            'headers' => [
                'Accept' => 'application/json',
                'User-Agent' => $this->userAgent,
                'Authorization' => 'Bearer ' . $captureToken,
                'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
            ],
            'body' => $parts,
            'timeout' => $this->timeout,
        ]);

        return $this->decode($answer)['data'] ?? [];
    }

    /**
     * @param array<string,string> $query
     * @param array<string,mixed>|null $body
     * @param array<string,string> $headers
     * @return array<string,mixed>
     */
    private function request(
        string $method,
        string $path,
        array $query = [],
        ?array $body = null,
        array $headers = [],
        bool $idempotent = false,
    ): array {
        $url = $this->baseUrl . $path;
        if ($query !== []) {
            $url .= '?' . http_build_query($query);
        }

        $requestHeaders = [
            'Accept' => 'application/json',
            'User-Agent' => $this->userAgent,
        ] + $headers;
        if ($this->accessToken !== null && $this->accessToken !== '') {
            $requestHeaders['Authorization'] = 'Bearer ' . $this->accessToken;
        } else {
            $requestHeaders['X-API-Key'] = $this->apiKey;
        }
        if ($this->subaccountId !== null && $this->subaccountId !== '') {
            $requestHeaders['X-Subaccount-Id'] = $this->subaccountId;
        }
        $payload = null;
        if ($body !== null) {
            $payload = json_encode($body, JSON_THROW_ON_ERROR);
            $requestHeaders['Content-Type'] = 'application/json';
        }

        $attempt = 0;
        while (true) {
            try {
                return $this->decode($this->send([
                    'method' => $method,
                    'url' => $url,
                    'headers' => $requestHeaders,
                    'body' => $payload,
                    'timeout' => $this->timeout,
                ]));
            } catch (BiometricsException $e) {
                // A 429 is always safe: the rate limiter refuses before anything runs.
                $retryable = $e->status === 429 || ($idempotent && ($e->status >= 500 || $e->status === 0));
                if (!$retryable || $attempt >= $this->maxRetries) {
                    throw $e;
                }
                usleep((int) ($this->backoff($attempt, $e) * 1_000_000));
                $attempt++;
            }
        }
    }

    private function backoff(int $attempt, BiometricsException $e): float
    {
        if ($e->retryAfter !== null && $e->retryAfter > 0) {
            return min((float) $e->retryAfter, 30.0);
        }
        $base = 0.5 * (2 ** $attempt);

        return min($base + (mt_rand(0, 250) / 1000), 8.0);
    }

    /** @return array<string,mixed> */
    private function decode(array $answer): array
    {
        $status = (int) $answer['status'];
        $parsed = null;
        if (($answer['body'] ?? '') !== '') {
            $parsed = json_decode((string) $answer['body'], true);
        }
        if ($status >= 400) {
            throw BiometricsException::fromResponse($status, $parsed, $answer['headers'] ?? []);
        }

        return is_array($parsed) ? $parsed : [];
    }

    /**
     * @param array<string,mixed> $request
     * @return array{status:int,headers:array<string,string>,body:string}
     */
    private function send(array $request): array
    {
        if ($this->transport !== null) {
            return ($this->transport)($request);
        }

        $ch = curl_init($request['url']);
        $headers = [];
        foreach ($request['headers'] as $name => $value) {
            $headers[] = "{$name}: {$value}";
        }
        $responseHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $request['method'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => (int) ceil((float) $request['timeout']),
            CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$responseHeaders): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }

                return strlen($line);
            },
        ]);
        if (($request['body'] ?? null) !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $request['body']);
        }

        $body = curl_exec($ch);
        if ($body === false) {
            $message = curl_error($ch);
            $timedOut = curl_errno($ch) === CURLE_OPERATION_TIMEDOUT;
            curl_close($ch);

            throw new BiometricsException(
                0,
                $timedOut ? 'TIMEOUT' : 'CONNECTION',
                $timedOut ? "no answer within {$request['timeout']}s" : "connection failed: {$message}",
            );
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return ['status' => $status, 'headers' => $responseHeaders, 'body' => (string) $body];
    }
}
