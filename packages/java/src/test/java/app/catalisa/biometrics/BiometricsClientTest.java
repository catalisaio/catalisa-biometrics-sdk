package app.catalisa.biometrics;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BiometricsClientTest {

    /** A transport that answers from a queue and records what went out. */
    private static final class FakeTransport implements BiometricsClient.Transport {
        private final Deque<BiometricsClient.Answer> answers = new ArrayDeque<>();
        final List<BiometricsClient.Call> calls = new ArrayList<>();

        FakeTransport answer(int status, String body) {
            return answer(status, body, Map.of());
        }

        FakeTransport answer(int status, String body, Map<String, String> headers) {
            answers.add(new BiometricsClient.Answer(status, headers, body));
            return this;
        }

        @Override
        public BiometricsClient.Answer send(BiometricsClient.Call call) {
            calls.add(call);
            return answers.isEmpty()
                    ? new BiometricsClient.Answer(500, Map.of(), "{\"error\":\"INTERNAL\"}")
                    : answers.poll();
        }
    }

    private static BiometricsClient client(FakeTransport transport) {
        return client(transport, null, 2);
    }

    private static BiometricsClient client(FakeTransport transport, String subaccountId, int maxRetries) {
        return BiometricsClient.builder()
                .apiKey("bio_test_key")
                .baseUrl("https://api.example/v1")
                .subaccountId(subaccountId)
                .maxRetries(maxRetries)
                .transport(transport)
                .sleeper(millis -> { })
                .build();
    }

    @Test
    void aCredentialIsRequired() {
        assertThrows(IllegalArgumentException.class, () -> BiometricsClient.builder().build());
        BiometricsClient.builder().accessToken("jwt").build();
    }

    @Test
    void createSessionSendsTheKeyAndReturnsTheEnvelope() {
        var transport = new FakeTransport().answer(201,
                "{\"data\":{\"sessionId\":\"s1\",\"status\":\"SESSION_OPEN\",\"environment\":\"test\",\"provider\":\"MOCK\","
                        + "\"handoff\":{\"captureUrl\":\"https://capture/x\",\"captureToken\":\"tok\"}}}");
        var client = client(transport, "sub-1", 2);

        var session = client.createSession(
                Map.of("flow", Models.Flows.LIVENESS_ONLY, "purpose", "abertura de conta"), "idem-1");

        var call = transport.calls.get(0);
        assertEquals("https://api.example/v1/sessions", call.url());
        assertEquals("bio_test_key", call.headers().get("X-API-Key"));
        assertEquals("sub-1", call.headers().get("X-Subaccount-Id"));
        assertEquals("idem-1", call.headers().get("Idempotency-Key"));
        assertTrue(new String(call.body(), StandardCharsets.UTF_8).contains("LIVENESS_ONLY"));
        assertEquals("s1", session.sessionId());
        assertTrue(session.isSandbox());
        assertEquals("https://capture/x", session.handoff().captureUrl());
    }

    @Test
    void quotaAndSuspensionKeepTheirCodeAndNumbers() {
        var transport = new FakeTransport().answer(402,
                "{\"error\":\"PAYMENT_REQUIRED\",\"message\":\"cota\",\"details\":{\"code\":\"QUOTA_EXCEEDED\",\"used\":100}}");

        var error = assertThrows(BiometricsException.class,
                () -> client(transport).createSession(Map.of("flow", "LIVENESS_ONLY", "purpose", "x")));

        assertTrue(error.isQuotaExceeded());
        assertFalse(error.isSubaccountSuspended());
        assertEquals(100, error.details().get("used"));

        var suspended = new FakeTransport().answer(403,
                "{\"error\":\"FORBIDDEN\",\"message\":\"suspensa\",\"details\":{\"code\":\"SUBACCOUNT_SUSPENDED\",\"reason\":\"inadimplência\"}}");
        var second = assertThrows(BiometricsException.class,
                () -> client(suspended).createSession(Map.of("flow", "LIVENESS_ONLY", "purpose", "x")));

        assertTrue(second.isSubaccountSuspended());
        assertEquals("inadimplência", second.details().get("reason"));
    }

    @Test
    void anHtmlErrorPageStillYieldsAUsableCode() {
        // A proxy in front of the API can answer HTML. The caller still needs a code.
        var transport = new FakeTransport().answer(502, "<html>502</html>");

        var error = assertThrows(BiometricsException.class, () -> client(transport, null, 0).getSession("s1"));

        assertEquals("INTERNAL", error.code());
        assertTrue(error.isTransient());
    }

    @Test
    void readsRetryButSessionCreationDoesNot() {
        var reads = new FakeTransport()
                .answer(500, "{\"error\":\"INTERNAL\"}")
                .answer(200, "{\"data\":{\"sessionId\":\"s1\",\"status\":\"APPROVED\"}}");
        assertEquals("APPROVED", client(reads).getSession("s1").status());
        assertEquals(2, reads.calls.size());

        // Creating twice would open two sessions and spend the allowance twice.
        var writes = new FakeTransport()
                .answer(500, "{\"error\":\"INTERNAL\"}")
                .answer(201, "{\"data\":{\"sessionId\":\"s2\"}}");
        assertThrows(BiometricsException.class,
                () -> client(writes).createSession(Map.of("flow", "LIVENESS_ONLY", "purpose", "x")));
        assertEquals(1, writes.calls.size());
    }

    @Test
    void rateLimitIsRetriedEvenOnCreation() {
        // The rate limiter refuses before the handler runs: nothing was done.
        var transport = new FakeTransport()
                .answer(429, "{\"error\":\"RATE_LIMITED\"}", Map.of("retry-after", "0"))
                .answer(201, "{\"data\":{\"sessionId\":\"s3\"}}");

        var session = client(transport).createSession(Map.of("flow", "LIVENESS_ONLY", "purpose", "x"));

        assertEquals("s3", session.sessionId());
        assertEquals(2, transport.calls.size());
    }

    @Test
    void listSendsPaginationAndFilters() {
        var transport = new FakeTransport().answer(200, "{\"data\":[],\"meta\":{\"total\":0}}");

        client(transport).listSessions(new java.util.LinkedHashMap<>(Map.of(
                "page", 2, "pageSize", 50, "status", "APPROVED", "environment", "test")));

        var url = transport.calls.get(0).url();
        assertTrue(url.contains("page%5Bnumber%5D=2"), url);
        assertTrue(url.contains("page%5Bsize%5D=50"), url);
        assertTrue(url.contains("status=APPROVED"), url);
        assertTrue(url.contains("environment=test"), url);
    }

    @Test
    void submitCaptureUsesTheCaptureTokenNotTheApiKey() {
        var transport = new FakeTransport().answer(200,
                "{\"data\":{\"sessionId\":\"s1\",\"status\":\"RETRY_ALLOWED\",\"attempt\":1,\"maxAttempts\":3,\"reasons\":[\"quality.too_dark\"]}}");

        var result = client(transport).submitCapture("s1", "capture-token",
                "webm-bytes".getBytes(StandardCharsets.UTF_8), "video/webm", "challenge.webm", "SDK", "{\"fps\":30}");

        var call = transport.calls.get(0);
        assertEquals("Bearer capture-token", call.headers().get("Authorization"));
        assertNull(call.headers().get("X-API-Key"));
        assertTrue(call.contentType().startsWith("multipart/form-data; boundary="));
        var body = new String(call.body(), StandardCharsets.UTF_8);
        assertTrue(body.contains("webm-bytes"));
        assertTrue(body.contains("{\"fps\":30}"));
        assertTrue(body.contains("name=\"channel\""));
        assertEquals(Models.Statuses.RETRY_ALLOWED, result.status());
        assertEquals(List.of("quality.too_dark"), result.reasons());
    }

    @Test
    void submitCaptureRefusesAnEmptyVideoBeforeTheNetwork() {
        var transport = new FakeTransport();
        var client = client(transport);

        assertThrows(BiometricsException.class,
                () -> client.submitCapture("s1", "tok", new byte[0], "video/webm", "c.webm", null, null));
        assertThrows(BiometricsException.class,
                () -> client.submitCapture("s1", "", "x".getBytes(StandardCharsets.UTF_8), "video/webm", "c.webm", null, null));
        assertTrue(transport.calls.isEmpty());
    }

    @Test
    void terminalStatusesAreTheOnesThatNeverChange() {
        assertTrue(Models.Statuses.isTerminal(Models.Statuses.APPROVED));
        assertTrue(Models.Statuses.isTerminal(Models.Statuses.CANCELLED));
        assertFalse(Models.Statuses.isTerminal(Models.Statuses.RETRY_ALLOWED));
        assertFalse(Models.Statuses.isTerminal(Models.Statuses.SESSION_OPEN));
    }
}
