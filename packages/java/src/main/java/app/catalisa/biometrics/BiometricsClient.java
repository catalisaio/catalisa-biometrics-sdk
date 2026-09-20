package app.catalisa.biometrics;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Catalisa Biometrics client.
 *
 * <p>The flow never trusts the browser:
 *
 * <ol>
 *   <li>your server creates a session and gets {@code handoff.captureUrl};</li>
 *   <li>the person opens that URL (tab, iframe or WebView) and does the challenge;</li>
 *   <li>the decision reaches your server through the webhook, or through {@link #getSession}.</li>
 * </ol>
 *
 * <p>The capture page never shows the result to the person in front of the
 * camera, on purpose: it would be a fraud oracle. Never decide anything from
 * front-end events.
 */
public final class BiometricsClient {

    /** The public API. */
    public static final String DEFAULT_BASE_URL = "https://api.biometrics.catalisa.app/v1";

    /** Version of this SDK, sent in the User-Agent. */
    public static final String VERSION = "0.1.0";

    static final ObjectMapper MAPPER = JsonMapper.builder()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .build();

    /** One HTTP round trip. Replaceable, which is how the tests avoid a real server. */
    public interface Transport {
        Answer send(Call call) throws IOException, InterruptedException;
    }

    /** What goes out. */
    public record Call(String method, String url, Map<String, String> headers, byte[] body, String contentType) {
    }

    /** What comes back. */
    public record Answer(int status, Map<String, String> headers, String body) {
    }

    private final String apiKey;
    private final String accessToken;
    private final String baseUrl;
    private final String subaccountId;
    private final Duration timeout;
    private final int maxRetries;
    private final Transport transport;
    private final Sleeper sleeper;

    /** Replaces the wait between attempts, in tests. */
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    private BiometricsClient(Builder builder) {
        if ((builder.apiKey == null || builder.apiKey.isEmpty())
                && (builder.accessToken == null || builder.accessToken.isEmpty())) {
            throw new IllegalArgumentException("Catalisa Biometrics: an API key (or an access token) is required");
        }
        this.apiKey = builder.apiKey;
        this.accessToken = builder.accessToken;
        this.baseUrl = builder.baseUrl.replaceAll("/+$", "");
        this.subaccountId = builder.subaccountId;
        this.timeout = builder.timeout;
        this.maxRetries = builder.maxRetries;
        this.transport = builder.transport != null ? builder.transport : new JdkTransport(builder.timeout);
        this.sleeper = builder.sleeper != null ? builder.sleeper : Thread::sleep;
    }

    /** Shorthand for the common case: just the key. */
    public static BiometricsClient of(String apiKey) {
        return builder().apiKey(apiKey).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String apiKey;
        private String accessToken;
        private String baseUrl = DEFAULT_BASE_URL;
        private String subaccountId;
        private Duration timeout = Duration.ofSeconds(30);
        private int maxRetries = 2;
        private Transport transport;
        private Sleeper sleeper;

        /** Key from the console. A test key runs the sandbox. */
        public Builder apiKey(String value) {
            this.apiKey = value;
            return this;
        }

        /** An IAM JWT instead of an API key. */
        public Builder accessToken(String value) {
            this.accessToken = value;
            return this;
        }

        public Builder baseUrl(String value) {
            this.baseUrl = value;
            return this;
        }

        /** Act on behalf of a subaccount while holding an organization key. */
        public Builder subaccountId(String value) {
            this.subaccountId = value;
            return this;
        }

        public Builder timeout(Duration value) {
            this.timeout = value;
            return this;
        }

        /** Retries for reads and for 429. Session creation is never retried on 5xx. */
        public Builder maxRetries(int value) {
            this.maxRetries = value;
            return this;
        }

        public Builder transport(Transport value) {
            this.transport = value;
            return this;
        }

        Builder sleeper(Sleeper value) {
            this.sleeper = value;
            return this;
        }

        public BiometricsClient build() {
            return new BiometricsClient(this);
        }
    }

    /**
     * Opens a session. The answer carries {@code handoff.captureUrl}, where the
     * person goes.
     *
     * <p>Never retried on a 5xx or a network failure: the server does not
     * deduplicate by {@code Idempotency-Key} yet, and a retry could open two
     * sessions (and spend the allowance twice).
     */
    public Models.Session createSession(Map<String, Object> input) {
        return createSession(input, null);
    }

    public Models.Session createSession(Map<String, Object> input, String idempotencyKey) {
        Map<String, String> headers = idempotencyKey == null
                ? Map.of()
                : Map.of("Idempotency-Key", idempotencyKey);

        JsonNode body = request("POST", "/sessions", Map.of(), input, headers, false);

        return convert(body.get("data"), Models.Session.class);
    }

    /**
     * Reads a session. One from another subaccount — or from the other
     * environment — answers 404, on purpose: existence is not confirmed.
     */
    public Models.Session getSession(String sessionId) {
        JsonNode body = request("GET", "/sessions/" + encode(sessionId), Map.of(), null, Map.of(), true);

        return convert(body.get("data"), Models.Session.class);
    }

    /** Lists sessions, newest first. */
    public Models.SessionPage listSessions(Map<String, Object> filters) {
        Map<String, String> query = new LinkedHashMap<>();
        filters.forEach((key, value) -> {
            if (value == null || value.toString().isEmpty()) {
                return;
            }
            String name = switch (key) {
                case "page" -> "page[number]";
                case "pageSize" -> "page[size]";
                default -> key;
            };
            query.put(name, value.toString());
        });

        return convert(request("GET", "/sessions", query, null, Map.of(), true), Models.SessionPage.class);
    }

    /** Closes a session that has not settled. The allowance slot comes back. */
    public Models.Session cancelSession(String sessionId) {
        JsonNode body = request("POST", "/sessions/" + encode(sessionId) + "/cancel", Map.of(), null, Map.of(), false);

        return convert(body.get("data"), Models.Session.class);
    }

    /** Signed evidence plus short-lived download links for the artifacts. */
    public Models.Evidence getEvidence(String sessionId) {
        JsonNode body = request("GET", "/sessions/" + encode(sessionId) + "/evidence", Map.of(), null, Map.of(), true);

        return convert(body.get("data"), Models.Evidence.class);
    }

    /** Published signing keys, retired ones included, so old evidence still verifies. */
    public List<Models.EvidenceKey> getEvidenceKeys() {
        JsonNode body = request("GET", "/evidence-keys", Map.of(), null, Map.of(), true);
        List<Models.EvidenceKey> keys = new ArrayList<>();
        JsonNode data = body.get("data");
        if (data != null) {
            data.forEach(node -> keys.add(convert(node, Models.EvidenceKey.class)));
        }

        return keys;
    }

    /**
     * Uploads a capture your own app recorded, authenticating with the session's
     * capture token — the account key never leaves your server. Only
     * {@code video/webm} and {@code video/mp4} are accepted, up to 16 MiB and 24
     * seconds.
     *
     * <p>Prefer the hosted page when you can: it already runs the quality checks
     * that keep a useless recording from spending an attempt.
     */
    public Models.CaptureResult submitCapture(String sessionId, String captureToken, byte[] video,
                                              String videoMime, String videoFilename,
                                              String channel, String telemetryJson) {
        if (captureToken == null || captureToken.isEmpty()) {
            throw new BiometricsException(0, "UNAUTHORIZED", "a capture token is required");
        }
        if (video == null || video.length == 0) {
            throw new BiometricsException(0, "VALIDATION", "the video is empty");
        }

        String boundary = "----catalisa" + Long.toHexString(ThreadLocalRandom.current().nextLong());
        var out = new java.io.ByteArrayOutputStream();
        try {
            out.write(("--" + boundary + "\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(("Content-Disposition: form-data; name=\"video\"; filename=\"" + videoFilename + "\"\r\n")
                    .getBytes(StandardCharsets.UTF_8));
            out.write(("Content-Type: " + videoMime + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
            out.write(video);
            out.write("\r\n".getBytes(StandardCharsets.UTF_8));
            Map<String, String> fields = new LinkedHashMap<>();
            if (telemetryJson != null) {
                fields.put("telemetry", telemetryJson);
            }
            if (channel != null) {
                fields.put("channel", channel);
            }
            for (var field : fields.entrySet()) {
                out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + field.getKey() + "\"\r\n\r\n"
                        + field.getValue() + "\r\n").getBytes(StandardCharsets.UTF_8));
            }
            out.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        headers.put("User-Agent", userAgent());
        // The capture token authenticates this call on its own.
        headers.put("Authorization", "Bearer " + captureToken);

        Answer answer = send(new Call("POST",
                baseUrl + "/sessions/" + encode(sessionId) + "/captures",
                headers, out.toByteArray(), "multipart/form-data; boundary=" + boundary));

        JsonNode body = decode(answer);

        return convert(body.get("data"), Models.CaptureResult.class);
    }

    private JsonNode request(String method, String path, Map<String, String> query, Object body,
                             Map<String, String> extraHeaders, boolean idempotent) {
        StringBuilder url = new StringBuilder(baseUrl).append(path);
        if (!query.isEmpty()) {
            List<String> pairs = new ArrayList<>();
            query.forEach((key, value) -> pairs.add(encode(key) + "=" + encode(value)));
            url.append('?').append(String.join("&", pairs));
        }

        Map<String, String> headers = new HashMap<>(extraHeaders);
        headers.put("Accept", "application/json");
        headers.put("User-Agent", userAgent());
        if (accessToken != null && !accessToken.isEmpty()) {
            headers.put("Authorization", "Bearer " + accessToken);
        } else {
            headers.put("X-API-Key", apiKey);
        }
        if (subaccountId != null && !subaccountId.isEmpty()) {
            headers.put("X-Subaccount-Id", subaccountId);
        }

        byte[] payload = null;
        String contentType = null;
        if (body != null) {
            try {
                payload = MAPPER.writeValueAsBytes(body);
            } catch (IOException e) {
                throw new BiometricsException(0, "VALIDATION", "could not encode the body: " + e.getMessage());
            }
            contentType = "application/json";
        }

        int attempt = 0;
        while (true) {
            try {
                return decode(send(new Call(method, url.toString(), headers, payload, contentType)));
            } catch (BiometricsException e) {
                // A 429 is always safe to retry: the rate limiter refuses before the
                // handler runs, so nothing was done.
                boolean retryable = e.status() == 429 || (idempotent && (e.status() >= 500 || e.status() == 0));
                if (!retryable || attempt >= maxRetries) {
                    throw e;
                }
                try {
                    sleeper.sleep(backoff(attempt, e));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
                attempt++;
            }
        }
    }

    private Answer send(Call call) {
        try {
            return transport.send(call);
        } catch (HttpTimeoutException e) {
            throw new BiometricsException(0, "TIMEOUT", "no answer within " + timeout.toSeconds() + "s");
        } catch (IOException e) {
            throw new BiometricsException(0, "CONNECTION", "connection failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BiometricsException(0, "CONNECTION", "interrupted");
        }
    }

    private JsonNode decode(Answer answer) {
        JsonNode parsed = null;
        if (answer.body() != null && !answer.body().isBlank()) {
            try {
                parsed = MAPPER.readTree(answer.body());
            } catch (IOException ignored) {
                // A proxy in front of the API can answer HTML. The caller still needs
                // a code, and the status gives one.
            }
        }
        if (answer.status() >= 400) {
            throw errorFrom(answer.status(), parsed, answer.headers());
        }

        return parsed == null ? MAPPER.createObjectNode() : parsed;
    }

    private BiometricsException errorFrom(int status, JsonNode body, Map<String, String> headers) {
        String code = BiometricsException.codeForStatus(status);
        String message = "";
        Map<String, Object> details = Map.of();

        if (body != null && body.isObject()) {
            if (body.hasNonNull("error") && body.get("error").isTextual()) {
                code = body.get("error").asText();
            }
            if (body.hasNonNull("message") && body.get("message").isTextual()) {
                message = body.get("message").asText();
            }
            JsonNode raw = body.get("details");
            if (raw != null && raw.isObject()) {
                details = MAPPER.convertValue(raw, Map.class);
                // The machine-readable code lives inside details on the cases that
                // carry numbers with them (quota, suspension).
                Object inner = details.get("code");
                if (inner instanceof String text && !text.isEmpty()) {
                    code = text;
                }
            }
        }
        if (message.isEmpty()) {
            message = BiometricsException.messageForStatus(status);
        }
        Integer retryAfter = Optional.ofNullable(headers.get("retry-after"))
                .map(value -> {
                    try {
                        return Integer.valueOf(value);
                    } catch (NumberFormatException e) {
                        return null;
                    }
                })
                .orElse(null);

        return new BiometricsException(status, code, message, details, headers.get("x-request-id"), retryAfter);
    }

    private long backoff(int attempt, BiometricsException error) {
        if (error.retryAfter() != null && error.retryAfter() > 0) {
            return Math.min(error.retryAfter() * 1000L, 30_000L);
        }
        long base = 500L * (1L << attempt);
        long jitter = new Random().nextInt((int) Math.max(1, base / 4));

        return Math.min(base + jitter, 8_000L);
    }

    private static <T> T convert(JsonNode node, Class<T> type) {
        if (node == null || node.isNull()) {
            return null;
        }
        return MAPPER.convertValue(node, type);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String userAgent() {
        return "catalisa-biometrics-java/" + VERSION;
    }

    /** The default transport: the JDK's own HTTP client, no dependency added. */
    private static final class JdkTransport implements Transport {
        private final HttpClient http = HttpClient.newHttpClient();
        private final Duration timeout;

        JdkTransport(Duration timeout) {
            this.timeout = timeout;
        }

        @Override
        public Answer send(Call call) throws IOException, InterruptedException {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(call.url())).timeout(timeout);
            call.headers().forEach(request::header);
            if (call.contentType() != null) {
                request.header("Content-Type", call.contentType());
            }
            var publisher = call.body() == null
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(call.body());
            request.method(call.method(), publisher);

            HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, String> headers = new HashMap<>();
            response.headers().map().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    headers.put(name.toLowerCase(), values.get(0));
                }
            });

            return new Answer(response.statusCode(), headers, response.body());
        }
    }
}
