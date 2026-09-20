package app.catalisa.biometrics;

import java.util.Map;

/**
 * Every failed call throws this. The API answers
 * {@code {"error":"<code>","message":"...","details":{...}}}, so {@link #code()}
 * is the API's own word for what happened — branch on it, never on the message.
 */
public class BiometricsException extends RuntimeException {

    private final int status;
    private final String code;
    private final Map<String, Object> details;
    private final String requestId;
    private final Integer retryAfter;

    public BiometricsException(int status, String code, String message,
                               Map<String, Object> details, String requestId, Integer retryAfter) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
        this.requestId = requestId;
        this.retryAfter = retryAfter;
    }

    public BiometricsException(int status, String code, String message) {
        this(status, code, message, null, null, null);
    }

    /** HTTP status, or 0 when the request never reached the API. */
    public int status() {
        return status;
    }

    /**
     * API error code (VALIDATION, NOT_FOUND, QUOTA_EXCEEDED…), or TIMEOUT /
     * CONNECTION when the request did not complete.
     */
    public String code() {
        return code;
    }

    /** Whatever the API attached: the offending fields, the quota numbers. */
    public Map<String, Object> details() {
        return details;
    }

    /** {@code x-request-id}, when the API sends one — quote it in a support ticket. */
    public String requestId() {
        return requestId;
    }

    /** {@code Retry-After} in seconds, on a 429. */
    public Integer retryAfter() {
        return retryAfter;
    }

    /** The customer's monthly allowance is gone. A test key never gets here. */
    public boolean isQuotaExceeded() {
        return "QUOTA_EXCEEDED".equals(code);
    }

    /** The subaccount is suspended: nothing opens until it is reactivated. */
    public boolean isSubaccountSuspended() {
        return "SUBACCOUNT_SUSPENDED".equals(code);
    }

    /** Worth trying again by itself: rate limit, server fault or network. */
    public boolean isTransient() {
        return status == 429 || status >= 500 || status == 0;
    }

    static String codeForStatus(int status) {
        return switch (status) {
            case 400, 415 -> "VALIDATION";
            case 401 -> "UNAUTHORIZED";
            case 402 -> "QUOTA_EXCEEDED";
            case 403 -> "FORBIDDEN";
            case 404 -> "NOT_FOUND";
            case 409 -> "CONFLICT";
            case 413 -> "PAYLOAD_TOO_LARGE";
            case 429 -> "RATE_LIMITED";
            default -> status >= 500 ? "INTERNAL" : "ERROR";
        };
    }

    static String messageForStatus(int status) {
        return switch (status) {
            case 401 -> "API key missing, wrong or revoked";
            case 402 -> "monthly allowance exhausted";
            case 403 -> "this key may not do that";
            case 404 -> "not found in this scope";
            case 429 -> "too many requests";
            default -> status >= 500 ? "the API failed" : "request failed with status " + status;
        };
    }
}
