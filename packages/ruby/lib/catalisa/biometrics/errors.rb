# frozen_string_literal: true

module Catalisa
  module Biometrics
    # Every failed call raises this. The API answers
    # `{"error":"<code>","message":"...","details":{...}}`, so #code is the API's
    # own word for what happened — branch on it, never on the message.
    class Error < StandardError
      # HTTP status, or 0 when the request never reached the API.
      attr_reader :status

      # API error code (VALIDATION, NOT_FOUND, QUOTA_EXCEEDED…), or
      # TIMEOUT/CONNECTION when the request did not complete.
      attr_reader :code

      # Whatever the API attached: the offending fields, the quota numbers.
      attr_reader :details

      # `x-request-id`, when the API sends one — quote it in a support ticket.
      attr_reader :request_id

      # `Retry-After` in seconds, on a 429.
      attr_reader :retry_after

      def initialize(status:, code:, message:, details: {}, request_id: nil, retry_after: nil)
        super(message)
        @status = status
        @code = code
        @details = details
        @request_id = request_id
        @retry_after = retry_after
      end

      # The customer's monthly allowance is gone. A test key never gets here.
      def quota_exceeded? = code == "QUOTA_EXCEEDED"

      # The subaccount is suspended: nothing opens until it is reactivated.
      def subaccount_suspended? = code == "SUBACCOUNT_SUSPENDED"

      # Worth trying again by itself: rate limit, server fault or network.
      def transient? = status == 429 || status >= 500 || status.zero?

      # Builds the error from what the API answered. A body that is not the
      # expected envelope — an HTML page from a proxy, say — still yields a usable
      # code, taken from the status.
      def self.from_response(status, body, headers)
        parsed = begin
          body.to_s.empty? ? nil : JSON.parse(body)
        rescue JSON::ParserError
          nil
        end

        code = code_for(status)
        message = ""
        details = {}

        if parsed.is_a?(Hash)
          code = parsed["error"] if parsed["error"].is_a?(String) && !parsed["error"].empty?
          message = parsed["message"] if parsed["message"].is_a?(String)
          if parsed["details"].is_a?(Hash)
            details = parsed["details"]
            # The machine-readable code lives inside details on the cases that
            # carry numbers with them (quota, suspension).
            code = details["code"] if details["code"].is_a?(String) && !details["code"].empty?
          end
        end
        message = message_for(status) if message.empty?

        new(
          status: status,
          code: code,
          message: message,
          details: details,
          request_id: headers["x-request-id"],
          retry_after: headers["retry-after"]&.to_i,
        )
      end

      def self.code_for(status)
        case status
        when 400, 415 then "VALIDATION"
        when 401 then "UNAUTHORIZED"
        when 402 then "QUOTA_EXCEEDED"
        when 403 then "FORBIDDEN"
        when 404 then "NOT_FOUND"
        when 409 then "CONFLICT"
        when 413 then "PAYLOAD_TOO_LARGE"
        when 429 then "RATE_LIMITED"
        when 500.. then "INTERNAL"
        else "ERROR"
        end
      end
      private_class_method :code_for

      def self.message_for(status)
        case status
        when 401 then "API key missing, wrong or revoked"
        when 402 then "monthly allowance exhausted"
        when 403 then "this key may not do that"
        when 404 then "not found in this scope"
        when 429 then "too many requests"
        when 500.. then "the API failed"
        else "request failed with status #{status}"
        end
      end
      private_class_method :message_for
    end

    # A webhook delivery that failed verification. Answer 400 and do not process
    # the body.
    class WebhookVerificationError < StandardError
      # Which check failed: :missing_headers, :invalid_signature,
      # :timestamp_out_of_tolerance, :unknown_key_id, :unsupported_signature_version.
      attr_reader :failure

      def initialize(failure, message)
        super(message)
        @failure = failure
      end
    end
  end
end
