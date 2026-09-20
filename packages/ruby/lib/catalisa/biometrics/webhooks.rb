# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "time"

module Catalisa
  module Biometrics
    # Verification of Catalisa Webhooks Engine deliveries:
    #
    #   message   = x-webhook-id + "\n" + x-webhook-timestamp + "\n" + raw body
    #   signature = RSA-SHA256 (PKCS#1 v1.5), base64, in x-webhook-signature as "v1=<base64>"
    #   key       = the subscription's PUBLIC key, chosen by x-webhook-key-id
    #
    # The signature is asymmetric: there is no shared secret to leak. The engine
    # does not refuse old deliveries — the receiver enforces the time tolerance,
    # or a captured delivery could be replayed forever.
    class WebhookVerifier
      MESSAGES = {
        missing_headers: "missing x-webhook-id, x-webhook-timestamp, x-webhook-key-id or x-webhook-signature",
        timestamp_invalid: "x-webhook-timestamp is not an ISO 8601 date",
        timestamp_out_of_tolerance: "delivery is outside the time tolerance (possible replay)",
        unknown_key_id: "no public key for this x-webhook-key-id",
        unsupported_signature_version: "unsupported signature version (expected v1=)",
        invalid_signature: "invalid signature",
      }.freeze

      # @param public_keys [Hash{String=>String}] keyId => PEM. Keep a retired key
      #   here while deliveries signed with it may still arrive.
      # @param tolerance [Integer] seconds; 0 disables the check (not recommended)
      # @param now [Proc] reference clock, for tests
      def initialize(public_keys, tolerance: 300, now: -> { Time.now })
        @public_keys = public_keys
        @tolerance = tolerance
        @now = now
      end

      # Verifies a delivery and returns the parsed event.
      #
      # Pass the RAW body — the bytes as they arrived. Decoding and re-encoding
      # the JSON changes them, and the signature will not match.
      #
      # @param headers [Hash] however your stack hands them over: Rack's
      #   HTTP_X_WEBHOOK_ID, a framework's x-webhook-id, arrays included
      def verify(headers, raw_body)
        id = header(headers, "x-webhook-id")
        timestamp = header(headers, "x-webhook-timestamp")
        key_id = header(headers, "x-webhook-key-id")
        signature = header(headers, "x-webhook-signature")

        fail_with(:missing_headers) if [id, timestamp, key_id, signature].any? { |v| v.nil? || v.empty? }

        sent_at = begin
          Time.iso8601(timestamp)
        rescue ArgumentError
          fail_with(:timestamp_invalid)
        end
        fail_with(:timestamp_out_of_tolerance) if @tolerance.positive? && (@now.call - sent_at).abs > @tolerance
        fail_with(:unsupported_signature_version) unless signature.start_with?("v1=")

        pem = @public_keys[key_id]
        fail_with(:unknown_key_id) if pem.nil?

        raw = Base64.strict_decode64(signature[3..]) rescue fail_with(:invalid_signature)
        key = begin
          OpenSSL::PKey::RSA.new(pem)
        rescue OpenSSL::PKey::RSAError
          fail_with(:unknown_key_id)
        end

        message = "#{id}\n#{timestamp}\n#{raw_body}"
        fail_with(:invalid_signature) unless key.verify(OpenSSL::Digest.new("SHA256"), raw, message)

        begin
          JSON.parse(raw_body)
        rescue JSON::ParserError => e
          fail_with(:invalid_signature, "the signed body is not valid JSON: #{e.message}")
        end
      end

      private

      def header(headers, name)
        headers.each do |key, value|
          normalized = key.to_s.downcase.tr("_", "-")
          normalized = normalized.delete_prefix("http-")
          next unless normalized == name

          found = value.is_a?(Array) ? value.first : value
          return found.nil? || found.to_s.empty? ? nil : found.to_s
        end
        nil
      end

      def fail_with(failure, message = nil)
        raise WebhookVerificationError.new(failure, message || MESSAGES.fetch(failure))
      end
    end

    # OFFLINE verification of the signed evidence, without calling Catalisa:
    #
    #   message   = "{sessionId}|{attempt}|{bundleHash}|{signedAt}"
    #   signature = Ed25519 (RFC 8032), base64
    #   key       = GET /evidence-keys, by the signature's keyId
    #
    # This is what lets a third party — an auditor, a court — confirm years later
    # that the bundle is the one Catalisa signed.
    module Evidence
      module_function

      # The exact string that was signed.
      def message(session_id, attempt, bundle_hash, signed_at)
        "#{session_id}|#{attempt}|#{bundle_hash}|#{signed_at}"
      end

      # @return [Hash] valid:, key_id:, unknown_key:, retired_at:
      def verify(session_id, attempt, bundle_hash, signature, keys)
        key_id = signature["keyId"] || signature[:keyId]
        key = keys.find { |k| (k["keyId"] || k[:keyId]) == key_id }
        return { valid: false, key_id: key_id, unknown_key: true, retired_at: nil } if key.nil?

        retired_at = key["retiredAt"] || key[:retiredAt]
        out = { valid: false, key_id: key_id, unknown_key: false, retired_at: retired_at }
        return out unless (signature["alg"] || signature[:alg]) == "Ed25519"

        raw = Base64.strict_decode64((signature["value"] || signature[:value]).to_s) rescue (return out)
        public_key = begin
          OpenSSL::PKey.read(key["publicKeyPem"] || key[:publicKeyPem])
        rescue OpenSSL::PKey::PKeyError
          return out
        end
        # Ed25519 signs the message itself, with no separate digest step: hence the
        # nil digest. Not verify_raw — that one answers false for Ed25519 instead
        # of raising, which is a quiet way to reject every valid receipt.
        signed = message(session_id, attempt, bundle_hash, signature["signedAt"] || signature[:signedAt])
        out[:valid] = public_key.verify(nil, raw, signed)

        out
      rescue OpenSSL::PKey::PKeyError
        out
      end
    end
  end
end
