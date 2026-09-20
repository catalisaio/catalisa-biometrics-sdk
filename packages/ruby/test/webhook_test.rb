# frozen_string_literal: true

require_relative "test_helper"

class WebhookTest < Minitest::Test
  include VectorHelper

  def webhook = vectors["webhook"]

  def verifier(now: nil, tolerance: 300)
    at = Time.iso8601(now || webhook["now"])
    Catalisa::Biometrics::WebhookVerifier.new(webhook["keys"], tolerance: tolerance, now: -> { at })
  end

  def test_accepts_a_genuine_delivery
    event = verifier.verify(webhook["headers"], webhook["body"])

    refute_empty event["id"]
    assert_equal "biometrics.session.completed", event["type"]
  end

  def test_reads_headers_in_rack_shape
    # Rack hands them over as HTTP_X_WEBHOOK_ID; a framework as x-webhook-id.
    rack = webhook["headers"].transform_keys { |name| "HTTP_#{name.upcase.tr('-', '_')}" }

    event = verifier.verify(rack, webhook["body"])

    refute_empty event["id"]
  end

  def test_rejects_a_tampered_body
    error = assert_raises(Catalisa::Biometrics::WebhookVerificationError) do
      verifier.verify(webhook["headers"], webhook["tamperedBody"])
    end

    assert_equal :invalid_signature, error.failure
  end

  def test_rejects_an_old_delivery
    # The engine does not refuse old deliveries — the receiver does, or a captured
    # delivery could be replayed forever.
    sent_at = Time.iso8601(webhook["headers"]["x-webhook-timestamp"])
    late = (sent_at + 600).iso8601

    error = assert_raises(Catalisa::Biometrics::WebhookVerificationError) do
      verifier(now: late).verify(webhook["headers"], webhook["body"])
    end
    assert_equal :timestamp_out_of_tolerance, error.failure

    event = verifier(now: late, tolerance: 3600).verify(webhook["headers"], webhook["body"])
    refute_empty event["id"]
  end

  def test_rejects_missing_headers_unknown_key_and_another_version
    error = assert_raises(Catalisa::Biometrics::WebhookVerificationError) { verifier.verify({}, webhook["body"]) }
    assert_equal :missing_headers, error.failure

    unknown = webhook["headers"].merge("x-webhook-key-id" => "whk_not_mine")
    error = assert_raises(Catalisa::Biometrics::WebhookVerificationError) { verifier.verify(unknown, webhook["body"]) }
    assert_equal :unknown_key_id, error.failure

    old_version = webhook["headers"].merge("x-webhook-signature" => "v2=abc")
    error = assert_raises(Catalisa::Biometrics::WebhookVerificationError) { verifier.verify(old_version, webhook["body"]) }
    assert_equal :unsupported_signature_version, error.failure
  end

  def test_verifies_evidence_offline
    evidence = vectors["evidence"]
    keys = evidence["evidenceKeysResponse"]["data"]
    signature = evidence["evidence"]["signature"]
    session_id = evidence["sessionId"]
    attempt = evidence["attempt"]
    bundle_hash = evidence["evidence"]["bundleHash"]

    out = Catalisa::Biometrics::Evidence.verify(session_id, attempt, bundle_hash, signature, keys)
    assert out[:valid]
    refute out[:unknown_key]

    # Any change to what was signed breaks it — that is the whole point.
    refute Catalisa::Biometrics::Evidence.verify(session_id, attempt + 1, bundle_hash, signature, keys)[:valid]
    refute Catalisa::Biometrics::Evidence.verify(session_id, attempt, "0000", signature, keys)[:valid]

    unknown = Catalisa::Biometrics::Evidence.verify(
      session_id, attempt, bundle_hash, signature.merge("keyId" => "ev-unknown"), keys
    )
    assert unknown[:unknown_key]
    refute unknown[:valid]
  end
end
