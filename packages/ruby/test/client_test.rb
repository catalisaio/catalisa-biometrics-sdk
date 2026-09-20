# frozen_string_literal: true

require_relative "test_helper"

class ClientTest < Minitest::Test
  # A transport that answers from a queue and records what went out.
  def client(answers, **options)
    @requests = []
    queue = answers.dup
    transport = lambda do |request|
      @requests << request
      answer = queue.shift || { status: 500, body: '{"error":"INTERNAL"}' }
      { status: answer[:status], headers: answer[:headers] || {}, body: answer[:body] }
    end

    Catalisa::Biometrics::Client.new(
      api_key: "bio_test_key",
      base_url: "https://api.example/v1",
      transport: transport,
      **options,
    )
  end

  def test_a_credential_is_required
    assert_raises(ArgumentError) { Catalisa::Biometrics::Client.new }
    Catalisa::Biometrics::Client.new(access_token: "jwt")
  end

  def test_create_session_sends_the_key_and_returns_the_envelope
    subject = client(
      [{ status: 201, body: '{"data":{"sessionId":"s1","status":"SESSION_OPEN","environment":"test","provider":"MOCK","handoff":{"captureUrl":"https://capture/x"}}}' }],
      subaccount_id: "sub-1",
    )

    session = subject.create_session(
      flow: Catalisa::Biometrics::Flows::LIVENESS_ONLY,
      purpose: "abertura de conta",
      idempotency_key: "idem-1",
      metadata: { orderId: "123" },
    )

    request = @requests.first
    assert_equal "https://api.example/v1/sessions", request[:url]
    assert_equal "bio_test_key", request[:headers]["X-API-Key"]
    assert_equal "sub-1", request[:headers]["X-Subaccount-Id"]
    assert_equal "idem-1", request[:headers]["Idempotency-Key"]
    assert_equal "LIVENESS_ONLY", JSON.parse(request[:body])["flow"]
    assert_equal "s1", session["sessionId"]
    assert_equal "test", session["environment"]
    assert_equal "https://capture/x", session.dig("handoff", "captureUrl")
  end

  def test_quota_and_suspension_keep_their_code_and_numbers
    subject = client([{ status: 402, body: '{"error":"PAYMENT_REQUIRED","message":"cota","details":{"code":"QUOTA_EXCEEDED","used":100,"monthlyQuota":100}}' }])

    error = assert_raises(Catalisa::Biometrics::Error) do
      subject.create_session(flow: "LIVENESS_ONLY", purpose: "x")
    end
    assert error.quota_exceeded?
    refute error.subaccount_suspended?
    assert_equal 100, error.details["used"]

    subject = client([{ status: 403, body: '{"error":"FORBIDDEN","message":"suspensa","details":{"code":"SUBACCOUNT_SUSPENDED","reason":"inadimplência"}}' }])
    error = assert_raises(Catalisa::Biometrics::Error) do
      subject.create_session(flow: "LIVENESS_ONLY", purpose: "x")
    end
    assert error.subaccount_suspended?
    assert_equal "inadimplência", error.details["reason"]
  end

  def test_an_html_error_page_still_yields_a_usable_code
    # A proxy in front of the API can answer HTML. The caller still needs a code.
    subject = client([{ status: 502, body: "<html>502</html>" }], max_retries: 0)

    error = assert_raises(Catalisa::Biometrics::Error) { subject.session("s1") }

    assert_equal "INTERNAL", error.code
    assert error.transient?
  end

  def test_reads_retry_but_session_creation_does_not
    subject = client([
      { status: 500, body: '{"error":"INTERNAL"}' },
      { status: 200, body: '{"data":{"sessionId":"s1","status":"APPROVED"}}' },
    ])
    assert_equal "APPROVED", subject.session("s1")["status"]
    assert_equal 2, @requests.length

    # Creating twice would open two sessions and spend the allowance twice.
    subject = client([
      { status: 500, body: '{"error":"INTERNAL"}' },
      { status: 201, body: '{"data":{"sessionId":"s2"}}' },
    ])
    assert_raises(Catalisa::Biometrics::Error) { subject.create_session(flow: "LIVENESS_ONLY", purpose: "x") }
    assert_equal 1, @requests.length
  end

  def test_rate_limit_is_retried_even_on_creation
    # The rate limiter refuses before the handler runs: nothing was done.
    subject = client([
      { status: 429, headers: { "retry-after" => "0" }, body: '{"error":"RATE_LIMITED"}' },
      { status: 201, body: '{"data":{"sessionId":"s3"}}' },
    ])

    session = subject.create_session(flow: "LIVENESS_ONLY", purpose: "x")

    assert_equal "s3", session["sessionId"]
    assert_equal 2, @requests.length
  end

  def test_list_sends_pagination_and_filters
    subject = client([{ status: 200, body: '{"data":[],"meta":{"total":0}}' }])

    subject.sessions(page: 2, page_size: 50, status: "APPROVED", environment: "test")

    url = @requests.first[:url]
    assert_includes url, "page%5Bnumber%5D=2"
    assert_includes url, "page%5Bsize%5D=50"
    assert_includes url, "status=APPROVED"
    assert_includes url, "environment=test"
  end

  def test_submit_capture_uses_the_capture_token_not_the_api_key
    subject = client([{ status: 200, body: '{"data":{"sessionId":"s1","status":"RETRY_ALLOWED","reasons":["quality.too_dark"]}}' }])

    out = subject.submit_capture("s1", "capture-token", video: "webm-bytes", channel: "SDK", telemetry: { fps: 30 })

    request = @requests.first
    assert_equal "Bearer capture-token", request[:headers]["Authorization"]
    refute request[:headers].key?("X-API-Key")
    assert_match(/\Amultipart\/form-data; boundary=/, request[:headers]["Content-Type"])
    assert_includes request[:body], "webm-bytes"
    assert_includes request[:body], '{"fps":30}'
    assert_includes request[:body], 'name="channel"'
    assert_equal "RETRY_ALLOWED", out["status"]
  end

  def test_submit_capture_refuses_an_empty_video_before_the_network
    subject = client([])

    assert_raises(Catalisa::Biometrics::Error) { subject.submit_capture("s1", "tok", video: "") }
    assert_raises(Catalisa::Biometrics::Error) { subject.submit_capture("s1", "", video: "x") }
    assert_equal 0, @requests.length
  end

  def test_terminal_statuses_are_the_ones_that_never_change
    assert Catalisa::Biometrics::Statuses.terminal?("APPROVED")
    assert Catalisa::Biometrics::Statuses.terminal?("CANCELLED")
    refute Catalisa::Biometrics::Statuses.terminal?("RETRY_ALLOWED")
    refute Catalisa::Biometrics::Statuses.terminal?("SESSION_OPEN")
  end
end
