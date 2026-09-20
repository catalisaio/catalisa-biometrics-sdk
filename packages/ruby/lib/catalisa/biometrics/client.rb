# frozen_string_literal: true

require "json"
require "net/http"
require "securerandom"
require "uri"

module Catalisa
  module Biometrics
    DEFAULT_BASE_URL = "https://api.biometrics.catalisa.app/v1"

    # Sandbox or production. A key belongs to one; a session keeps the one it was
    # born in.
    module Environments
      TEST = "test"
      LIVE = "live"
    end

    module Flows
      ONBOARDING = "ONBOARDING"
      AUTHENTICATION = "AUTHENTICATION"
      ENROLLMENT = "ENROLLMENT"
      LIVENESS_ONLY = "LIVENESS_ONLY"
      DEDUP = "DEDUP"
    end

    module Statuses
      SESSION_OPEN = "SESSION_OPEN"
      PROCESSING = "PROCESSING"
      APPROVED = "APPROVED"
      REJECTED = "REJECTED"
      INCONCLUSIVE = "INCONCLUSIVE"
      RETRY_ALLOWED = "RETRY_ALLOWED"
      EXPIRED = "EXPIRED"
      CANCELLED = "CANCELLED"
      ERROR = "ERROR"

      TERMINAL = [APPROVED, REJECTED, INCONCLUSIVE, EXPIRED, CANCELLED].freeze

      # The session has settled: nothing will change after this.
      def self.terminal?(status) = TERMINAL.include?(status)
    end

    # Catalisa Biometrics client.
    #
    # The flow never trusts the browser:
    #
    #   1. your server creates a session and gets handoff.captureUrl;
    #   2. the person opens that URL (tab, iframe or WebView) and does the challenge;
    #   3. the decision reaches your server through the webhook, or through #session.
    #
    # The capture page never shows the result to the person in front of the
    # camera, on purpose: it would be a fraud oracle. Never decide anything from
    # front-end events.
    class Client
      # @param api_key [String] key from the console; a test key runs the sandbox
      # @param access_token [String, nil] an IAM JWT instead of an API key
      # @param subaccount_id [String, nil] act on behalf of a subaccount (organization key only)
      # @param timeout [Numeric] seconds per attempt
      # @param max_retries [Integer] reads and 429 only
      # @param transport [#call, nil] ->(request) { { status:, headers:, body: } }, for tests
      def initialize(api_key: nil, base_url: DEFAULT_BASE_URL, access_token: nil, subaccount_id: nil,
                     timeout: 30, max_retries: 2, transport: nil)
        if (api_key.nil? || api_key.empty?) && (access_token.nil? || access_token.empty?)
          raise ArgumentError, "Catalisa Biometrics: an API key (or an access token) is required"
        end

        @api_key = api_key
        @access_token = access_token
        @base_url = base_url.chomp("/")
        @subaccount_id = subaccount_id
        @timeout = timeout
        @max_retries = max_retries
        @transport = transport
      end

      # Opens a session. The answer carries handoff.captureUrl, where the person goes.
      #
      # Never retried on a 5xx or a network failure: the server does not
      # deduplicate by Idempotency-Key yet, and a retry could open two sessions
      # (and spend the allowance twice).
      def create_session(flow:, purpose:, idempotency_key: nil, **fields)
        headers = idempotency_key ? { "Idempotency-Key" => idempotency_key } : {}
        body = { flow: flow, purpose: purpose }.merge(fields)

        request(:post, "/sessions", body: body, headers: headers).fetch("data", {})
      end

      # Reads a session. One from another subaccount — or from the other
      # environment — answers 404, on purpose: existence is not confirmed.
      def session(session_id)
        request(:get, "/sessions/#{escape(session_id)}", idempotent: true).fetch("data", {})
      end

      # Lists sessions, newest first.
      def sessions(page: nil, page_size: nil, **filters)
        query = {}
        query["page[number]"] = page if page
        query["page[size]"] = page_size if page_size
        %i[status flow customer_id subject_cpf from to subaccount_id environment].each do |key|
          value = filters[key]
          next if value.nil? || value.to_s.empty?

          query[camel(key)] = value
        end

        request(:get, "/sessions", query: query, idempotent: true)
      end

      # Closes a session that has not settled. The allowance slot comes back.
      def cancel_session(session_id)
        request(:post, "/sessions/#{escape(session_id)}/cancel").fetch("data", {})
      end

      # Signed evidence plus short-lived download links for the artifacts.
      def evidence(session_id)
        request(:get, "/sessions/#{escape(session_id)}/evidence", idempotent: true).fetch("data", {})
      end

      # Asks the API to check the evidence signature. Handy, but it trusts the
      # same party that signed it: for an audit, verify offline with
      # Catalisa::Biometrics::Evidence.verify.
      def verify_evidence_on_server(session_id)
        request(:get, "/sessions/#{escape(session_id)}/evidence/verify", idempotent: true).fetch("data", {})
      end

      # Published signing keys, retired ones included, so old evidence still verifies.
      def evidence_keys
        request(:get, "/evidence-keys", idempotent: true).fetch("data", [])
      end

      # Uploads a capture your own app recorded, authenticating with the session's
      # capture token — the account key never leaves your server. Only video/webm
      # and video/mp4 are accepted, up to 16 MiB and 24 seconds.
      #
      # Prefer the hosted page when you can: it already runs the quality checks
      # that keep a useless recording from spending an attempt.
      def submit_capture(session_id, capture_token, video:, video_mime: "video/webm",
                         video_filename: "challenge.webm", telemetry: nil, channel: nil, captured_at: nil)
        raise Error.new(status: 0, code: "UNAUTHORIZED", message: "a capture token is required") if capture_token.to_s.empty?
        raise Error.new(status: 0, code: "VALIDATION", message: "the video is empty") if video.to_s.empty?

        boundary = "----catalisa#{SecureRandom.hex(8)}"
        parts = +"--#{boundary}\r\n"
        parts << "Content-Disposition: form-data; name=\"video\"; filename=\"#{video_filename}\"\r\n"
        parts << "Content-Type: #{video_mime}\r\n\r\n"
        parts << video.dup.force_encoding(Encoding::BINARY)
        parts << "\r\n"
        { "telemetry" => telemetry && JSON.generate(telemetry), "channel" => channel, "capturedAt" => captured_at }
          .each do |name, value|
            next if value.nil?

            parts << "--#{boundary}\r\nContent-Disposition: form-data; name=\"#{name}\"\r\n\r\n#{value}\r\n"
          end
        parts << "--#{boundary}--\r\n"

        answer = send_request(
          method: :post,
          url: "#{@base_url}/sessions/#{escape(session_id)}/captures",
          # The capture token authenticates on its own; the API key is not sent.
          headers: {
            "Accept" => "application/json",
            "User-Agent" => user_agent,
            "Authorization" => "Bearer #{capture_token}",
            "Content-Type" => "multipart/form-data; boundary=#{boundary}",
          },
          body: parts,
        )

        decode(answer).fetch("data", {})
      end

      private

      def user_agent = "catalisa-biometrics-ruby/#{VERSION}"

      def escape(value) = URI.encode_www_form_component(value.to_s)

      def camel(key)
        head, *rest = key.to_s.split("_")
        ([head] + rest.map(&:capitalize)).join
      end

      def request(method, path, query: {}, body: nil, headers: {}, idempotent: false)
        url = "#{@base_url}#{path}"
        url += "?#{URI.encode_www_form(query)}" unless query.empty?

        request_headers = { "Accept" => "application/json", "User-Agent" => user_agent }.merge(headers)
        if @access_token && !@access_token.empty?
          request_headers["Authorization"] = "Bearer #{@access_token}"
        else
          request_headers["X-API-Key"] = @api_key
        end
        request_headers["X-Subaccount-Id"] = @subaccount_id if @subaccount_id && !@subaccount_id.empty?
        payload = body && JSON.generate(body)
        request_headers["Content-Type"] = "application/json" if payload

        attempt = 0
        begin
          decode(send_request(method: method, url: url, headers: request_headers, body: payload))
        rescue Error => e
          # A 429 is always safe to retry: the rate limiter refuses before the
          # handler runs, so nothing was done.
          retryable = e.status == 429 || (idempotent && (e.status >= 500 || e.status.zero?))
          raise unless retryable && attempt < @max_retries

          sleep(backoff(attempt, e))
          attempt += 1
          retry
        end
      end

      def backoff(attempt, error)
        return [error.retry_after, 30].min if error.retry_after&.positive?

        base = 0.5 * (2**attempt)
        [base + rand * base * 0.25, 8.0].min
      end

      def decode(answer)
        status = answer[:status]
        raise Error.from_response(status, answer[:body], answer[:headers]) if status >= 400
        return {} if answer[:body].to_s.empty?

        JSON.parse(answer[:body])
      rescue JSON::ParserError => e
        raise Error.new(status: status, code: "INTERNAL", message: "unexpected answer: #{e.message}")
      end

      def send_request(method:, url:, headers:, body: nil)
        return @transport.call(method: method, url: url, headers: headers, body: body) if @transport

        uri = URI(url)
        klass = { get: Net::HTTP::Get, post: Net::HTTP::Post, patch: Net::HTTP::Patch, delete: Net::HTTP::Delete }.fetch(method)
        request = klass.new(uri, headers)
        request.body = body if body

        response = Net::HTTP.start(uri.host, uri.port,
                                   use_ssl: uri.scheme == "https",
                                   open_timeout: @timeout,
                                   read_timeout: @timeout) { |http| http.request(request) }

        { status: response.code.to_i, headers: response.each_header.to_h, body: response.body }
      rescue Net::OpenTimeout, Net::ReadTimeout
        raise Error.new(status: 0, code: "TIMEOUT", message: "no answer within #{@timeout}s")
      rescue SystemCallError, SocketError, OpenSSL::SSL::SSLError => e
        raise Error.new(status: 0, code: "CONNECTION", message: "connection failed: #{e.message}")
      end
    end
  end
end
