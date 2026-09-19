# Handles 402 (quota) and 403 (suspended subaccount) when creating a session (Ruby 3, stdlib only).
require "json"
require "net/http"

base_url = ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1")
uri = URI("#{base_url}/sessions")
req = Net::HTTP::Post.new(uri, "X-API-Key" => ENV.fetch("CATALISA_API_KEY"),
                               "X-Subaccount-Id" => ENV.fetch("CATALISA_SUBACCOUNT_ID"),
                               "Content-Type" => "application/json")
req.body = { flow: "LIVENESS_ONLY", purpose: "abertura de conta" }.to_json
res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(req) }
body = JSON.parse(res.body)
code = body.dig("details", "code") || body["error"]

case [res.code, code]
in ["201", _]
  puts "ok: #{body['data']['handoff']['captureUrl']}"
in ["402", "QUOTA_EXCEEDED"]
  puts "blocked: QUOTA_EXCEEDED — monthly quota used (#{body['details']['used']}/#{body['details']['monthlyQuota']})"
in ["403", "SUBACCOUNT_SUSPENDED"]
  puts "blocked: SUBACCOUNT_SUSPENDED — subaccount suspended"
else
  abort "error #{res.code}: #{code}"
end
