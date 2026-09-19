# Creates a liveness session (Ruby, stdlib only).
require "json"
require "net/http"

base_url = ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1")
uri = URI("#{base_url}/sessions")

req = Net::HTTP::Post.new(uri, "X-API-Key" => ENV.fetch("CATALISA_API_KEY"), "Content-Type" => "application/json")
req.body = { flow: "LIVENESS_ONLY", purpose: "abertura de conta", metadata: { orderId: "123" } }.to_json
res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(req) }
body = JSON.parse(res.body)

abort "Error #{res.code}: #{body.dig('details', 'code') || body['error']}" unless res.code == "201"
puts "sessionId: #{body['data']['sessionId']}"
puts "captureUrl: #{body['data']['handoff']['captureUrl']}"
