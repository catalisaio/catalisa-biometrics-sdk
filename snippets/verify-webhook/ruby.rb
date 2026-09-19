# Receives the Biometrics webhook and verifies the signature (Ruby, stdlib only: socket, openssl, json).
# In Rails, use request.raw_post as the body and the same valid? check.
# CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
require "json"
require "openssl"
require "socket"
require "time"

PUBLIC_KEYS = JSON.parse(ENV.fetch("CATALISA_WEBHOOK_KEYS")).transform_values { |pem| OpenSSL::PKey.read(pem) }

def valid?(headers, body)
  id, timestamp, key_id, signature = headers.values_at("x-webhook-id", "x-webhook-timestamp", "x-webhook-key-id", "x-webhook-signature")
  return false unless id && timestamp && key_id && signature&.start_with?("v1=")
  return false if (Time.now - Time.iso8601(timestamp)).abs > 300 # replay tolerance
  key = PUBLIC_KEYS[key_id] or return false
  key.verify("SHA256", signature.delete_prefix("v1=").unpack1("m"), "#{id}\n#{timestamp}\n#{body}")
rescue ArgumentError, OpenSSL::PKey::PKeyError
  false
end

server = TCPServer.new("0.0.0.0", Integer(ENV.fetch("PORT", "3000")))
loop do
  client = server.accept
  request_line = client.gets
  headers = {}
  while (line = client.gets) && line != "\r\n"
    name, value = line.split(":", 2)
    headers[name.strip.downcase] = value.strip
  end
  body = client.read(headers["content-length"].to_i) # RAW body
  ok = request_line.start_with?("POST /webhooks/biometrics ") && valid?(headers, body)
  if ok
    event = JSON.parse(body) # idempotency: event["id"], not the x-webhook-id header
    puts "#{event['type']} #{event.dig('data', 'sessionId')} → #{event.dig('data', 'outcome')}"
  end
  client.write(ok ? "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" : "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
  client.close
end
