# Minimal server that receives the Biometrics webhook and verifies the signature.
# gem install catalisa-biometrics webrick   (webrick left the standard library in Ruby 3)
# CATALISA_WEBHOOK_KEYS = {"whk_…":"-----BEGIN PUBLIC KEY-----…"}
require "json"
require "webrick"
require "catalisa/biometrics"

verifier = Catalisa::Biometrics::WebhookVerifier.new(JSON.parse(ENV.fetch("CATALISA_WEBHOOK_KEYS"))) # tolerance: 300 s

server = WEBrick::HTTPServer.new(Port: Integer(ENV.fetch("PORT", "3000")), AccessLog: [], Logger: WEBrick::Log.new(File::NULL))

server.mount_proc "/webhooks/biometrics" do |req, res|
  begin
    event = verifier.verify(req.header, req.body) # RAW body: re-encoding it breaks the signature
  rescue Catalisa::Biometrics::WebhookVerificationError => e
    warn "webhook rejected: #{e.failure}"
    res.status = 400
    res.body = "invalid signature"
    next
  end

  # event["id"] is stable: use it for idempotency, a delivery can repeat
  warn "session #{event['data']['sessionId']} → #{event['data']['outcome']}" if event["type"] == "biometrics.session.completed"

  res.status = 200 # answer fast; do the work afterwards
  res.body = "ok"
end

trap("INT") { server.shutdown }
server.start
