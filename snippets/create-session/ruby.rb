# gem install catalisa-biometrics
require "catalisa/biometrics"

bio = Catalisa::Biometrics::Client.new(
  api_key: ENV.fetch("CATALISA_API_KEY"),
  base_url: ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"),
)

session = bio.create_session(
  flow: "LIVENESS_ONLY",
  purpose: "abertura de conta",
  metadata: { orderId: "123" },
)

puts "sessionId: #{session['sessionId']}"
puts "captureUrl: #{session['handoff']['captureUrl']}" # send the person here
