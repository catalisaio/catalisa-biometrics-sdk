# Reads the session envelope (Ruby, stdlib only). Usage: SESSION_ID=… ruby ruby.rb
require "json"
require "net/http"

base_url = ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1")
uri = URI("#{base_url}/sessions/#{URI.encode_www_form_component(ENV.fetch('SESSION_ID'))}")

req = Net::HTTP::Get.new(uri, "X-API-Key" => ENV.fetch("CATALISA_API_KEY"))
res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(req) }
abort "Error #{res.code}" unless res.code == "200"

session = JSON.parse(res.body)["data"]
puts "status: #{session['status']}"
if session["decision"]
  puts "decision: #{session['decision']['outcome']} #{session['decision']['reasons'].join(', ')}"
  session["checks"].each { |c| puts " - #{c['kind']}: #{c['status']} (score #{c['score']} / threshold #{c['threshold']})" }
end
