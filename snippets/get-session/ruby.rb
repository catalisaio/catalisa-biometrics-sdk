require "catalisa/biometrics"

bio = Catalisa::Biometrics::Client.new(
  api_key: ENV.fetch("CATALISA_API_KEY"),
  base_url: ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"),
)

begin
  session = bio.session(ENV.fetch("SESSION_ID"))
  puts "status: #{session['status']}"
  if session["decision"]
    reasons = session["decision"]["reasons"].join(", ")
    puts "decision: #{session['decision']['outcome']} #{reasons.empty? ? '(no reasons)' : reasons}"
    session["checks"].each do |check|
      puts " - #{check['kind']}: #{check['status']} (score #{check['score']} / threshold #{check['threshold']})"
    end
  end
rescue Catalisa::Biometrics::Error => e
  raise unless e.status == 404

  puts "Session not found (or owned by another organization)"
end
