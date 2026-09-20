require "catalisa/biometrics"

bio = Catalisa::Biometrics::Client.new(
  api_key: ENV.fetch("CATALISA_API_KEY"),
  base_url: ENV.fetch("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"),
  # organization key acting on behalf of the subaccount
  subaccount_id: ENV["CATALISA_SUBACCOUNT_ID"],
)

begin
  session = bio.create_session(flow: "LIVENESS_ONLY", purpose: "abertura de conta")
  puts "ok: #{session['handoff']['captureUrl']}"
rescue Catalisa::Biometrics::Error => e
  if e.quota_exceeded?            # 402
    puts "blocked: #{e.code} — monthly quota used (#{e.details['used']}/#{e.details['monthlyQuota']})"
  elsif e.subaccount_suspended?   # 403
    puts "blocked: #{e.code} — subaccount suspended"
  elsif e.status == 429           # the SDK already retried
    puts "rate limited; retry in #{e.retry_after || 1} s"
  else
    warn "error #{e.status}: #{e.code} (requestId #{e.request_id})"
    exit 1
  end
end
