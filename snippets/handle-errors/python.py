import os
import sys

from catalisa_biometrics import Biometrics, BiometricsError, QuotaExceededError, RateLimitError, SubaccountSuspendedError

bio = Biometrics(
    os.environ["CATALISA_API_KEY"],
    base_url=os.environ.get("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"),
    subaccount_id=os.environ.get("CATALISA_SUBACCOUNT_ID"),  # organization key acting on behalf of the subaccount
)

try:
    session = bio.sessions.create(flow="LIVENESS_ONLY", purpose="abertura de conta")
    print("ok:", session["handoff"]["captureUrl"])
except QuotaExceededError as e:  # 402
    print(f"blocked: {e.code} — monthly quota used ({e.details['used']}/{e.details['monthlyQuota']})")
except SubaccountSuspendedError as e:  # 403
    print(f"blocked: {e.code} — subaccount suspended")
except RateLimitError as e:  # 429 (the SDK already retried)
    print(f"rate limited; retry in {e.retry_after or 1} s")
except BiometricsError as e:
    print(f"error {e.status}: {e.code} (requestId {e.request_id})", file=sys.stderr)
    sys.exit(1)
