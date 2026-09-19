# pip install catalisa-biometrics
import os

from catalisa_biometrics import Biometrics

bio = Biometrics(
    os.environ["CATALISA_API_KEY"],
    base_url=os.environ.get("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"),
)

session = bio.sessions.create(
    flow="LIVENESS_ONLY",
    purpose="abertura de conta",
    metadata={"orderId": "123"},
)

print("sessionId:", session["sessionId"])
print("captureUrl:", session["handoff"]["captureUrl"])  # send the person here
