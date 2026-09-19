import os

from catalisa_biometrics import Biometrics, NotFoundError

bio = Biometrics(os.environ["CATALISA_API_KEY"], base_url=os.environ.get("CATALISA_BIOMETRICS_URL", "https://api.biometrics.catalisa.app/v1"))

try:
    session = bio.sessions.get(os.environ["SESSION_ID"])
    print("status:", session["status"])
    if session["decision"]:
        print("decision:", session["decision"]["outcome"], ", ".join(session["decision"]["reasons"]) or "(no reasons)")
        for c in session["checks"]:
            print(f" - {c['kind']}: {c['status']} (score {c['score']} / threshold {c['threshold']})")
except NotFoundError:
    print("Session not found (or owned by another organization)")
