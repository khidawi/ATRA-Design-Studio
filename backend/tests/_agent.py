"""
Ratifying an agent in a test. The platform asks for a recorded review when the gate says REVIEW or when the person ratifying owns the agent; these tests are about something else
and only need a ratified agent, so this records the review the way a second person would and ratifies again.
"""
from tests._auth import authed_client


def ratify(api, body):
    r = api.post("/api/agents/ratify", json=body)
    detail = r.json().get("detail", "") if r.status_code == 422 else ""
    if "records a review" in detail or "recorded review" in detail:
        with authed_client("compliance", "Zz Independent Reviewer") as other:
            rv = other.post(f"/api/agents/designs/{body['design_key']}/review", json={"decision": "APPROVED", "note": "Reviewed for the test."})
            assert rv.status_code == 201, rv.text
        r = api.post("/api/agents/ratify", json=body)
    return r
