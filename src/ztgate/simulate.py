"""Policy simulator: "what would happen if" for a user, device, and context, without touching live state."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from .engine import Gate
from .geo import CITY_BY_NAME, UNKNOWN, locate
from .policy import Inputs, Policy, evaluate, parse_policy
from .posture import trust_of
from .risk import RiskEngine

POSTURE_FIELDS = {"managed", "disk_encrypted", "edr_running", "screen_lock", "os_supported", "patch_age_days"}


class SimError(ValueError):
    pass


def simulate(g: Gate, req: dict) -> dict:
    users, devices = g.data.users, g.data.devices
    uid = req.get("user")
    if uid not in users:
        raise SimError(f"unknown user {uid!r}")
    u = users[uid]
    app = req.get("app")
    policy: Policy
    if req.get("policy_yaml"):
        policy = parse_policy(req["policy_yaml"], "draft")
        app = policy.app
    elif app in g.policies:
        policy = g.policies[app]
    else:
        raise SimError(f"unknown app {app!r}")
    action = req.get("action", "read")

    did = req.get("device") or f"lt-{uid}"
    dev = devices.get(did) if did != "unregistered" else None
    if did != "unregistered" and dev is None:
        raise SimError(f"unknown device {did!r}")
    overrides = {k: v for k, v in (req.get("posture") or {}).items() if k in POSTURE_FIELDS}
    if dev is not None and overrides:
        dev = replace(dev, **overrides)
    trust = trust_of(dev)

    ip = req.get("ip") or ""
    city = locate(ip) if ip else CITY_BY_NAME[u.city]
    if city is UNKNOWN and req.get("city") in CITY_BY_NAME:
        city = CITY_BY_NAME[req["city"]]
    if req.get("city") in CITY_BY_NAME and not ip:
        city = CITY_BY_NAME[req["city"]]
    hour = float(req.get("local_hour", 11))
    day = g.data.as_of.replace(hour=0, minute=0, second=0, microsecond=0)
    ts: datetime = day + timedelta(hours=hour - city.tz)

    # A throwaway risk engine with this user's known devices and countries.
    risk = RiskEngine(g.risk.threat_intel)
    risk.known_devices[uid] = set(g.risk.known_devices.get(uid, set()))
    risk.known_countries[uid] = set(g.risk.known_countries.get(uid, set()))
    for k in range(int(req.get("failed_logins", 0))):
        risk.record_failure(uid, ip or "0.0.0.0", ts - timedelta(minutes=5 + k))
    prev = req.get("previous") or {}
    if prev.get("city") in CITY_BY_NAME:
        risk.last_seen[uid] = (ts - timedelta(minutes=float(prev.get("minutes_ago", 60))), CITY_BY_NAME[prev["city"]])
    if req.get("risk_signal"):
        risk.add_event(uid, ts - timedelta(minutes=1), int(req["risk_signal"]), "simulated risk signal")
    score = risk.score(uid, did, dev.owner if dev else None, ip, ts, city=city)

    active, status = g.user_status(uid, ts if not req.get("as_of") else datetime.fromisoformat(req["as_of"]))
    mfa = req.get("mfa_age_minutes", 30)
    session = req.get("session", "fresh")  # fresh | sso | replayed
    token_device = None if session == "fresh" else (f"lt-{uid}" if session == "replayed" else did)
    x = Inputs(
        user=uid, groups=list(u.groups), user_active=active, user_status=status, app=app, action=action, device=did,
        device_trust=trust.level,
        device_detail="; ".join(s["detail"] for s in trust.signals if not s["ok"]) or "all posture checks pass",
        risk=score.score, risk_detail="; ".join(c["detail"] for c in score.components) or "no risk signals",
        mfa_age=None if mfa is None else float(mfa), country=city.country, city=city.name, local_hour=hour,
        token_device=token_device, ip=ip,
    )
    d = evaluate(policy, x)
    after = None
    if d.outcome == "step_up":
        after = evaluate(policy, replace(x, mfa_age=0.0, stepped_up=True)).outcome
    return {
        "decision": d.outcome, "after_step_up": after, "restrictions": d.restrictions, "reasons": d.reasons,
        "trace": d.trace, "risk": score.to_dict(), "device_trust": trust.to_dict(), "inputs": x.to_dict(),
        "session_lifetime_minutes": d.session_lifetime, "policy": policy.to_dict(),
    }
