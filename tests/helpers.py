from __future__ import annotations

import yaml

from ztgate.policy import Inputs, Policy, parse_policy

BASE = {
    "app": "payroll",
    "sensitivity": "critical",
    "allow_groups": ["payroll-admins"],
    "deny_groups": ["contractors"],
    "device": {"min_trust": "high"},
    "risk": {"step_up_above": 20, "deny_above": 40},
    "mfa": {"max_age_minutes": 240},
    "step_up": {"actions": ["write", "export"], "mfa_max_age_minutes": 15},
    "hours": {"start": 6, "end": 22, "outside": "step_up"},
    "location": {"allowed_countries": ["US", "GB"]},
    "session": {"lifetime_minutes": 60},
}


def policy(**over) -> Policy:
    data = {**BASE, **over}
    data = {k: v for k, v in data.items() if v is not None}
    return parse_policy(yaml.safe_dump(data))


def inputs(**over) -> Inputs:
    base = dict(
        user="u1", groups=["hr", "payroll-admins", "all-employees"], user_active=True, user_status="active employee",
        app="payroll", action="read", device="lt-u1", device_trust="high", device_detail="all posture checks pass",
        risk=0, risk_detail="no risk signals", mfa_age=5.0, country="US", city="San Francisco", local_hour=11.0,
    )
    base.update(over)
    return Inputs(**base)


def result(decision, check: str) -> str:
    return next(t["result"] for t in decision.trace if t["check"] == check)
