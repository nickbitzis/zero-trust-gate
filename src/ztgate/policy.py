"""Per-app access policies: YAML parsing, validation, and evaluation with a full decision trace.

Every check runs and reports, even after one has already denied, so the trace explains the whole decision. The outcome
follows a fixed precedence: deny beats step-up, step-up beats allow with restrictions, and that beats allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import OUTCOMES, SENSITIVITIES, TRUST_LEVELS

ACTIONS = ["read", "write", "export", "admin"]
SCHEMA: dict[str, dict | type | tuple] = {
    "app": str,
    "name": str,
    "sensitivity": str,
    "owner": str,
    "description": str,
    "allow_groups": list,
    "deny_groups": list,
    "device": {"min_trust": str, "read_only_trust": (str, type(None))},
    "risk": {"step_up_above": int, "deny_above": int},
    "mfa": {"max_age_minutes": int},
    "step_up": {"actions": list, "mfa_max_age_minutes": int},
    "hours": {"start": (int, float), "end": (int, float), "outside": str},
    "location": {"allowed_countries": list, "denied_countries": list},
    "session": {"lifetime_minutes": int, "bind_to_device": bool},
    "identity": {"require_active": bool},
}
REQUIRED = ["app", "sensitivity", "allow_groups"]


class PolicyError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class Policy:
    app: str
    name: str
    sensitivity: str
    owner: str = ""
    description: str = ""
    allow_groups: list[str] = field(default_factory=list)
    deny_groups: list[str] = field(default_factory=list)
    min_trust: str = "low"
    read_only_trust: str | None = None
    step_up_risk: int = 30
    deny_risk: int = 60
    mfa_max_age: int = 720
    step_up_actions: list[str] = field(default_factory=list)
    step_up_mfa_age: int = 15
    hours: tuple[float, float] | None = None
    outside_hours: str = "step_up"
    allowed_countries: list[str] | None = None
    denied_countries: list[str] = field(default_factory=list)
    session_lifetime: int = 480
    bind_to_device: bool = True
    require_active: bool = True
    source: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "source"}


def _check_types(data: dict, schema: dict, path: str, errors: list[str]) -> None:
    for key, value in data.items():
        where = f"{path}{key}"
        if key not in schema:
            errors.append(f"{where}: unknown key")
            continue
        want = schema[key]
        if isinstance(want, dict):
            if not isinstance(value, dict):
                errors.append(f"{where}: expected a mapping")
            else:
                _check_types(value, want, where + ".", errors)
        elif isinstance(value, bool) and want is not bool and bool not in (want if isinstance(want, tuple) else ()):
            errors.append(f"{where}: expected {_tname(want)}, got a boolean")
        elif not isinstance(value, want):
            errors.append(f"{where}: expected {_tname(want)}, got {type(value).__name__}")


def _tname(t) -> str:
    names = {str: "a string", int: "an integer", float: "a number", list: "a list", bool: "true or false",
             type(None): "null", dict: "a mapping"}
    if isinstance(t, tuple):
        return " or ".join(names[x] for x in t)
    return names[t]


def parse_policy(text: str, source: str = "<string>") -> Policy:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError([f"invalid YAML: {e}".splitlines()[0]]) from e
    if not isinstance(data, dict):
        raise PolicyError(["policy must be a YAML mapping"])
    errors: list[str] = []
    for key in REQUIRED:
        if key not in data:
            errors.append(f"{key}: required")
    _check_types(data, SCHEMA, "", errors)
    if errors:
        raise PolicyError(errors)

    dev, risk, mfa = data.get("device", {}), data.get("risk", {}), data.get("mfa", {})
    su, hours, loc = data.get("step_up", {}), data.get("hours"), data.get("location", {})
    sess, ident = data.get("session", {}), data.get("identity", {})
    p = Policy(
        app=data["app"],
        name=data.get("name", data["app"]),
        sensitivity=data["sensitivity"],
        owner=data.get("owner", ""),
        description=data.get("description", ""),
        allow_groups=list(data["allow_groups"]),
        deny_groups=list(data.get("deny_groups", [])),
        min_trust=dev.get("min_trust", "low"),
        read_only_trust=dev.get("read_only_trust"),
        step_up_risk=risk.get("step_up_above", 30),
        deny_risk=risk.get("deny_above", 60),
        mfa_max_age=mfa.get("max_age_minutes", 720),
        step_up_actions=list(su.get("actions", [])),
        step_up_mfa_age=su.get("mfa_max_age_minutes", 15),
        hours=(hours["start"], hours["end"]) if hours else None,
        outside_hours=(hours or {}).get("outside", "step_up"),
        allowed_countries=list(loc["allowed_countries"]) if "allowed_countries" in loc else None,
        denied_countries=list(loc.get("denied_countries", [])),
        session_lifetime=sess.get("lifetime_minutes", 480),
        bind_to_device=sess.get("bind_to_device", True),
        require_active=ident.get("require_active", True),
        source=source,
    )
    errors = validate(p, hours)
    if errors:
        raise PolicyError(errors)
    return p


def validate(p: Policy, hours: dict | None = None) -> list[str]:
    e: list[str] = []
    if p.sensitivity not in SENSITIVITIES:
        e.append(f"sensitivity: must be one of {', '.join(SENSITIVITIES)}")
    if not p.allow_groups:
        e.append("allow_groups: at least one group is required (an empty list would deny everyone)")
    if any(not isinstance(g, str) for g in p.allow_groups + p.deny_groups):
        e.append("allow_groups and deny_groups must be lists of group names")
    for name, level in (("device.min_trust", p.min_trust), ("device.read_only_trust", p.read_only_trust)):
        if level is not None and level not in TRUST_LEVELS:
            e.append(f"{name}: must be one of {', '.join(TRUST_LEVELS)}")
    if (p.read_only_trust in TRUST_LEVELS and p.min_trust in TRUST_LEVELS
            and TRUST_LEVELS.index(p.read_only_trust) >= TRUST_LEVELS.index(p.min_trust)):
        e.append("device.read_only_trust: must be below device.min_trust")
    if not 0 <= p.step_up_risk <= 100 or not 0 <= p.deny_risk <= 100:
        e.append("risk: thresholds must be between 0 and 100")
    elif p.step_up_risk > p.deny_risk:
        e.append("risk.step_up_above: must not be greater than risk.deny_above")
    if p.mfa_max_age <= 0 or p.step_up_mfa_age <= 0:
        e.append("mfa ages must be positive")
    bad = [a for a in p.step_up_actions if a not in ACTIONS]
    if bad:
        e.append(f"step_up.actions: unknown action {bad[0]!r} (use {', '.join(ACTIONS)})")
    if p.hours is not None:
        s, t = p.hours
        if not (0 <= s < 24 and 0 < t <= 24) or s == t:
            e.append("hours: start and end must be hours of the day, 0 to 24, and differ")
        if p.outside_hours not in ("step_up", "deny"):
            e.append("hours.outside: must be step_up or deny")
    for c in (p.allowed_countries or []) + p.denied_countries:
        if not (isinstance(c, str) and len(c) == 2 and c.isupper()):
            e.append(f"location: {c!r} is not a two-letter country code")
    if p.session_lifetime <= 0 or p.session_lifetime > 24 * 60:
        e.append("session.lifetime_minutes: must be between 1 and 1440")
    return e


def load_policies(directory: Path, overlay: Path | None = None) -> dict[str, Policy]:
    out: dict[str, Policy] = {}
    errors: list[str] = []
    for d in [directory] + ([overlay] if overlay else []):
        for f in sorted(Path(d).glob("*.yaml")):
            try:
                p = parse_policy(f.read_text(), str(f))
            except PolicyError as e:
                errors.extend(f"{f.name}: {m}" for m in e.errors)
                continue
            out[p.app] = p
    if errors:
        raise PolicyError(errors)
    return out


# ---------------------------------------------------------------- evaluation


@dataclass
class Inputs:
    """Everything a decision depends on, frozen at request time so it can be replayed against a new policy."""

    user: str
    groups: list[str]
    user_active: bool
    user_status: str
    app: str
    action: str
    device: str
    device_trust: str
    device_detail: str
    risk: int
    risk_detail: str
    mfa_age: float | None  # minutes since the last MFA, None when there was none
    country: str
    city: str
    local_hour: float
    auth_failed: bool = False
    token_device: str | None = None
    stepped_up: bool = False
    ip: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class Decision:
    outcome: str
    restrictions: list[str]
    trace: list[dict]
    reasons: list[str]
    session_lifetime: int
    policy: str

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _hm(h: float) -> str:
    return f"{int(h) % 24:02d}:{int(round((h % 1) * 60)) % 60:02d}"


def evaluate(p: Policy, x: Inputs) -> Decision:
    trace: list[dict] = []

    def step(check: str, result: str, detail: str) -> None:
        trace.append({"check": check, "result": result, "detail": detail})

    if x.auth_failed:
        step("authentication", "deny", "password check failed at the identity provider")
        return Decision("deny", [], trace, ["authentication failed"], 0, p.app)
    step("authentication", "pass", "fresh sign-in" if x.token_device is None else "SSO session token verified")

    if x.token_device is not None and p.bind_to_device:
        if x.token_device != x.device:
            step("session_binding", "deny",
                 f"token was issued to device {x.token_device} but presented from {x.device}")
        else:
            step("session_binding", "pass", f"token bound to {x.device}")
    else:
        step("session_binding", "skip", "no session token yet" if x.token_device is None else "binding off in policy")

    if p.require_active and not x.user_active:
        step("identity_status", "deny", x.user_status)
    else:
        step("identity_status", "pass", x.user_status)

    denied = sorted(set(x.groups) & set(p.deny_groups))
    allowed = sorted(set(x.groups) & set(p.allow_groups))
    if denied:
        step("groups", "deny", f"member of denied group {denied[0]}")
    elif not allowed:
        step("groups", "deny", f"not in any allowed group ({', '.join(p.allow_groups)})")
    else:
        step("groups", "pass", f"member of {', '.join(allowed)}")

    tr = TRUST_LEVELS.index(x.device_trust)
    need = TRUST_LEVELS.index(p.min_trust)
    ro = TRUST_LEVELS.index(p.read_only_trust) if p.read_only_trust else None
    restrictions: list[str] = []
    if tr >= need:
        step("device_trust", "pass", f"device trust {x.device_trust} meets {p.min_trust}")
    elif ro is not None and tr >= ro:
        if x.action == "read":
            restrictions.append("read_only")
            step("device_trust", "restrict",
                 f"device trust {x.device_trust} is below {p.min_trust}: read-only ({x.device_detail})")
        else:
            step("device_trust", "deny",
                 f"device trust {x.device_trust} allows read-only, not {x.action} ({x.device_detail})")
    else:
        step("device_trust", "deny", f"device trust {x.device_trust} is below {p.min_trust} ({x.device_detail})")

    if x.risk > p.deny_risk:
        step("user_risk", "deny", f"risk {x.risk} is above {p.deny_risk}: {x.risk_detail}")
    elif x.risk > p.step_up_risk:
        if x.stepped_up:
            step("user_risk", "pass", f"risk {x.risk} is above {p.step_up_risk}, satisfied by step-up")
        else:
            step("user_risk", "step_up", f"risk {x.risk} is above {p.step_up_risk}: {x.risk_detail}")
    else:
        step("user_risk", "pass", f"risk {x.risk} is at or below {p.step_up_risk}")

    if x.mfa_age is None:
        step("mfa_freshness", "step_up", "no MFA on this session")
    elif x.mfa_age > p.mfa_max_age:
        step("mfa_freshness", "step_up", f"last MFA {x.mfa_age:.0f} min ago, policy allows {p.mfa_max_age}")
    else:
        step("mfa_freshness", "pass", f"last MFA {x.mfa_age:.0f} min ago (limit {p.mfa_max_age})")

    if x.action in p.step_up_actions:
        if x.mfa_age is not None and x.mfa_age <= p.step_up_mfa_age:
            step("sensitive_action", "pass", f"{x.action} with MFA {x.mfa_age:.0f} min old")
        else:
            step("sensitive_action", "step_up", f"{x.action} needs MFA in the last {p.step_up_mfa_age} min")
    else:
        step("sensitive_action", "skip", f"{x.action} is not a sensitive action here")

    if p.hours is None:
        step("time_of_day", "skip", "no hours condition")
    else:
        s, t = p.hours
        inside = s <= x.local_hour < t if s < t else (x.local_hour >= s or x.local_hour < t)
        window = f"{_hm(s)} to {_hm(t)} local"
        if inside:
            step("time_of_day", "pass", f"{_hm(x.local_hour)} is inside {window}")
        elif p.outside_hours == "step_up" and x.stepped_up:
            step("time_of_day", "pass", f"{_hm(x.local_hour)} is outside {window}, satisfied by step-up")
        else:
            step("time_of_day", p.outside_hours, f"{_hm(x.local_hour)} is outside {window}")

    if x.country in p.denied_countries:
        step("location", "deny", f"{x.city}, {x.country} is in a denied country")
    elif p.allowed_countries is not None and x.country not in p.allowed_countries:
        step("location", "deny", f"{x.city}, {x.country} is not in the allowed countries")
    else:
        step("location", "pass", f"{x.city}, {x.country}")

    results = [t["result"] for t in trace]
    if "deny" in results:
        outcome = "deny"
    elif "step_up" in results:
        outcome = "step_up"
    elif "restrict" in results:
        outcome = "allow_restricted"
    else:
        outcome = "allow"
    assert outcome in OUTCOMES
    worst = {"allow": (), "allow_restricted": ("restrict",), "step_up": ("step_up",), "deny": ("deny",)}[outcome]
    reasons = [f"{t['check']}: {t['detail']}" for t in trace if t["result"] in worst]
    return Decision(outcome, restrictions if outcome == "allow_restricted" else [], trace, reasons,
                    p.session_lifetime, p.app)
