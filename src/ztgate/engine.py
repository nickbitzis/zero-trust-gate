"""The gate: builds decision inputs from identity, device, and risk, evaluates policy, runs the step-up flow, keeps
sessions, and re-checks open sessions when a posture or risk signal arrives (continuous evaluation).

The same code path serves the 30-day log replay and live proxy requests.
"""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .generator import Dataset
from .geo import CITY_BY_NAME
from .model import Attempt, Signal
from .policy import Decision, Inputs, Policy, evaluate
from .posture import trust_cached
from .risk import RiskEngine, context_for

STEPUP_PASS_RATE = 0.97  # a real person sometimes misses the push; replays use a seeded draw


@dataclass(slots=True)
class Record:
    id: int
    ts: datetime
    user: str
    app: str
    action: str
    device: str
    ip: str
    outcome: str  # first decision
    final: str  # after the step-up flow: allow, allow_restricted, or deny
    stepup: str | None  # passed | failed | None
    reasons: list[str]
    restrictions: list[str]
    risk: dict
    inputs: Inputs
    planted: str | None
    source: str  # log | live
    session: str | None = None
    entitled: bool = True

    @property
    def legit(self) -> bool:
        return self.planted is None and not self.device.startswith("x-")

    def to_dict(self, trace: list[dict] | None = None) -> dict:
        d = {
            "id": self.id, "ts": self.ts.isoformat(), "user": self.user, "app": self.app, "action": self.action,
            "device": self.device, "ip": self.ip, "city": self.inputs.city, "country": self.inputs.country,
            "outcome": self.outcome, "final": self.final, "stepup": self.stepup, "reasons": self.reasons,
            "restrictions": self.restrictions, "risk": self.risk, "device_trust": self.inputs.device_trust,
            "planted": self.planted, "source": self.source, "session": self.session, "legit": self.legit,
            "entitled": self.entitled,
        }
        if trace is not None:
            d["trace"] = trace
            d["inputs"] = self.inputs.to_dict()
        return d


@dataclass
class Session:
    id: str
    user: str
    device: str
    app: str
    ip: str
    issued: datetime
    expires: datetime
    restrictions: list[str]
    status: str = "active"  # active | revoked
    revoked_at: datetime | None = None
    revoke_reason: str | None = None
    planted: str | None = None
    source: str = "log"
    last_seen: datetime | None = None
    requests: int = 0

    def state(self, now: datetime) -> str:
        if self.status == "revoked":
            return "revoked"
        return "active" if now < self.expires else "expired"

    def to_dict(self, now: datetime) -> dict:
        return {
            "id": self.id, "user": self.user, "device": self.device, "app": self.app, "ip": self.ip,
            "issued": self.issued.isoformat(), "expires": self.expires.isoformat(), "restrictions": self.restrictions,
            "status": self.state(now), "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoke_reason": self.revoke_reason, "planted": self.planted, "source": self.source,
            "requests": self.requests,
        }


@dataclass
class Revocation:
    ts: datetime
    session: str
    user: str
    app: str
    reason: str
    signal: str
    planted: str | None


@dataclass
class Gate:
    data: Dataset
    policies: dict[str, Policy]
    seed: int = 7
    risk: RiskEngine = field(init=False)
    records: list[Record] = field(default_factory=list)
    sessions: dict[str, Session] = field(default_factory=dict)
    revocations: list[Revocation] = field(default_factory=list)

    def __post_init__(self):
        self.risk = RiskEngine(self.data.threat_intel)
        for u in self.data.users.values():
            self.risk.seed(u.id, [d.id for d in self.data.devices_of(u.id)], CITY_BY_NAME[u.city].country)
        self.last_mfa: dict[tuple[str, str], datetime] = {}
        self.open: dict[tuple[str, str, str], str] = {}  # (user, device, app) -> session id
        self.rng = random.Random(self.seed)
        self.lock = threading.RLock()

    # ----------------------------------------------------------- inputs
    def user_status(self, user: str, ts: datetime) -> tuple[bool, str]:
        u = self.data.users.get(user)
        if u is None:
            return False, "unknown user"
        if u.disabled:
            return False, "account disabled"
        if u.contract_end and ts >= u.contract_end:
            days = (ts - u.contract_end).days
            return False, f"contract ended {u.contract_end.date()} ({days} days ago)"
        if u.kind == "contractor":
            return True, f"active contractor until {u.contract_end.date() if u.contract_end else 'n/a'}"
        return True, "active employee"

    def inputs(self, user: str, app: str, action: str, device: str, ip: str, ts: datetime, *,
               token_device: str | None = None, mfa_age: float | None = None, auth_failed: bool = False,
               stepped_up: bool = False) -> tuple[Inputs, dict]:
        dev = self.data.devices.get(device)
        trust = trust_cached(dev)
        failed = [s["detail"] for s in trust.signals if not s["ok"]]
        risk = self.risk.score(user, device, dev.owner if dev else None, ip, ts)
        ctx = context_for(ip, ts)
        active, status = self.user_status(user, ts)
        u = self.data.users.get(user)
        x = Inputs(
            user=user, groups=list(u.groups) if u else [], user_active=active, user_status=status, app=app,
            action=action, device=device, device_trust=trust.level,
            device_detail="; ".join(failed) if failed else "all posture checks pass",
            risk=risk.score, risk_detail="; ".join(c["detail"] for c in risk.components) or "no risk signals",
            mfa_age=mfa_age, country=ctx.city.country, city=ctx.city.name, local_hour=round(ctx.local_hour, 2),
            auth_failed=auth_failed, token_device=token_device, stepped_up=stepped_up, ip=ip,
        )
        return x, risk.to_dict()

    def mfa_age(self, user: str, device: str, ts: datetime) -> float | None:
        t = self.last_mfa.get((user, device))
        return None if t is None else max(0.0, (ts - t).total_seconds() / 60)

    # ----------------------------------------------------------- decisions
    def policy(self, app: str) -> Policy:
        return self.policies[app]

    def decide(self, *, user: str, app: str, action: str, device: str, ip: str, ts: datetime,
               fresh_auth: bool = False, password_ok: bool = True, token_device: str | None = None,
               stepup_capable: bool | None = None, planted: str | None = None, source: str = "log") -> Record:
        """Evaluate one request. `stepup_capable=None` leaves a step-up pending (live requests answer it later)."""
        with self.lock:
            p = self.policies.get(app)
            if p is None:
                raise KeyError(app)
            if fresh_auth and not password_ok:
                x, risk = self.inputs(user, app, action, device, ip, ts, auth_failed=True)
                self.risk.record_failure(user, ip, ts)
                d = evaluate(p, x)
                return self._log(ts, x, d, risk, "deny", None, planted, source)
            if fresh_auth:
                self.last_mfa[(user, device)] = ts
                mfa = 0.0
            else:
                mfa = self.mfa_age(user, token_device or device, ts)
            x, risk = self.inputs(user, app, action, device, ip, ts, token_device=None if fresh_auth else
                                  (token_device or device), mfa_age=mfa)
            d = evaluate(p, x)
            final, stepup = d.outcome, None
            if d.outcome == "step_up":
                if stepup_capable is None:
                    final = "step_up"
                else:
                    ok = stepup_capable and self.rng.random() < STEPUP_PASS_RATE
                    stepup = "passed" if ok else "failed"
                    if ok:
                        final = self._after_stepup(x, ts)
                    else:
                        final = "deny"
            rec = self._log(ts, x, d, risk, final, stepup, planted, source)
            if final in ("allow", "allow_restricted"):
                self._grant(rec, p, ts)
            return rec

    def _after_stepup(self, x: Inputs, ts: datetime) -> str:
        self.last_mfa[(x.user, x.token_device or x.device)] = ts
        self.last_mfa[(x.user, x.device)] = ts
        x2 = Inputs(**{**x.to_dict(), "mfa_age": 0.0, "stepped_up": True})
        return evaluate(self.policies[x.app], x2).outcome

    def complete_stepup(self, rec: Record, passed: bool, ts: datetime) -> Record:
        """Answer a pending live step-up challenge."""
        with self.lock:
            rec.stepup = "passed" if passed else "failed"
            rec.final = self._after_stepup(rec.inputs, ts) if passed else "deny"
            if rec.final in ("allow", "allow_restricted"):
                self._grant(rec, self.policies[rec.app], ts)
            return rec

    def _log(self, ts, x: Inputs, d: Decision, risk: dict, final: str, stepup, planted, source) -> Record:
        p = self.policies[x.app]
        rec = Record(len(self.records) + 1, ts, x.user, x.app, x.action, x.device, x.ip, d.outcome, final, stepup,
                     d.reasons, d.restrictions, risk, x, planted, source,
                     entitled=bool(set(x.groups) & set(p.allow_groups)))
        self.records.append(rec)
        if final in ("allow", "allow_restricted") and not x.auth_failed:
            self.risk.record_success(x.user, x.device, rec.ip, ts)
        return rec

    def _grant(self, rec: Record, p: Policy, ts: datetime) -> None:
        key = (rec.user, rec.device, rec.app)
        sid = self.open.get(key)
        s = self.sessions.get(sid) if sid else None
        if s is None or s.state(ts) != "active":
            sid = f"s{len(self.sessions) + 1:06d}"
            s = Session(sid, rec.user, rec.device, rec.app, rec.ip, ts, ts + timedelta(minutes=p.session_lifetime),
                        list(rec.restrictions), planted=rec.planted, source=rec.source)
            self.sessions[sid] = s
            self.open[key] = sid
        s.last_seen, s.requests, s.ip = ts, s.requests + 1, rec.ip
        s.restrictions = list(rec.restrictions)
        rec.session = sid

    def trace(self, rec: Record) -> list[dict]:
        p = self.policies.get(rec.app)
        return evaluate(p, rec.inputs).trace if p else []

    # ----------------------------------------------------------- continuous evaluation
    def apply_signal(self, sig: Signal) -> list[Revocation]:
        with self.lock:
            if sig.kind == "device_posture":
                dev = self.data.devices.get(sig.target)
                if dev is None:
                    raise KeyError(sig.target)
                for k, v in sig.changes.items():
                    if not hasattr(dev, k):
                        raise ValueError(f"unknown posture field {k}")
                    setattr(dev, k, v)
                affected = [s for s in self.sessions.values() if s.device == sig.target and s.state(sig.ts) == "active"]
            elif sig.kind == "user_risk":
                c = sig.changes
                self.risk.add_event(sig.target, sig.ts, int(c.get("points", 40)), c.get("reason", sig.reason),
                                    float(c.get("hours", 24)))
                affected = [s for s in self.sessions.values() if s.user == sig.target and s.state(sig.ts) == "active"]
            else:
                raise ValueError(f"unknown signal kind {sig.kind}")
            out = []
            for s in affected:
                x, _ = self.inputs(s.user, s.app, "read", s.device, s.ip, sig.ts, token_device=s.device,
                                   mfa_age=self.mfa_age(s.user, s.device, sig.ts))
                d = evaluate(self.policies[s.app], x)
                if d.outcome in ("deny", "step_up"):
                    s.status, s.revoked_at = "revoked", sig.ts
                    s.revoke_reason = f"{sig.reason}: " + (d.reasons[0] if d.reasons else d.outcome)
                    r = Revocation(sig.ts, s.id, s.user, s.app, s.revoke_reason, sig.kind, sig.planted)
                    self.revocations.append(r)
                    out.append(r)
            return out

    def revoke(self, sid: str, ts: datetime, reason: str = "revoked by an administrator") -> Session:
        with self.lock:
            s = self.sessions[sid]
            if s.status != "revoked":
                s.status, s.revoked_at, s.revoke_reason = "revoked", ts, reason
                self.revocations.append(Revocation(ts, sid, s.user, s.app, reason, "admin", None))
            return s

    # ----------------------------------------------------------- replay
    def replay(self) -> Gate:
        events: list[tuple[datetime, int, object]] = [(a.ts, 1, a) for a in self.data.attempts]
        events += [(s.ts, 0, s) for s in self.data.signals]
        events.sort(key=lambda e: (e[0], e[1]))
        for _, _, ev in events:
            if isinstance(ev, Signal):
                self.apply_signal(ev)
            else:
                self.run_attempt(ev)
        return self

    def run_attempt(self, a: Attempt) -> Record:
        return self.decide(user=a.user, app=a.app, action=a.action, device=a.device, ip=a.ip, ts=a.ts,
                           fresh_auth=a.fresh_auth, password_ok=a.password_ok, token_device=a.token_device,
                           stepup_capable=a.stepup_capable, planted=a.planted)
