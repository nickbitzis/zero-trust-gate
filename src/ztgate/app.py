"""Admin service and policy decision point (PDP).

The proxy calls POST /api/decide on every request. Everything else is the control plane: policies, the simulator,
policy diff, sessions, signals, the decision log, analytics, health, metrics, and the web UI.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from . import analytics
from .engine import Gate, Record
from .generator import generate
from .logs import get_logger, log_event
from .metrics import Metrics
from .model import Signal
from .policy import PolicyError, load_policies, parse_policy
from .posture import trust_of
from .simulate import SimError, simulate
from .tokens import TokenError, sign, signing_key, verify

STATIC = Path(__file__).parent / "static"
TOKEN_HOURS = 10


def policies_dir() -> Path:
    env = os.environ.get("ZTGATE_POLICIES")
    if env:
        return Path(env)
    for p in (Path.cwd() / "policies", Path(__file__).resolve().parents[2] / "policies"):
        if p.is_dir():
            return p
    raise SystemExit("policies directory not found; set ZTGATE_POLICIES")


class SimClock:
    """Service time starts where the 30-day log ends and moves with the wall clock. Demos can advance it."""

    def __init__(self, start: datetime):
        self.start, self.t0, self.offset = start, time.monotonic(), 0.0

    def now(self) -> datetime:
        return self.start + timedelta(seconds=time.monotonic() - self.t0 + self.offset)

    def advance(self, minutes: float) -> datetime:
        self.offset += minutes * 60
        return self.now()


def build_gate(seed: int = 7, policy_dir: Path | None = None) -> Gate:
    return Gate(generate(seed), load_policies(policy_dir or policies_dir()), seed=seed).replay()


def create_app(gate: Gate | None = None, key: bytes | None = None, clock: SimClock | None = None) -> FastAPI:
    app = FastAPI(title="Zero Trust Gate admin", version="1.0.0")
    log = get_logger()
    t0 = time.perf_counter()
    g = gate or build_gate()
    load_seconds = time.perf_counter() - t0
    key = key or signing_key()
    clock = clock or SimClock(g.data.as_of)
    metrics = Metrics("ztgate")
    challenges: dict[str, int] = {}
    cache: dict = {}
    lock = threading.Lock()
    app.state.gate, app.state.clock, app.state.key = g, clock, key
    log_event(log, "admin ready", users=len(g.data.users), apps=len(g.policies), decisions=len(g.records),
              load_seconds=round(load_seconds, 2))

    @app.middleware("http")
    async def observe(request: Request, call_next):
        t = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        metrics.observe_request(path, response.status_code, time.perf_counter() - t)
        return response

    def summary() -> dict:
        k = (len(g.records), len(g.revocations))
        with lock:
            if cache.get("k") != k:
                cache["k"], cache["v"] = k, analytics.summary(g)
            return cache["v"]

    def rec_or_404(rid: int) -> Record:
        if not 1 <= rid <= len(g.records):
            raise HTTPException(404, "no such decision")
        return g.records[rid - 1]

    # ------------------------------------------------------------ ops
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "decisions": len(g.records), "policies": len(g.policies),
                "now": clock.now().isoformat()}

    @app.get("/metrics", response_class=PlainTextResponse)
    def prom():
        s = summary()
        now = clock.now()
        metrics.set_gauge("ztgate_sessions_active", "Sessions active now.",
                          sum(1 for x in g.sessions.values() if x.state(now) == "active"))
        metrics.set_gauge("ztgate_sessions_revoked_total", "Sessions revoked.", len(g.revocations))
        metrics.set_gauge("ztgate_planted_events_caught", "Planted risky events denied or stepped up.",
                          s["planted_caught"])
        metrics.set_gauge("ztgate_false_deny_rate", "Denied share of legitimate, entitled requests.",
                          s["friction"]["false_deny_rate"])
        metrics.set_gauge("ztgate_decisions_logged", "Decisions in the log.", len(g.records))
        return metrics.render()

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    # ------------------------------------------------------------ directory
    @app.get("/api/summary")
    def api_summary():
        s = summary()
        return {k: v for k, v in s.items() if k not in ("by_app", "daily", "least_privilege")}

    @app.get("/api/analytics")
    def api_analytics():
        return summary()

    @app.get("/api/apps")
    def apps():
        return [{**a.__dict__, "policy_groups": g.policies[a.id].allow_groups} for a in g.data.apps.values()]

    @app.get("/api/users")
    def users(q: str = "", limit: Annotated[int, Query(ge=1, le=1000)] = 50):
        ql = q.lower()
        items = [u for u in g.data.users.values()
                 if not ql or ql in u.id or ql in u.name.lower() or ql in u.email or ql in u.department]
        return {"total": len(items), "items": [u.to_dict() for u in items[:limit]]}

    @app.get("/api/users/{uid}")
    def user(uid: str):
        u = g.data.users.get(uid)
        if not u:
            raise HTTPException(404, "no such user")
        devs = [{**d.to_dict(), "trust": trust_of(d).to_dict()} for d in g.data.devices_of(uid)]
        return {**u.to_dict(), "devices": devs, "status": g.user_status(uid, clock.now())[1]}

    # ------------------------------------------------------------ policies
    @app.get("/api/policies")
    def policies():
        return [p.to_dict() for p in g.policies.values()]

    @app.get("/api/policies/{app_id}")
    def policy(app_id: str):
        p = g.policies.get(app_id)
        if not p:
            raise HTTPException(404, "no such policy")
        text = Path(p.source).read_text() if p.source and Path(p.source).exists() else ""
        return {**p.to_dict(), "yaml": text}

    @app.post("/api/policies/validate")
    def validate(body: Annotated[dict, Body()]):
        try:
            p = parse_policy(body.get("yaml", ""), "draft")
        except PolicyError as e:
            return {"valid": False, "errors": e.errors}
        return {"valid": True, "errors": [], "policy": p.to_dict()}

    @app.post("/api/simulate")
    def api_simulate(body: Annotated[dict, Body()]):
        try:
            out = simulate(g, body)
        except PolicyError as e:
            raise HTTPException(422, "; ".join(e.errors)) from e
        except SimError as e:
            raise HTTPException(422, str(e)) from e
        metrics.action("simulate", out["decision"])
        return out

    @app.post("/api/diff")
    def api_diff(body: Annotated[dict, Body()]):
        try:
            p = parse_policy(body.get("yaml", ""), "draft")
        except PolicyError as e:
            raise HTTPException(422, "; ".join(e.errors)) from e
        if p.app not in g.policies:
            raise HTTPException(422, f"no current policy for app {p.app!r}")
        out = analytics.diff(g, p, sample=int(body.get("sample", 50)))
        metrics.action("diff", "planted_exposed" if out["planted_newly_allowed"] else "ok")
        return out

    # ------------------------------------------------------------ decision log
    @app.get("/api/decisions")
    def decisions(
        app_id: Annotated[str, Query(alias="app")] = "",
        outcome: str = "",
        final: str = "",
        user: str = "",
        planted: str = "",
        legit: str = "",
        source: str = "",
        q: str = "",
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ):
        ql = q.lower()
        out = []
        for r in reversed(g.records):
            if app_id and r.app != app_id or outcome and r.outcome != outcome or final and r.final != final:
                continue
            if user and r.user != user or source and r.source != source:
                continue
            if planted == "any" and not r.planted or planted and planted != "any" and r.planted != planted:
                continue
            if legit == "false_deny" and not (r.legit and r.entitled and r.final == "deny"
                                               and not r.inputs.auth_failed):
                continue
            if ql and not (ql in r.user or ql in r.ip or ql in r.device or any(ql in x.lower() for x in r.reasons)):
                continue
            out.append(r)
        page = out[offset:offset + limit]
        return {"total": len(out), "items": [r.to_dict() for r in page]}

    @app.get("/api/decisions/{rid}")
    def decision(rid: int):
        r = rec_or_404(rid)
        u = g.data.users.get(r.user)
        return {**r.to_dict(trace=g.trace(r)), "user_name": u.name if u else None}

    # ------------------------------------------------------------ sessions and signals
    @app.get("/api/sessions")
    def sessions(status: str = "active", user: str = "", limit: Annotated[int, Query(ge=1, le=1000)] = 200):
        now = clock.now()
        items = [s for s in reversed(list(g.sessions.values()))
                 if (not status or s.state(now) == status) and (not user or s.user == user)]
        if status == "revoked":
            items.sort(key=lambda s: s.revoked_at, reverse=True)
        return {"total": len(items), "now": now.isoformat(), "items": [s.to_dict(now) for s in items[:limit]]}

    @app.post("/api/sessions/{sid}/revoke")
    def revoke(sid: str, body: Annotated[dict | None, Body()] = None):
        if sid not in g.sessions:
            raise HTTPException(404, "no such session")
        s = g.revoke(sid, clock.now(), (body or {}).get("reason") or "revoked by an administrator")
        metrics.action("revoke", "admin")
        log_event(log, "session revoked", session=sid, user=s.user, app=s.app, reason=s.revoke_reason)
        return s.to_dict(clock.now())

    @app.post("/api/signals")
    def signals(body: Annotated[dict, Body()]):
        try:
            sig = Signal(clock.now(), body["kind"], body["target"], dict(body.get("changes") or {}),
                         body.get("reason") or body["kind"].replace("_", " "))
            revs = g.apply_signal(sig)
        except KeyError as e:
            raise HTTPException(422, f"missing or unknown {e}") from e
        except ValueError as e:
            raise HTTPException(422, str(e)) from e
        for r in revs:
            metrics.action("revoke", sig.kind)
            log_event(log, "session revoked", session=r.session, user=r.user, app=r.app, reason=r.reason)
        return {"revoked": [r.__dict__ | {"ts": r.ts.isoformat()} for r in revs]}

    # ------------------------------------------------------------ live sign-in, step-up, and the PDP
    def issue(user: str, device: str) -> str:
        now = clock.now()
        return sign({"sub": user, "dev": device, "iat": now.timestamp(), "exp": (now + timedelta(hours=TOKEN_HOURS))
                     .timestamp(), "jti": secrets.token_hex(8)}, key)

    def respond(r: Record, token: str | None = None) -> dict:
        out = {"decision": r.outcome if r.final == "step_up" else r.final, "decision_id": r.id, "reasons": r.reasons,
               "restrictions": r.restrictions, "risk": r.risk["score"], "device_trust": r.inputs.device_trust}
        if r.final == "step_up":
            cid = secrets.token_urlsafe(12)
            challenges[cid] = r.id
            out["challenge"] = cid
        if token:
            out["token"] = token
        if r.final in ("allow", "allow_restricted"):
            u = g.data.users[r.user]
            out["headers"] = {
                "X-ZT-User": u.email, "X-ZT-User-Id": u.id, "X-ZT-Groups": ",".join(u.groups),
                "X-ZT-Device-Trust": r.inputs.device_trust, "X-ZT-Restrictions": ",".join(r.restrictions),
                "X-ZT-Decision-Id": str(r.id),
                # Short-lived and on the wall clock, because the backend checks it with its own clock.
                "X-ZT-Assertion": sign({"sub": u.id, "email": u.email, "app": r.app, "dec": r.id,
                                        "exp": time.time() + 60}, key, purpose="assertion"),
            }
        metrics.action(f"decide:{r.app}", out["decision"])
        log_event(log, "decision", id=r.id, user=r.user, app=r.app, action=r.action, device=r.device, ip=r.ip,
                  outcome=r.outcome, final=r.final, risk=r.risk["score"], reasons=r.reasons[:2])
        return out

    @app.post("/api/login")
    def login(body: Annotated[dict, Body()]):
        """Stand-in for the identity provider: password and MFA succeed, then the first app is checked."""
        try:
            r = g.decide(user=body["user"], app=body.get("app", "wiki"), action="read", device=body["device"],
                         ip=body.get("ip", ""), ts=clock.now(), fresh_auth=True,
                         password_ok=body.get("password_ok", True), stepup_capable=None, source="live")
        except KeyError as e:
            raise HTTPException(422, f"missing or unknown {e}") from e
        token = issue(r.user, r.device) if r.final in ("allow", "allow_restricted") else None
        return respond(r, token)

    @app.post("/api/stepup")
    def stepup(body: Annotated[dict, Body()]):
        rid = challenges.pop(body.get("challenge", ""), None)
        if rid is None:
            raise HTTPException(404, "unknown or used challenge")
        r = g.complete_stepup(g.records[rid - 1], bool(body.get("passed", True)), clock.now())
        fresh = r.final != "deny" and r.inputs.token_device is None  # a sign-in that needed step-up gets its token now
        token = issue(r.user, r.device) if fresh else None
        return respond(r, token)

    @app.post("/api/decide")
    def decide(body: Annotated[dict, Body()]):
        now = clock.now()
        try:
            claims = verify(body.get("token", ""), key, now.timestamp())
        except TokenError as e:
            metrics.action("decide", "bad_token")
            return JSONResponse({"decision": "deny", "reasons": [f"session token: {e}"], "status": 401},
                                status_code=200)
        app_id = body.get("app", "")
        if app_id not in g.policies:
            raise HTTPException(404, "no such app")
        bound = claims["dev"]
        sid = g.open.get((claims["sub"], bound, app_id))
        s = g.sessions.get(sid) if sid else None
        if s and s.status == "revoked" and s.revoked_at and s.revoked_at.timestamp() >= claims["iat"]:
            metrics.action("decide", "revoked")
            return {"decision": "deny", "reasons": [f"session revoked: {s.revoke_reason}"], "status": 401}
        r = g.decide(user=claims["sub"], app=app_id, action=body.get("action", "read"),
                     device=body.get("device") or "unregistered", ip=body.get("ip", ""), ts=now,
                     token_device=bound, stepup_capable=None, source="live")
        return respond(r)

    @app.post("/api/clock/advance")
    def advance(body: Annotated[dict, Body()]):
        if os.environ.get("ZTGATE_DEMO_CLOCK", "1") != "1":
            raise HTTPException(403, "clock control is off")
        return {"now": clock.advance(float(body.get("minutes", 0))).isoformat()}

    return app
