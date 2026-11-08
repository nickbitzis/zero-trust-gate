from datetime import timedelta

import pytest
from conftest import POLICIES

from ztgate.engine import Gate
from ztgate.generator import generate
from ztgate.geo import office_ip
from ztgate.model import Signal
from ztgate.policy import load_policies
from ztgate.tokens import TokenError, sign, verify

KEY = b"k" * 32


@pytest.fixture
def g():
    """A gate with the synthetic org but no replayed history."""
    return Gate(generate(7), load_policies(POLICIES))


def payroll_admin(g):
    for u in sorted(g.data.users.values(), key=lambda u: u.id):
        if "payroll-admins" in u.groups and u.city == "San Francisco":
            d = g.data.devices[f"lt-{u.id}"]
            d.patch_age_days, d.edr_running, d.os_supported = 3, True, True
            return u
    raise AssertionError


def noon(g, u):
    return g.data.as_of.replace(hour=20, minute=0)  # 12:00 in San Francisco


# ---------------------------------------------------------------- step-up flow and sessions


def test_sign_in_creates_a_session_with_policy_lifetime(g):
    u = payroll_admin(g)
    t = noon(g, u)
    r = g.decide(user=u.id, app="payroll", action="read", device=f"lt-{u.id}", ip=office_ip(u.city), ts=t,
                 fresh_auth=True)
    assert r.final == "allow" and r.session
    s = g.sessions[r.session]
    assert s.expires - s.issued == timedelta(minutes=60)
    again = g.decide(user=u.id, app="payroll", action="read", device=f"lt-{u.id}", ip=office_ip(u.city),
                     ts=t + timedelta(minutes=5), token_device=f"lt-{u.id}")
    assert again.session == r.session and s.requests == 2


def test_step_up_passed_then_allows_and_refreshes_mfa(g):
    u = payroll_admin(g)
    t = noon(g, u)
    lt, ip = f"lt-{u.id}", office_ip(u.city)
    g.decide(user=u.id, app="payroll", action="read", device=lt, ip=ip, ts=t, fresh_auth=True)
    r = g.decide(user=u.id, app="payroll", action="write", device=lt, ip=ip, ts=t + timedelta(minutes=30),
                 token_device=lt, stepup_capable=None)
    assert r.outcome == "step_up" and r.final == "step_up"
    g.complete_stepup(r, True, t + timedelta(minutes=31))
    assert r.final == "allow" and r.stepup == "passed"
    nxt = g.decide(user=u.id, app="payroll", action="write", device=lt, ip=ip, ts=t + timedelta(minutes=33),
                   token_device=lt)
    assert nxt.outcome == "allow"


def test_step_up_failed_is_a_deny(g):
    u = payroll_admin(g)
    t = noon(g, u)
    lt = f"lt-{u.id}"
    g.decide(user=u.id, app="payroll", action="read", device=lt, ip=office_ip(u.city), ts=t, fresh_auth=True)
    r = g.decide(user=u.id, app="payroll", action="write", device=lt, ip=office_ip(u.city),
                 ts=t + timedelta(minutes=30), token_device=lt, stepup_capable=False)
    assert r.outcome == "step_up" and r.final == "deny" and r.stepup == "failed"
    assert r.session is None


def test_failed_password_feeds_risk(g):
    u = payroll_admin(g)
    t = noon(g, u)
    for k in range(4):
        g.decide(user=u.id, app="wiki", action="read", device=f"lt-{u.id}", ip=office_ip(u.city),
                 ts=t + timedelta(seconds=k), fresh_auth=True, password_ok=False)
    r = g.decide(user=u.id, app="payroll", action="read", device=f"lt-{u.id}", ip=office_ip(u.city),
                 ts=t + timedelta(minutes=1), fresh_auth=True, stepup_capable=None)
    assert r.risk["score"] == 24 and r.outcome == "step_up"


# ---------------------------------------------------------------- continuous evaluation


def test_posture_signal_revokes_only_sessions_that_now_fail(g):
    u = payroll_admin(g)
    t = noon(g, u)
    lt, ip = f"lt-{u.id}", office_ip(u.city)
    pay = g.decide(user=u.id, app="payroll", action="read", device=lt, ip=ip, ts=t, fresh_auth=True)
    wiki = g.decide(user=u.id, app="wiki", action="read", device=lt, ip=ip, ts=t + timedelta(minutes=1),
                    token_device=lt)
    revs = g.apply_signal(Signal(t + timedelta(minutes=10), "device_posture", lt, {"edr_running": False}, "EDR off"))
    assert [r.session for r in revs] == [pay.session]
    assert g.sessions[pay.session].status == "revoked"
    assert g.sessions[wiki.session].state(t + timedelta(minutes=11)) == "active"  # wiki accepts low trust
    assert "EDR agent not running" in revs[0].reason


def test_risk_signal_revokes_sessions(g):
    u = payroll_admin(g)
    t = noon(g, u)
    lt = f"lt-{u.id}"
    pay = g.decide(user=u.id, app="payroll", action="read", device=lt, ip=office_ip(u.city), ts=t, fresh_auth=True)
    revs = g.apply_signal(Signal(t + timedelta(minutes=5), "user_risk", u.id, {"points": 45, "reason": "MFA fatigue"},
                                 "risk spike"))
    assert pay.session in [r.session for r in revs]


def test_expired_sessions_are_not_rechecked(g):
    u = payroll_admin(g)
    t = noon(g, u)
    lt = f"lt-{u.id}"
    g.decide(user=u.id, app="payroll", action="read", device=lt, ip=office_ip(u.city), ts=t, fresh_auth=True)
    assert g.apply_signal(Signal(t + timedelta(hours=2), "device_posture", lt, {"edr_running": False}, "x")) == []


def test_bad_signals_are_rejected(g):
    with pytest.raises(KeyError):
        g.apply_signal(Signal(g.data.as_of, "device_posture", "nope", {}, "x"))
    with pytest.raises(ValueError):
        g.apply_signal(Signal(g.data.as_of, "device_posture", "lt-u0001", {"color": "red"}, "x"))
    with pytest.raises(ValueError):
        g.apply_signal(Signal(g.data.as_of, "weather", "u0001", {}, "x"))


# ---------------------------------------------------------------- tokens


def test_token_round_trip():
    tok = sign({"sub": "u1", "dev": "lt-u1", "exp": 200}, KEY)
    assert verify(tok, KEY, now=100)["sub"] == "u1"


def test_expired_token():
    tok = sign({"sub": "u1", "exp": 200}, KEY)
    with pytest.raises(TokenError, match="expired"):
        verify(tok, KEY, now=200)


@pytest.mark.parametrize("mutate", ["payload", "signature", "truncate"])
def test_tampered_token_fails(mutate):
    tok = sign({"sub": "u1", "exp": 200}, KEY)
    body, sig = tok.split(".")
    if mutate == "payload":
        forged = sign({"sub": "u0001-admin", "exp": 200}, b"other-key").split(".")[0]
        bad = f"{forged}.{sig}"
    elif mutate == "signature":
        bad = f"{body}.{sig[:-2]}{'AA' if sig[-2:] != 'AA' else 'BB'}"
    else:
        bad = body
    with pytest.raises(TokenError):
        verify(bad, KEY, now=100)


def test_wrong_key_and_wrong_purpose():
    tok = sign({"sub": "u1"}, KEY)
    with pytest.raises(TokenError, match="bad signature"):
        verify(tok, b"x" * 32, now=0)
    with pytest.raises(TokenError):
        verify(tok, KEY, now=0, purpose="assertion")
