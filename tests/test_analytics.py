from collections import Counter

import yaml
from conftest import POLICIES, ROOT

from ztgate import analytics
from ztgate.generator import generate
from ztgate.policy import parse_policy

PLANTED_KINDS = {"impossible_travel", "stolen_session", "contractor_after_end", "unpatched_device", "unusual_hours",
                 "credential_stuffing", "posture_drift", "risk_spike"}


def test_synthetic_org_shape(gate):
    d = gate.data
    assert len(d.users) == 800 and len(d.apps) == 30
    assert Counter(u.kind for u in d.users.values())["contractor"] == 72
    assert 40_000 < len(d.attempts) < 70_000
    assert {p.kind for p in d.planted.values()} == PLANTED_KINDS


def test_generation_is_deterministic():
    a, b = generate(7), generate(7)
    assert [(x.ts, x.user, x.app) for x in a.attempts[:500]] == [(x.ts, x.user, x.app) for x in b.attempts[:500]]
    assert generate(8).attempts[0].user != a.attempts[0].user or len(generate(8).attempts) != len(a.attempts)


def test_every_planted_event_is_caught(summary):
    missed = [p["id"] for p in summary["planted"] if not p["caught"]]
    assert missed == []
    assert summary["gate"]["pass"]


def test_planted_events_are_caught_by_the_intended_control(summary):
    by = {p["kind"]: set() for p in summary["planted"]}
    for p in summary["planted"]:
        by[p["kind"]].update(p["caught_by"])
    assert "user_risk" in by["impossible_travel"]
    assert "session_binding" in by["stolen_session"]
    assert "identity_status" in by["contractor_after_end"]
    assert "device_trust" in by["unpatched_device"]
    assert "time_of_day" in by["unusual_hours"]
    assert "user_risk" in by["credential_stuffing"]
    assert by["posture_drift"] == {"continuous evaluation"} and by["risk_spike"] == {"continuous evaluation"}


def test_stuffing_success_requests_show_ip_velocity(gate):
    recs = [r for r in gate.records if r.planted == "P11" and not r.inputs.auth_failed]
    assert len(recs) == 3
    assert all("failed sign-ins for" in r.inputs.risk_detail for r in recs)


def test_friction_is_low_and_explained(summary):
    f = summary["friction"]
    assert f["legit_requests"] > 40_000
    assert f["false_deny_rate"] < 0.02
    assert 0 < f["step_up_rate"] < 0.05
    assert f["step_up_passed"] / f["step_ups"] > 0.9
    assert sum(f["false_deny_by_check"].values()) == f["false_denies"]


def test_by_app_counts_add_up(summary, gate):
    rows = summary["by_app"]
    assert len(rows) == 30
    assert sum(r["total"] for r in rows) == len(gate.records)
    for r in rows:
        assert r["allow"] + r["allow_restricted"] + r["step_up"] + r["deny"] == r["total"]


def test_least_privilege_finds_planted_over_grants(summary):
    recs = {(r["group"], r["app"]) for r in summary["least_privilege"]}
    assert {("product", "source-code"), ("sales-managers", "finance-reports"),
            ("contractors-eng", "data-warehouse")} <= recs
    # Groups that use their access are never flagged.
    assert ("payroll-admins", "payroll") not in recs and ("engineering", "source-code") not in recs


def test_diff_no_change_is_empty(gate):
    p = parse_policy((POLICIES / "payroll.yaml").read_text())
    d = analytics.diff(gate, p)
    assert d["changed"] == 0 and d["requests"] > 0


def test_diff_loosened_policy_exposes_planted_event(gate):
    p = parse_policy((ROOT / "examples/policies-weak/payroll.yaml").read_text())
    d = analytics.diff(gate, p)
    assert d["counts"]["newly_allowed"] > 0
    assert "P9" in d["planted_newly_allowed"]
    assert all(t["after"] in ("allow", "allow_restricted") for t in d["transitions"])


def test_diff_tightened_policy_lists_newly_denied(gate):
    data = yaml.safe_load((POLICIES / "crm.yaml").read_text())
    data["allow_groups"] = ["sales"]
    d = analytics.diff(gate, parse_policy(yaml.safe_dump(data)))
    assert d["counts"]["newly_denied"] > 100
    assert all(s["after"] == "deny" for s in d["samples"]["newly_denied"])
    assert d["planted_newly_allowed"] == []


def test_gate_fails_on_weak_overlay(gate):
    from ztgate.engine import Gate
    from ztgate.policy import load_policies

    weak = Gate(generate(7), load_policies(POLICIES, ROOT / "examples/policies-weak")).replay()
    res = analytics.summary(weak)["gate"]
    assert not res["pass"] and set(res["missed"]) == {"P5", "P9"}
