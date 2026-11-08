import pytest
from helpers import BASE, inputs, policy, result

from ztgate.policy import PolicyError, evaluate, load_policies, parse_policy

# ---------------------------------------------------------------- parsing and validation


def test_repo_policies_load_and_cover_every_app(gate):
    assert len(gate.policies) == 30
    assert set(gate.policies) == set(gate.data.apps)


def test_defaults_fill_in():
    p = parse_policy("app: wiki\nsensitivity: low\nallow_groups: [all-employees]\n")
    assert p.min_trust == "low" and p.read_only_trust is None
    assert p.bind_to_device and p.require_active
    assert p.hours is None and p.allowed_countries is None


@pytest.mark.parametrize(
    "text, message",
    [
        ("app: x\nsensitivity: low\n", "allow_groups: required"),
        ("app: x\nsensitivity: secret\nallow_groups: [a]\n", "sensitivity: must be one of"),
        ("app: x\nsensitivity: low\nallow_groups: []\n", "at least one group"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\ncolor: blue\n", "color: unknown key"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\ndevice: {min_trust: ultra}\n", "device.min_trust"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nrisk: {step_up_above: 70, deny_above: 40}\n", "step_up_above"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nrisk: {deny_above: '50'}\n", "expected an integer"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nhours: {start: 25, end: 3}\n", "hours"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nhours: {start: 1, end: 3, outside: warn}\n", "hours.outside"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nlocation: {allowed_countries: [usa]}\n", "two-letter"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nstep_up: {actions: [delete]}\n", "unknown action"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nsession: {lifetime_minutes: 5000}\n", "lifetime_minutes"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\nsession: {bind_to_device: 1}\n", "true or false"),
        ("app: x\nsensitivity: low\nallow_groups: [a]\ndevice: {min_trust: medium, read_only_trust: high}\n",
         "below device.min_trust"),
        ("- just\n- a list\n", "must be a YAML mapping"),
        ("app: [unclosed\n", "invalid YAML"),
    ],
)
def test_validation_errors(text, message):
    with pytest.raises(PolicyError) as e:
        parse_policy(text)
    assert any(message in m for m in e.value.errors), e.value.errors


def test_load_reports_file_names(tmp_path):
    (tmp_path / "a.yaml").write_text("app: a\nsensitivity: low\nallow_groups: [g]\n")
    (tmp_path / "b.yaml").write_text("app: b\nsensitivity: nope\nallow_groups: [g]\n")
    with pytest.raises(PolicyError) as e:
        load_policies(tmp_path)
    assert e.value.errors[0].startswith("b.yaml:")


def test_overlay_replaces_by_app(tmp_path):
    base, over = tmp_path / "base", tmp_path / "over"
    base.mkdir()
    over.mkdir()
    (base / "a.yaml").write_text("app: a\nsensitivity: low\nallow_groups: [g]\n")
    (over / "a.yaml").write_text("app: a\nsensitivity: high\nallow_groups: [g2]\n")
    ps = load_policies(base, over)
    assert ps["a"].sensitivity == "high" and ps["a"].allow_groups == ["g2"]


# ---------------------------------------------------------------- each condition


def test_clean_request_allows_with_full_trace():
    d = evaluate(policy(), inputs())
    assert d.outcome == "allow"
    checks = [t["check"] for t in d.trace]
    assert checks == ["authentication", "session_binding", "identity_status", "groups", "device_trust", "user_risk",
                      "mfa_freshness", "sensitive_action", "time_of_day", "location"]
    assert d.session_lifetime == 60


def test_failed_password_denies_and_stops():
    d = evaluate(policy(), inputs(auth_failed=True))
    assert d.outcome == "deny" and len(d.trace) == 1


def test_group_not_allowed():
    d = evaluate(policy(), inputs(groups=["sales", "all-employees"]))
    assert d.outcome == "deny" and result(d, "groups") == "deny"


def test_deny_group_beats_allow_group():
    d = evaluate(policy(), inputs(groups=["payroll-admins", "contractors"]))
    assert d.outcome == "deny" and "denied group" in d.reasons[0]


def test_inactive_identity_denied():
    d = evaluate(policy(), inputs(user_active=False, user_status="contract ended 2026-10-18"))
    assert result(d, "identity_status") == "deny"
    assert evaluate(policy(identity={"require_active": False}), inputs(user_active=False)).outcome == "allow"


def test_device_below_minimum_denied():
    assert evaluate(policy(), inputs(device_trust="medium")).outcome == "deny"


def test_device_read_only_band():
    p = policy(device={"min_trust": "high", "read_only_trust": "medium"})
    read = evaluate(p, inputs(device_trust="medium"))
    assert read.outcome == "allow_restricted" and read.restrictions == ["read_only"]
    write = evaluate(p, inputs(device_trust="medium", action="write", mfa_age=1))
    assert write.outcome == "deny" and "read-only" in write.reasons[0]
    assert evaluate(p, inputs(device_trust="low")).outcome == "deny"


def test_risk_bands():
    assert result(evaluate(policy(), inputs(risk=20)), "user_risk") == "pass"
    assert evaluate(policy(), inputs(risk=21)).outcome == "step_up"
    assert evaluate(policy(), inputs(risk=41)).outcome == "deny"


def test_mfa_freshness():
    assert evaluate(policy(), inputs(mfa_age=241)).outcome == "step_up"
    assert evaluate(policy(), inputs(mfa_age=None)).outcome == "step_up"


def test_sensitive_action_needs_recent_mfa():
    assert evaluate(policy(), inputs(action="write", mfa_age=10)).outcome == "allow"
    d = evaluate(policy(), inputs(action="write", mfa_age=16))
    assert d.outcome == "step_up" and result(d, "sensitive_action") == "step_up"
    assert result(evaluate(policy(), inputs(action="read", mfa_age=16)), "sensitive_action") == "skip"


def test_hours_step_up_or_deny_and_overnight_windows():
    assert evaluate(policy(), inputs(local_hour=3.2)).outcome == "step_up"
    assert evaluate(policy(hours={"start": 6, "end": 22, "outside": "deny"}), inputs(local_hour=23)).outcome == "deny"
    night = policy(hours={"start": 20, "end": 6})
    assert evaluate(night, inputs(local_hour=2)).outcome == "allow"
    assert evaluate(night, inputs(local_hour=12)).outcome == "step_up"


def test_location_allow_and_deny_lists():
    assert evaluate(policy(), inputs(country="NL", city="Amsterdam")).outcome == "deny"
    p = policy(location={"denied_countries": ["RO"]})
    assert evaluate(p, inputs(country="RO")).outcome == "deny"
    assert evaluate(p, inputs(country="NL")).outcome == "allow"


def test_session_binding():
    d = evaluate(policy(), inputs(token_device="lt-u1", device="x-other"))
    assert d.outcome == "deny" and result(d, "session_binding") == "deny"
    assert result(evaluate(policy(), inputs(token_device="lt-u1")), "session_binding") == "pass"
    unbound = policy(session={"lifetime_minutes": 60, "bind_to_device": False})
    assert evaluate(unbound, inputs(token_device="lt-u1", device="x-other")).outcome == "allow"


# ---------------------------------------------------------------- precedence


def test_deny_beats_step_up():
    d = evaluate(policy(), inputs(risk=30, groups=["sales"]))
    assert d.outcome == "deny"
    assert result(d, "user_risk") == "step_up"  # the trace still shows every check


def test_step_up_beats_restriction():
    p = policy(device={"min_trust": "high", "read_only_trust": "medium"})
    assert evaluate(p, inputs(device_trust="medium", local_hour=3)).outcome == "step_up"


def test_reasons_list_only_the_deciding_checks():
    d = evaluate(policy(), inputs(groups=["sales"], country="NL"))
    assert [r.split(":")[0] for r in d.reasons] == ["groups", "location"]


def test_step_up_satisfies_risk_and_hours_but_not_denies():
    x = inputs(risk=30, local_hour=3, mfa_age=0, stepped_up=True)
    assert evaluate(policy(), x).outcome == "allow"
    assert evaluate(policy(hours={**BASE["hours"], "outside": "deny"}), x).outcome == "deny"
