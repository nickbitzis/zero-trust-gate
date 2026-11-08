import httpx
import pytest
import yaml
from conftest import POLICIES
from fastapi.testclient import TestClient

from ztgate.app import build_gate, create_app
from ztgate.backends import make_backend
from ztgate.demo import run_demo
from ztgate.geo import office_ip
from ztgate.proxy import action_for, create_proxy, parse_routes

KEY = b"t" * 32


@pytest.fixture(scope="module")
def stack():
    admin_app = create_app(build_gate(7, POLICIES), key=KEY)
    proxy_app = create_proxy(
        httpx.AsyncClient(transport=httpx.ASGITransport(app=admin_app), base_url="http://admin"),
        {n: httpx.AsyncClient(transport=httpx.ASGITransport(app=make_backend(n, KEY)), base_url=f"http://{n}")
         for n in ("wiki", "payroll")},
        KEY,
    )
    with TestClient(admin_app) as admin, TestClient(proxy_app) as proxy:
        yield admin, proxy


@pytest.fixture(scope="module")
def admin(stack):
    return stack[0]


@pytest.fixture(scope="module")
def proxy(stack):
    return stack[1]


def login(admin, uid: str, city: str, app: str = "wiki"):
    lt = f"lt-{uid}"
    ip = office_ip(city, int(uid[1:]))
    r = admin.post("/api/login", json={"user": uid, "device": lt, "ip": ip, "app": app}).json()
    return r, {"X-Device-Id": lt, "X-Forwarded-For": ip, "Authorization": f"Bearer {r.get('token', '')}"}


def compliant_user(admin, group="all-employees"):
    users = admin.get("/api/users", params={"limit": 1000}).json()["items"]
    for u in users:
        if group in u["groups"] and u["city"] in ("San Francisco", "London") and u["kind"] == "employee":
            lt = next(d for d in admin.get(f"/api/users/{u['id']}").json()["devices"] if d["id"] == f"lt-{u['id']}")
            if lt["trust"]["level"] == "high":
                return u
    raise AssertionError


# ---------------------------------------------------------------- proxy units


def test_action_mapping_and_routes():
    assert action_for("GET", "/runs") == "read"
    assert action_for("POST", "/runs") == "write"
    assert action_for("GET", "/runs/export") == "export"
    assert action_for("DELETE", "/admin/users") == "admin"
    assert parse_routes("wiki=http://a:1/, payroll=http://b:2") == {"wiki": "http://a:1", "payroll": "http://b:2"}


def test_proxy_injects_identity_and_strips_spoofed_headers(admin, proxy):
    u = compliant_user(admin)
    _, h = login(admin, u["id"], u["city"])
    r = proxy.get("/wiki/handbook", headers={**h, "X-ZT-User": "ceo@tallowmere.example", "X-ZT-Groups": "exec"})
    assert r.status_code == 200
    who = r.json()["seen_identity"]
    assert who["user"] == u["email"] and "exec" not in who["groups"]
    assert who["device_trust"] == "high" and r.headers["x-zt-decision"] == "allow"


def test_proxy_requires_a_token(proxy):
    r = proxy.get("/wiki/handbook")
    assert r.status_code == 401 and "sign in" in r.json()["reasons"][0]


def test_proxy_rejects_tampered_token_locally(admin, proxy):
    u = compliant_user(admin)
    _, h = login(admin, u["id"], u["city"])
    h["Authorization"] = h["Authorization"][:-3] + "abc"
    assert proxy.get("/wiki/x", headers=h).status_code == 401


def test_proxy_unknown_route(proxy):
    assert proxy.get("/nope/x", headers={"Authorization": "Bearer a.b"}).status_code == 404


def test_backend_refuses_requests_that_skip_the_proxy():
    with TestClient(make_backend("payroll", KEY)) as b:
        r = b.get("/runs", headers={"X-ZT-User": "someone@tallowmere.example"})
        assert r.status_code == 401 and "access proxy" in r.json()["error"]


def test_proxy_fails_closed_when_pdp_is_down():
    def boom(request):
        raise httpx.ConnectError("down")

    app = create_proxy(httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="http://pdp"),
                       {"wiki": httpx.AsyncClient(transport=httpx.MockTransport(boom), base_url="http://w")}, KEY)
    from ztgate.tokens import sign

    with TestClient(app) as c:
        r = c.get("/wiki/x", headers={"Authorization": f"Bearer {sign({'sub': 'u1', 'dev': 'd'}, KEY)}"})
    assert r.status_code == 503 and "failing closed" in r.json()["reasons"][0]


def test_replayed_token_from_other_device_denied(admin, proxy):
    u = compliant_user(admin)
    _, h = login(admin, u["id"], u["city"])
    r = proxy.get("/wiki/x", headers={**h, "X-Device-Id": "x-attacker"})
    assert r.status_code == 403 and "session_binding" in r.json()["reasons"][0]


def test_user_outside_group_denied_by_proxy(admin, proxy):
    u = compliant_user(admin, "sales")
    _, h = login(admin, u["id"], u["city"])
    r = proxy.get("/payroll/runs", headers=h)
    assert r.status_code == 403 and any("groups" in x for x in r.json()["reasons"])


def test_admin_revoke_ends_proxy_access(admin, proxy):
    u = compliant_user(admin, "sales")
    r, h = login(admin, u["id"], u["city"])
    assert proxy.get("/wiki/x", headers=h).status_code == 200
    sid = admin.get(f"/api/decisions/{r['decision_id']}").json()["session"]
    assert sid in [s["id"] for s in admin.get("/api/sessions", params={"user": u["id"]}).json()["items"]]
    assert admin.post(f"/api/sessions/{sid}/revoke", json={"reason": "lost laptop"}).json()["status"] == "revoked"
    r = proxy.get("/wiki/x", headers=h)
    assert r.status_code == 401 and "lost laptop" in r.json()["reasons"][0]
    revoked = admin.get("/api/sessions", params={"status": "revoked", "user": u["id"]}).json()["items"]
    assert any(s["id"] == sid for s in revoked)


def test_full_demo_flow(stack):
    steps = run_demo(*stack)
    assert all(s["ok"] for s in steps), [(s["step"], s["status"]) for s in steps if not s["ok"]]
    assert len(steps) >= 10


# ---------------------------------------------------------------- admin API


def test_healthz_and_metrics(admin):
    assert admin.get("/healthz").json()["status"] == "ok"
    text = admin.get("/metrics").text
    assert "ztgate_planted_events_caught 13" in text
    assert "ztgate_http_requests_total" in text and "ztgate_false_deny_rate" in text


def test_ui_served(admin):
    r = admin.get("/")
    assert r.status_code == 200 and "Zero Trust Gate" in r.text


def test_summary_and_analytics(admin):
    s = admin.get("/api/summary").json()
    assert s["users"] == 800 and s["planted_caught"] == len(s["planted"]) == 13
    a = admin.get("/api/analytics").json()
    assert len(a["by_app"]) == 30 and a["least_privilege"] and len(a["daily"]) == 30


def test_policies_endpoints(admin):
    ps = admin.get("/api/policies").json()
    assert len(ps) == 30
    p = admin.get("/api/policies/payroll").json()
    assert p["allow_groups"] == ["payroll-admins"] and "app: payroll" in p["yaml"]
    assert admin.get("/api/policies/nope").status_code == 404
    bad = admin.post("/api/policies/validate", json={"yaml": "app: x\nsensitivity: low\n"}).json()
    assert not bad["valid"] and bad["errors"]
    ok = admin.post("/api/policies/validate", json={"yaml": p["yaml"]}).json()
    assert ok["valid"]


def test_decision_log_filters_and_trace(admin):
    d = admin.get("/api/decisions", params={"app": "payroll", "outcome": "step_up", "limit": 5}).json()
    assert d["total"] > 0 and all(x["app"] == "payroll" and x["outcome"] == "step_up" for x in d["items"])
    planted = admin.get("/api/decisions", params={"planted": "any", "limit": 500}).json()
    assert {x["planted"] for x in planted["items"]} >= {"P1", "P3", "P5", "P7", "P9", "P11"}
    fd = admin.get("/api/decisions", params={"legit": "false_deny", "limit": 3}).json()
    assert fd["total"] > 0 and all(x["final"] == "deny" and x["legit"] for x in fd["items"])
    one = admin.get(f"/api/decisions/{planted['items'][0]['id']}").json()
    assert len(one["trace"]) >= 1 and "inputs" in one
    assert admin.get("/api/decisions/99999999").status_code == 404
    q = admin.get("/api/decisions", params={"q": "session_binding", "limit": 5}).json()
    assert q["total"] >= 6


def test_simulate_what_if(admin):
    u = compliant_user(admin, "payroll-admins")
    base = {"user": u["id"], "app": "payroll", "action": "read", "local_hour": 11, "mfa_age_minutes": 5}
    assert admin.post("/api/simulate", json=base).json()["decision"] == "allow"
    night = admin.post("/api/simulate", json={**base, "local_hour": 3}).json()
    assert night["decision"] == "step_up" and night["after_step_up"] == "allow"
    edr = admin.post("/api/simulate", json={**base, "posture": {"edr_running": False}}).json()
    assert edr["decision"] == "deny" and edr["device_trust"]["level"] == "low"
    travel = admin.post("/api/simulate", json={**base, "city": "London",
                                               "previous": {"city": "San Francisco" if u["city"] != "San Francisco"
                                                            else "Austin", "minutes_ago": 30}}).json()
    assert travel["decision"] == "deny"
    assert any(c["component"] == "impossible_travel" for c in travel["risk"]["components"])
    replay = admin.post("/api/simulate", json={**base, "session": "replayed", "device": "unregistered"}).json()
    assert replay["decision"] == "deny"
    assert admin.post("/api/simulate", json={**base, "user": "nobody"}).status_code == 422


def test_simulate_against_draft_policy(admin):
    u = compliant_user(admin, "payroll-admins")
    draft = yaml.safe_load((POLICIES / "payroll.yaml").read_text())
    draft.pop("hours")
    out = admin.post("/api/simulate", json={"user": u["id"], "local_hour": 3, "mfa_age_minutes": 5,
                                            "policy_yaml": yaml.safe_dump(draft)}).json()
    assert out["decision"] == "allow"


def test_diff_endpoint(admin):
    draft = yaml.safe_load((POLICIES / "source-code.yaml").read_text())
    draft["identity"] = {"require_active": False}
    d = admin.post("/api/diff", json={"yaml": yaml.safe_dump(draft)}).json()
    assert "P5" in d["planted_newly_allowed"] and d["counts"]["newly_allowed"] >= 3
    assert admin.post("/api/diff", json={"yaml": "app: x\n"}).status_code == 422


def test_signal_endpoint_validation(admin):
    assert admin.post("/api/signals", json={"kind": "device_posture"}).status_code == 422
    assert admin.post("/api/signals", json={"kind": "weather", "target": "u0001"}).status_code == 422


def test_sessions_list_has_history(admin):
    revoked = admin.get("/api/sessions", params={"status": "revoked"}).json()
    assert revoked["total"] >= 4
    assert any(s["planted"] is None and "EDR" in (s["revoke_reason"] or "") for s in revoked["items"])
    active = admin.get("/api/sessions", params={"status": "active"}).json()
    assert active["total"] > 0
    assert admin.post("/api/sessions/nope/revoke").status_code == 404


def test_stepup_challenge_single_use(admin):
    assert admin.post("/api/stepup", json={"challenge": "made-up"}).status_code == 404
