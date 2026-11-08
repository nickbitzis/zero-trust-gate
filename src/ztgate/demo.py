"""End-to-end demo against a running stack (or in-process test clients): sign in, use two apps through the proxy,
step up for a payroll change, replay the cookie from another device, tamper with it, then watch continuous
evaluation revoke the session when the laptop's EDR agent stops."""

from __future__ import annotations

from .geo import office_ip


def pick_user(admin) -> dict:
    """A payroll admin with a fully compliant laptop, so every step shows one control at a time."""
    users = admin.get("/api/users", params={"q": "hr", "limit": 1000}).json()["items"]
    for u in users:
        # Pick someone whose local time when the log ends is inside payroll's 06:00 to 22:00 window.
        if "payroll-admins" not in u["groups"] or u["city"] not in ("San Francisco", "London"):
            continue
        detail = admin.get(f"/api/users/{u['id']}").json()
        lt = next((d for d in detail["devices"] if d["id"] == f"lt-{u['id']}"), None)
        if lt and lt["trust"]["level"] == "high":
            return u
    raise RuntimeError("no payroll admin with a compliant laptop")


def run_demo(admin, proxy) -> list[dict]:
    steps: list[dict] = []

    def note(name: str, resp, expect: int) -> dict:
        body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        step = {"step": name, "status": resp.status_code, "expected": expect, "ok": resp.status_code == expect,
                "body": body}
        steps.append(step)
        return step

    u = pick_user(admin)
    uid, laptop = u["id"], f"lt-{u['id']}"
    ip = office_ip(u["city"], int(uid[1:]))
    hdr = {"X-Device-Id": laptop, "X-Forwarded-For": ip}

    login = admin.post("/api/login", json={"user": uid, "device": laptop, "ip": ip, "app": "wiki"}).json()
    steps.append({"step": f"sign in as {u['email']} on {laptop}", "status": 200, "expected": 200,
                  "ok": "token" in login, "body": {k: v for k, v in login.items() if k != "token"}})
    token = login["token"]
    auth = {**hdr, "Authorization": f"Bearer {token}"}

    note("GET /wiki/handbook through the proxy", proxy.get("/wiki/handbook", headers=auth), 200)
    note("GET /payroll/runs (read)", proxy.get("/payroll/runs", headers=auth), 200)

    admin.post("/api/clock/advance", json={"minutes": 40})
    r = proxy.post("/payroll/runs", headers=auth, json={"period": "2026-11", "action": "approve"})
    s = note("POST /payroll/runs 40 minutes later: write needs fresh MFA", r, 401)
    if r.status_code == 401 and s["body"].get("challenge"):
        st = admin.post("/api/stepup", json={"challenge": s["body"]["challenge"], "passed": True})
        note("answer the MFA step-up challenge", st, 200)
        note("POST /payroll/runs again", proxy.post("/payroll/runs", headers=auth, json={"period": "2026-11"}), 200)

    stolen = {"X-Device-Id": "x-unknown-laptop", "X-Forwarded-For": "203.0.113.170", "Authorization": f"Bearer {token}"}
    note("replay the same token from another device", proxy.get("/payroll/runs", headers=stolen), 403)

    body, sig = token.split(".")
    tampered = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1] + "." + sig
    note("tampered token", proxy.get("/wiki/handbook", headers={**hdr, "Authorization": f"Bearer {tampered}"}), 401)

    sig_resp = admin.post("/api/signals", json={"kind": "device_posture", "target": laptop,
                                                "changes": {"edr_running": False},
                                                "reason": "EDR agent stopped reporting"}).json()
    steps.append({"step": "EDR stops on the laptop: continuous evaluation", "status": 200, "expected": 200,
                  "ok": len(sig_resp["revoked"]) > 0, "body": sig_resp})
    note("GET /payroll/runs after revocation", proxy.get("/payroll/runs", headers=auth), 401)
    admin.post("/api/signals", json={"kind": "device_posture", "target": laptop, "changes": {"edr_running": True},
                                     "reason": "EDR agent restarted"})
    return steps
