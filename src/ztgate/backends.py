"""Two tiny internal apps behind the proxy: a wiki and a payroll system.

They trust only the signed X-ZT-Assertion header the proxy injects, so a request that skips the proxy is refused.
"""

from __future__ import annotations

import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .tokens import TokenError, verify

PAGES = {"handbook": "Tallowmere handbook: holidays, travel, and expenses.",
         "oncall": "On-call rota and escalation policy.", "": "Wiki home"}
PAY_RUNS = [{"id": "pr-2026-10", "period": "2026-10", "employees": 794, "status": "paid"},
            {"id": "pr-2026-11", "period": "2026-11", "employees": 796, "status": "draft"}]


def make_backend(name: str, key: bytes) -> FastAPI:
    app = FastAPI(title=f"{name} (demo backend)")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "app": name}

    def identity(request: Request) -> dict:
        try:
            claims = verify(request.headers.get("x-zt-assertion", ""), key, time.time(), purpose="assertion")
        except TokenError as e:
            raise PermissionError(str(e)) from e
        if claims.get("app") != name:
            raise PermissionError("assertion is for another app")
        return {
            "user": request.headers.get("x-zt-user"), "user_id": claims["sub"],
            "groups": [g for g in request.headers.get("x-zt-groups", "").split(",") if g],
            "device_trust": request.headers.get("x-zt-device-trust"),
            "restrictions": [r for r in request.headers.get("x-zt-restrictions", "").split(",") if r],
            "decision_id": request.headers.get("x-zt-decision-id"),
        }

    @app.exception_handler(PermissionError)
    async def refused(_: Request, exc: PermissionError):
        return JSONResponse({"error": f"request did not come through the access proxy: {exc}"}, status_code=401)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def handle(path: str, request: Request):
        who = identity(request)
        body: dict = {"app": name, "path": "/" + path, "method": request.method, "seen_identity": who}
        if name == "wiki":
            body["page"] = PAGES.get(path.strip("/"), "page not found")
        elif name == "payroll":
            if request.method == "GET":
                body["pay_runs"] = PAY_RUNS
            else:
                body["result"] = f"pay run change recorded by {who['user']}"
        return body

    return app
