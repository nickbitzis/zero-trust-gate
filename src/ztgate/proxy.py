"""Identity-aware reverse proxy (the policy enforcement point).

For every request: read the session token, check its signature locally, ask the decision point, and only then
forward to the backend with identity headers. Client-supplied X-ZT-* headers are stripped so they cannot be spoofed.
If the decision point is unreachable the proxy fails closed.
"""

from __future__ import annotations

import os
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from .logs import get_logger, log_event
from .metrics import Metrics
from .tokens import TokenError, verify

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "host", "content-length"}
COOKIE = "zt_session"


def action_for(method: str, path: str) -> str:
    p = path.lower()
    if "/admin" in p:
        return "admin"
    if "/export" in p or p.endswith(".csv"):
        return "export"
    return "read" if method in ("GET", "HEAD", "OPTIONS") else "write"


def parse_routes(spec: str) -> dict[str, str]:
    """"wiki=http://localhost:8863,payroll=http://localhost:8864" -> {"wiki": "...", "payroll": "..."}"""
    out = {}
    for part in filter(None, (x.strip() for x in spec.split(","))):
        name, _, url = part.partition("=")
        out[name.strip()] = url.strip().rstrip("/")
    return out


def create_proxy(pdp: httpx.AsyncClient, backends: dict[str, httpx.AsyncClient], key: bytes) -> FastAPI:
    app = FastAPI(title="Zero Trust Gate proxy", version="1.0.0")
    log = get_logger()
    metrics = Metrics("ztproxy")

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok", "routes": sorted(backends)}

    @app.get("/metrics", response_class=PlainTextResponse)
    async def prom():
        return metrics.render()

    def deny(status: int, body: dict, app_name: str, t: float) -> JSONResponse:
        metrics.observe_request(f"/{app_name}", status, time.perf_counter() - t)
        metrics.action(app_name, body.get("decision", "error"))
        return JSONResponse(body, status_code=status)

    @app.api_route("/{app_name}/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"])
    async def gate(app_name: str, path: str, request: Request):
        t = time.perf_counter()
        backend = backends.get(app_name)
        if backend is None:
            return deny(404, {"error": f"no route for /{app_name}"}, "unknown", t)
        auth = request.headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else request.cookies.get(COOKIE, "")
        if not token:
            return deny(401, {"decision": "deny", "reasons": ["sign in required"]}, app_name, t)
        try:
            verify(token, key, now=0)  # signature only; expiry runs on the decision point's clock
        except TokenError as e:
            return deny(401, {"decision": "deny", "reasons": [f"session token: {e}"]}, app_name, t)
        device = request.headers.get("x-device-id", "unregistered")  # stands in for the mTLS client certificate
        fwd = request.headers.get("x-forwarded-for", "")
        ip = fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "")
        action = action_for(request.method, "/" + path)
        try:
            resp = await pdp.post("/api/decide", json={"token": token, "app": app_name, "action": action,
                                                       "device": device, "ip": ip, "path": "/" + path}, timeout=3)
            resp.raise_for_status()
            d = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            log_event(log, "decision point unavailable", app=app_name, error=str(e))
            return deny(503, {"decision": "deny", "reasons": ["decision point unavailable, failing closed"]},
                        app_name, t)
        log_event(log, "proxy decision", app=app_name, path="/" + path, method=request.method, device=device, ip=ip,
                  decision=d.get("decision"), decision_id=d.get("decision_id"))
        if d.get("decision") == "step_up":
            return deny(401, {"decision": "step_up", "challenge": d.get("challenge"), "reasons": d.get("reasons"),
                              "decision_id": d.get("decision_id")}, app_name, t)
        if d.get("decision") not in ("allow", "allow_restricted"):
            return deny(d.get("status", 403), {"decision": "deny", "reasons": d.get("reasons", []),
                                               "decision_id": d.get("decision_id")}, app_name, t)
        if "read_only" in d.get("restrictions", []) and action != "read":
            return deny(403, {"decision": "deny", "reasons": ["read-only session"]}, app_name, t)

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in HOP_BY_HOP and not k.lower().startswith("x-zt-")
                   and k.lower() not in ("authorization", "cookie")}
        headers.update(d.get("headers", {}))
        body = await request.body()
        try:
            upstream = await backend.request(request.method, "/" + path, params=dict(request.query_params),
                                             headers=headers, content=body, timeout=10)
        except httpx.HTTPError as e:
            return deny(502, {"error": f"backend {app_name} unavailable: {e}"}, app_name, t)
        out = Response(upstream.content, status_code=upstream.status_code,
                       headers={k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP})
        out.headers["X-ZT-Decision"] = d["decision"]
        out.headers["X-ZT-Decision-Id"] = str(d.get("decision_id"))
        metrics.observe_request(f"/{app_name}", upstream.status_code, time.perf_counter() - t)
        metrics.action(app_name, d["decision"])
        return out

    return app


def proxy_from_env(key: bytes) -> FastAPI:
    pdp = httpx.AsyncClient(base_url=os.environ.get("ZTGATE_PDP_URL", "http://127.0.0.1:8861"))
    routes = parse_routes(os.environ.get("ZTGATE_ROUTES", "wiki=http://127.0.0.1:8863,payroll=http://127.0.0.1:8864"))
    return create_proxy(pdp, {k: httpx.AsyncClient(base_url=v) for k, v in routes.items()}, key)
