"""Command line: run the services, the demo, the CI gate, a policy diff, and the results report."""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path


def _gate(args):
    from .app import build_gate
    from .engine import Gate
    from .generator import generate
    from .policy import load_policies

    if getattr(args, "overlay", None):
        from .app import policies_dir

        base = Path(args.policies) if args.policies else policies_dir()
        return Gate(generate(args.seed), load_policies(base, Path(args.overlay)), seed=args.seed).replay()
    return build_gate(args.seed, Path(args.policies) if args.policies else None)


def cmd_serve(args):
    import uvicorn

    from .app import create_app

    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="warning")


def cmd_proxy(args):
    import uvicorn

    from .proxy import proxy_from_env
    from .tokens import signing_key

    if not os.environ.get("ZTGATE_SIGNING_KEY"):
        sys.exit("set ZTGATE_SIGNING_KEY to the same value as the admin service")
    uvicorn.run(proxy_from_env(signing_key()), host=args.host, port=args.port, log_level="warning")


def cmd_backend(args):
    import uvicorn

    from .backends import make_backend
    from .tokens import signing_key

    if not os.environ.get("ZTGATE_SIGNING_KEY"):
        sys.exit("set ZTGATE_SIGNING_KEY to the same value as the admin service")
    uvicorn.run(make_backend(args.name, signing_key()), host=args.host, port=args.port, log_level="warning")


def cmd_stack(args):
    """All four processes' apps in one Python process, for running without Docker."""
    import secrets

    import httpx
    import uvicorn

    from .app import create_app
    from .backends import make_backend
    from .proxy import create_proxy

    key = os.environ.get("ZTGATE_SIGNING_KEY", "").encode() or secrets.token_bytes(32)
    p = args.port
    host = args.host
    admin = create_app(key=key)
    loop_host = "127.0.0.1"
    proxy = create_proxy(
        httpx.AsyncClient(base_url=f"http://{loop_host}:{p}"),
        {"wiki": httpx.AsyncClient(base_url=f"http://{loop_host}:{p + 2}"),
         "payroll": httpx.AsyncClient(base_url=f"http://{loop_host}:{p + 3}")},
        key,
    )
    servers = [
        uvicorn.Server(uvicorn.Config(admin, host=host, port=p, log_level="warning")),
        uvicorn.Server(uvicorn.Config(proxy, host=host, port=p + 1, log_level="warning")),
        uvicorn.Server(uvicorn.Config(make_backend("wiki", key), host=loop_host, port=p + 2, log_level="warning")),
        uvicorn.Server(uvicorn.Config(make_backend("payroll", key), host=loop_host, port=p + 3, log_level="warning")),
    ]
    for s in servers[1:]:
        s.install_signal_handlers = lambda: None
        threading.Thread(target=s.run, daemon=True).start()
    print(json.dumps({"admin": f"http://{loop_host}:{p}", "proxy": f"http://{loop_host}:{p + 1}",
                      "wiki_backend": p + 2, "payroll_backend": p + 3}), flush=True)
    servers[0].run()


def cmd_demo(args):
    from .demo import run_demo

    if args.admin:
        import httpx

        admin, proxy = httpx.Client(base_url=args.admin), httpx.Client(base_url=args.proxy)
        steps = run_demo(admin, proxy)
    else:
        steps = demo_inprocess()
    for s in steps:
        mark = "ok " if s["ok"] else "BAD"
        body = s["body"]
        detail = ""
        if isinstance(body, dict):
            if s["status"] == 200 and body.get("decision") and "seen_identity" not in body:
                detail = f"decision {body['decision']}"
            elif "seen_identity" in body:
                who = body["seen_identity"]
                detail = f"backend saw {who['user']} groups={','.join(who['groups'][:3])} trust={who['device_trust']}"
            elif body.get("reasons"):
                detail = body["reasons"][0]
            elif body.get("revoked"):
                detail = f"revoked {len(body['revoked'])} session(s): {body['revoked'][0]['reason']}"
            elif body.get("decision"):
                detail = f"decision {body['decision']}"
        print(f"[{mark}] {s['status']}  {s['step']}" + (f"\n        {detail}" if detail else ""))
    sys.exit(0 if all(s["ok"] for s in steps) else 1)


def demo_inprocess(gate=None):
    import secrets

    import httpx
    from fastapi.testclient import TestClient

    from .app import create_app
    from .backends import make_backend
    from .demo import run_demo
    from .proxy import create_proxy

    key = secrets.token_bytes(32)
    admin_app = create_app(gate, key=key)
    proxy_app = create_proxy(
        httpx.AsyncClient(transport=httpx.ASGITransport(app=admin_app), base_url="http://admin"),
        {n: httpx.AsyncClient(transport=httpx.ASGITransport(app=make_backend(n, key)), base_url=f"http://{n}")
         for n in ("wiki", "payroll")},
        key,
    )
    with TestClient(admin_app) as admin, TestClient(proxy_app) as proxy:
        return run_demo(admin, proxy)


def report_markdown(s: dict) -> str:
    lines = ["| # | Planted event | Requests | Decision | Caught | Caught by |", "|---|---|---:|---|---|---|"]
    for p in s["planted"]:
        if "revoked" in p:
            dec, n = f"{p['revoked']} sessions revoked", "signal"
        else:
            o = p["outcomes"]
            dec = ", ".join(f"{k} {v}" for k, v in sorted(o.items()))
            if p.get("stepup_failed"):
                dec += f" (step-up failed {p['stepup_failed']})"
            n = str(p["requests"])
        lines.append(f"| {p['id']} | {p['title']} | {n} | {dec} | {'yes' if p['caught'] else 'NO'} | "
                     f"{', '.join(p['caught_by'][:3])} |")
    f = s["friction"]
    lines += ["", f"Legitimate, entitled requests: {f['legit_requests']:,}. False denies: {f['false_denies']} "
              f"({f['false_deny_rate'] * 100:.2f}%), affecting {f['users_with_a_false_deny']} people. Step-ups: "
              f"{f['step_ups']} ({f['step_up_rate'] * 100:.2f}%), {f['step_up_passed']} passed. Read-only grants: "
              f"{f['read_only']}.", "", "False denies by check: " +
              ", ".join(f"{k} {v}" for k, v in f["false_deny_by_check"].items())]
    return "\n".join(lines)


def cmd_report(args):
    from . import analytics

    t = time.perf_counter()
    g = _gate(args)
    s = analytics.summary(g, args.max_false_deny_rate)
    if args.json:
        print(json.dumps(s, indent=1, default=str))
        return
    print(f"{s['company']}: {s['users']} people ({s['contractors']} contractors), {s['groups']} groups, {s['apps']} "
          f"apps, {s['devices']} devices, {s['decisions']:,} decisions, replayed in {time.perf_counter() - t:.1f}s")
    print(f"Outcomes: {s['outcomes']}")
    print(report_markdown(s))
    print("\nLeast-privilege recommendations:")
    for r in s["least_privilege"]:
        print(f"- {r['recommendation']} ({r['sensitivity']})")


def cmd_gate(args):
    from . import analytics

    g = _gate(args)
    s = analytics.summary(g, args.max_false_deny_rate)
    res = s["gate"]
    print(report_markdown(s))
    if args.summary:
        Path(args.summary).write_text("## Zero trust gate\n\n" + report_markdown(s) + "\n")
    if res["pass"]:
        print(f"\nGATE PASS: {len(s['planted'])} of {len(s['planted'])} planted events caught, false deny rate "
              f"{res['false_deny_rate'] * 100:.2f}% (limit {args.max_false_deny_rate * 100:.1f}%)")
        return
    why = []
    if res["missed"]:
        why.append(f"missed planted events {', '.join(res['missed'])}")
    if res["false_deny_rate"] > args.max_false_deny_rate:
        why.append(f"false deny rate {res['false_deny_rate'] * 100:.2f}% is over {args.max_false_deny_rate * 100:.1f}%")
    print("\nGATE FAIL: " + "; ".join(why))
    sys.exit(1)


def cmd_diff(args):
    from . import analytics
    from .policy import parse_policy

    g = _gate(args)
    p = parse_policy(Path(args.file).read_text(), args.file)
    d = analytics.diff(g, p, sample=5)
    print(f"{p.app}: {d['changed']} of {d['requests']} past requests change")
    for t in d["transitions"]:
        print(f"  {t['before']:>16} -> {t['after']:<16} {t['count']}")
    for k, v in d["counts"].items():
        if v:
            print(f"  {k}: {v} requests, {d['users'].get(k, 0)} users")
    if d["planted_newly_allowed"]:
        print(f"  WARNING: planted risky events would be allowed: {', '.join(d['planted_newly_allowed'])}")
        sys.exit(1)


def cmd_validate(args):
    from .policy import PolicyError, load_policies

    try:
        ps = load_policies(Path(args.dir))
    except PolicyError as e:
        print("\n".join(e.errors))
        sys.exit(1)
    print(f"{len(ps)} policies valid")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ztgate")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--seed", type=int, default=7)
        p.add_argument("--policies", default=None)
        p.add_argument("--overlay", default=None, help="directory of policies that replace the base ones by app")
        p.add_argument("--max-false-deny-rate", type=float, default=0.02)

    for name, port in (("serve", 8861), ("proxy", 8862)):
        p = sub.add_parser(name)
        p.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
        p.add_argument("--port", type=int, default=int(os.environ.get("PORT", port)))
    p = sub.add_parser("backend")
    p.add_argument("name", choices=["wiki", "payroll"])
    p.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", 8863)))
    p = sub.add_parser("stack", help="admin, proxy, and both backends in one process (ports p to p+3)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8861)
    p = sub.add_parser("demo")
    p.add_argument("--admin", default=None, help="admin URL of a running stack; omit to run in-process")
    p.add_argument("--proxy", default="http://127.0.0.1:8862")
    for name in ("report", "gate", "diff"):
        p = sub.add_parser(name)
        common(p)
        if name == "report":
            p.add_argument("--json", action="store_true")
        if name == "gate":
            p.add_argument("--summary", default=None, help="write a markdown summary (for the CI job summary)")
        if name == "diff":
            p.add_argument("file")
    p = sub.add_parser("validate")
    p.add_argument("dir", nargs="?", default="policies")

    args = ap.parse_args(argv)
    {"serve": cmd_serve, "proxy": cmd_proxy, "backend": cmd_backend, "stack": cmd_stack, "demo": cmd_demo,
     "report": cmd_report, "gate": cmd_gate, "diff": cmd_diff, "validate": cmd_validate}[args.cmd](args)


if __name__ == "__main__":
    main()
