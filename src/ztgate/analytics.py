"""Analytics over the decision log: outcomes by app, step-up rates, planted event results, friction for legitimate
users, least-privilege recommendations, and the policy diff."""

from __future__ import annotations

from collections import Counter, defaultdict

from .engine import Gate, Record
from .model import OUTCOMES
from .policy import Policy, evaluate

GRANTED = ("allow", "allow_restricted")
UNUSED_SHARE = 0.05  # recommend removing a group when fewer than 5% of its members used the app in 30 days


def caught_record(r: Record) -> bool:
    return r.final == "deny"


def planted_results(g: Gate) -> list[dict]:
    by: dict[str, list[Record]] = defaultdict(list)
    for r in g.records:
        if r.planted:
            by[r.planted].append(r)
    revs: dict[str, list] = defaultdict(list)
    for v in g.revocations:
        if v.planted:
            revs[v.planted].append(v)
    out = []
    for pid, p in g.data.planted.items():
        recs = by.get(pid, [])
        row = {"id": pid, "kind": p.kind, "title": p.title, "detail": p.detail, "user": p.user,
               "requests": len(recs), "outcomes": dict(Counter(r.outcome for r in recs))}
        if p.kind in ("posture_drift", "risk_spike"):
            row["revoked"] = len(revs.get(pid, []))
            row["caught"] = row["revoked"] > 0
            row["caught_by"] = ["continuous evaluation"] if row["caught"] else []
            row["evidence"] = [v.reason for v in revs.get(pid, [])][:3]
        else:
            # Password failures in a stuffing burst are denied by the identity provider. What matters is every
            # request that got past the password.
            judged = [r for r in recs if not r.inputs.auth_failed] or recs
            row["caught"] = bool(judged) and all(caught_record(r) for r in judged)
            checks = Counter()
            for r in judged:
                for t in g.trace(r):
                    if t["result"] in ("deny", "step_up"):
                        checks[t["check"]] += 1
            row["caught_by"] = [c for c, _ in checks.most_common()]
            row["past_password"] = len(judged)
            row["stepup_failed"] = sum(1 for r in judged if r.stepup == "failed")
            # Attacker devices are never in the inventory, so device trust fails on most events. Lead with the
            # more specific evidence.
            ev = list(dict.fromkeys(x for r in judged for x in r.reasons))
            row["evidence"] = sorted(ev, key=lambda x: x.startswith("device_trust"))[:3]
            row["records"] = [r.id for r in judged][:10]
        out.append(row)
    return out


def friction(g: Gate) -> dict:
    """Legitimate, entitled requests that were denied (false denies) or asked to step up (friction)."""
    legit = [r for r in g.records if r.legit and r.entitled and not r.inputs.auth_failed and r.source == "log"]
    denied = [r for r in legit if r.final == "deny"]
    stepped = [r for r in legit if r.outcome == "step_up"]
    restricted = [r for r in legit if r.final == "allow_restricted"]
    reasons = Counter(r.reasons[0].split(":")[0] if r.reasons else "other" for r in denied)
    n = len(legit) or 1
    return {
        "legit_requests": len(legit),
        "false_denies": len(denied),
        "false_deny_rate": round(len(denied) / n, 5),
        "step_ups": len(stepped),
        "step_up_rate": round(len(stepped) / n, 5),
        "step_up_passed": sum(1 for r in stepped if r.stepup == "passed"),
        "read_only": len(restricted),
        "false_deny_by_check": dict(reasons.most_common()),
        "users_with_a_false_deny": len({r.user for r in denied}),
    }


def by_app(g: Gate) -> list[dict]:
    c: dict[str, Counter] = defaultdict(Counter)
    for r in g.records:
        c[r.app][r.outcome] += 1
    rows = []
    for app in g.data.apps:
        k = c.get(app, Counter())
        total = sum(k.values())
        rows.append({"app": app, "sensitivity": g.data.apps[app].sensitivity, "total": total,
                     **{o: k.get(o, 0) for o in OUTCOMES},
                     "step_up_rate": round(k.get("step_up", 0) / total, 4) if total else 0.0,
                     "deny_rate": round(k.get("deny", 0) / total, 4) if total else 0.0})
    return rows


def daily(g: Gate) -> list[dict]:
    c: dict[str, Counter] = defaultdict(Counter)
    for r in g.records:
        c[r.ts.date().isoformat()][r.outcome] += 1
    return [{"day": d, **{o: c[d].get(o, 0) for o in OUTCOMES}} for d in sorted(c)]


def least_privilege(g: Gate, share: float = UNUSED_SHARE) -> list[dict]:
    used: dict[str, set] = defaultdict(set)
    for r in g.records:
        if r.final in GRANTED and r.legit:
            used[r.app].add(r.user)
    recs = []
    for app, p in g.policies.items():
        sens = g.data.apps[app].sensitivity if app in g.data.apps else p.sensitivity
        if sens not in ("high", "critical"):
            continue
        for grp in p.allow_groups:
            members = set(g.data.groups[grp].members) if grp in g.data.groups else set()
            if len(members) < 3:
                continue
            active = members & used[app]
            if len(active) / len(members) < share:
                other = [x for x in p.allow_groups if x != grp]
                keep = {m for m in active if any(x in g.data.users[m].groups for x in other)}
                recs.append({
                    "app": app, "sensitivity": sens, "group": grp, "members": len(members), "active": len(active),
                    "active_share": round(len(active) / len(members), 4),
                    "still_covered": len(keep),
                    "recommendation": f"remove {grp} from {app}: {len(active)} of {len(members)} members used it in "
                                      f"30 days" + (f", and {len(keep)} of those keep access through another group"
                                                    if active else ""),
                })
    recs.sort(key=lambda r: ({"critical": 0, "high": 1}[r["sensitivity"]], -r["members"]))
    return recs


def summary(g: Gate, max_false_deny_rate: float = 0.02) -> dict:
    planted = planted_results(g)
    f = friction(g)
    return {
        "company": g.data.company,
        "start": g.data.start.isoformat(),
        "as_of": g.data.as_of.isoformat(),
        "users": len(g.data.users),
        "contractors": sum(1 for u in g.data.users.values() if u.kind == "contractor"),
        "groups": len(g.data.groups),
        "apps": len(g.data.apps),
        "devices": len(g.data.devices),
        "decisions": len(g.records),
        "outcomes": dict(Counter(r.outcome for r in g.records)),
        "final": dict(Counter(r.final for r in g.records)),
        "planted": planted,
        "planted_caught": sum(1 for p in planted if p["caught"]),
        "friction": f,
        "by_app": by_app(g),
        "daily": daily(g),
        "least_privilege": least_privilege(g),
        "revocations": len(g.revocations),
        "gate": gate_result(planted, f, max_false_deny_rate),
    }


def gate_result(planted: list[dict], f: dict, max_false_deny_rate: float) -> dict:
    missed = [p["id"] for p in planted if not p["caught"]]
    ok = not missed and f["false_deny_rate"] <= max_false_deny_rate
    return {"pass": ok, "missed": missed, "false_deny_rate": f["false_deny_rate"],
            "max_false_deny_rate": max_false_deny_rate}


# ---------------------------------------------------------------- policy diff


def diff(g: Gate, new: Policy, sample: int = 50) -> dict:
    """Re-evaluate every logged request for the app against a draft policy and report what would change."""
    app = new.app
    old = g.policies.get(app)
    trans: Counter = Counter()
    rows = {"newly_allowed": [], "newly_denied": [], "newly_stepped_up": [], "other": []}
    counts = Counter()
    planted_hit: set[str] = set()
    users: dict[str, set] = defaultdict(set)
    total = 0
    for r in g.records:
        if r.app != app:
            continue
        total += 1
        after = evaluate(new, r.inputs)
        before = r.outcome
        if after.outcome == before:
            continue
        trans[(before, after.outcome)] += 1
        if after.outcome in GRANTED and before not in GRANTED:
            kind = "newly_allowed"
        elif after.outcome == "deny":
            kind = "newly_denied"
        elif after.outcome == "step_up":
            kind = "newly_stepped_up"
        else:
            kind = "other"
        counts[kind] += 1
        users[kind].add(r.user)
        if r.planted:
            planted_hit.add(r.planted)
        if len(rows[kind]) < sample:
            rows[kind].append({**r.to_dict(), "before": before, "after": after.outcome,
                               "why": after.reasons[:2] if after.reasons else r.reasons[:1]})
    newly_allowed_planted = sorted({r.planted for r in g.records if r.app == app and r.planted in planted_hit
                                    and r.outcome not in GRANTED and evaluate(new, r.inputs).outcome in GRANTED})
    return {
        "app": app,
        "requests": total,
        "changed": sum(trans.values()),
        "counts": {k: counts.get(k, 0) for k in rows},
        "users": {k: len(v) for k, v in users.items()},
        "transitions": [{"before": a, "after": b, "count": n} for (a, b), n in trans.most_common()],
        "planted_newly_allowed": newly_allowed_planted,
        "samples": rows,
        "old_policy": old.to_dict() if old else None,
        "new_policy": new.to_dict(),
    }
