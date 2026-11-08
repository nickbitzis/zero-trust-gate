"""Seeded synthetic organization for Tallowmere Systems, a made-up 800-person software company.

It builds people, groups, devices, and apps, then 30 days of access attempts with normal working patterns (sign-in in
the morning, SSO for the rest of the day, travel, late nights, personal phones, the odd typo) plus planted risky events
whose ground truth is known, so the evaluation can say whether policy caught each one.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .geo import CITY_BY_NAME, home_ip, hosting_ip, office_ip
from .model import App, Attempt, Device, Group, Planted, Signal, User
from .posture import trust_of

COMPANY = "Tallowmere Systems"
START = datetime(2026, 10, 1, tzinfo=UTC)
DAYS = 30
AS_OF = START + timedelta(days=DAYS - 1, hours=20)  # the log ends here; the service clock starts here

APPS: list[tuple[str, str, str, str, str]] = [
    # id, name, sensitivity, owner, description
    ("wiki", "Wiki", "low", "it", "Company wiki and handbooks"),
    ("intranet", "Intranet", "low", "it", "News, org chart, and benefits links"),
    ("it-helpdesk", "IT helpdesk", "low", "it", "Tickets for laptops, access, and accounts"),
    ("office-booking", "Office booking", "low", "it", "Desk and room booking"),
    ("design-library", "Design library", "low", "design", "Brand assets and UI kit"),
    ("expense", "Expenses", "medium", "finance", "Expense claims and receipts"),
    ("crm", "CRM", "medium", "sales", "Accounts, contacts, and pipeline"),
    ("customer-support", "Support desk", "medium", "support", "Customer tickets and chat"),
    ("marketing-analytics", "Marketing analytics", "medium", "marketing", "Campaign and web analytics"),
    ("ci-dashboard", "CI dashboard", "medium", "engineering", "Builds, test runs, and deploy history"),
    ("issue-tracker", "Issue tracker", "medium", "engineering", "Tickets and sprints"),
    ("feature-flags", "Feature flags", "medium", "engineering", "Flag rules for the product"),
    ("recruiting", "Recruiting", "medium", "hr", "Candidates and interview loops"),
    ("contract-repo", "Contract repository", "medium", "legal", "Signed customer and vendor contracts"),
    ("bi-dashboards", "BI dashboards", "medium", "data", "Business metrics dashboards"),
    ("status-admin", "Status page admin", "medium", "sre", "Incident posts on the public status page"),
    ("source-code", "Source code", "high", "engineering", "Git hosting and code review"),
    ("hr-system", "HR system", "high", "hr", "Employee records, reviews, and leave"),
    ("finance-reports", "Finance reports", "high", "finance", "Monthly close, forecasts, and board numbers"),
    ("data-warehouse", "Data warehouse", "high", "data", "Product and customer analytics tables"),
    ("customer-db-console", "Customer DB console", "high", "sre", "Read and fix customer records in production"),
    ("siem", "SIEM", "high", "security", "Security logs and detections"),
    ("legal-hold", "Legal hold", "high", "legal", "Preserved mailboxes and documents"),
    ("board-portal", "Board portal", "high", "exec", "Board decks and minutes"),
    ("secrets-vault", "Secrets vault", "critical", "security", "Service credentials and keys"),
    ("payroll", "Payroll", "critical", "hr", "Salaries, bank details, and pay runs"),
    ("prod-admin", "Production admin console", "critical", "sre", "Deploys, scaling, and feature kill switches"),
    ("billing-admin", "Billing admin", "critical", "finance", "Refunds, credits, and invoice changes"),
    ("identity-admin", "Identity admin", "critical", "it", "Users, groups, and MFA resets"),
    ("cloud-console", "Cloud console", "critical", "sre", "Cloud accounts and infrastructure"),
]

# Base daily usage for every employee, then department profiles. Values are the chance of using the app on a workday.
COMMON = {"wiki": 0.45, "intranet": 0.25, "expense": 0.04, "it-helpdesk": 0.03, "office-booking": 0.08}
DEPTS: dict[str, dict] = {
    "engineering": {"n": 210, "cities": {"San Francisco": 4, "New York": 1.5, "Austin": 1.5, "Berlin": 1.5,
                                         "Bangalore": 1.5},
                    "apps": {"source-code": 0.9, "ci-dashboard": 0.6, "issue-tracker": 0.75, "feature-flags": 0.2,
                             "design-library": 0.05},
                    "sub": [("oncall", 30, {"status-admin": 0.1})], "title": "Software Engineer"},
    "sre": {"n": 40, "cities": {"San Francisco": 2, "Austin": 1, "Dublin": 1},
            "apps": {"source-code": 0.6, "cloud-console": 0.6, "ci-dashboard": 0.5, "status-admin": 0.3,
                     "secrets-vault": 0.25, "customer-db-console": 0.08, "issue-tracker": 0.4},
            "sub": [("prod-admins", 15, {"prod-admin": 0.45}), ("oncall", 20, {})],
            "title": "Site Reliability Engineer"},
    "security": {"n": 16, "cities": {"San Francisco": 1, "London": 1},
                 "apps": {"siem": 0.9, "secrets-vault": 0.15, "source-code": 0.3, "issue-tracker": 0.3},
                 "sub": [("security-admins", 5, {"identity-admin": 0.3})], "title": "Security Engineer"},
    "it": {"n": 20, "cities": {"San Francisco": 1, "London": 1, "Bangalore": 1},
           "apps": {"it-helpdesk": 0.9, "issue-tracker": 0.2},
           "sub": [("it-admins", 8, {"identity-admin": 0.5})], "title": "IT Specialist"},
    "data": {"n": 30, "cities": {"San Francisco": 1, "New York": 1, "Berlin": 1},
             "apps": {"data-warehouse": 0.85, "bi-dashboards": 0.7, "source-code": 0.3, "issue-tracker": 0.3},
             "sub": [], "title": "Data Analyst"},
    "product": {"n": 40, "cities": {"San Francisco": 2, "New York": 1, "London": 1},
                "apps": {"issue-tracker": 0.85, "bi-dashboards": 0.35, "feature-flags": 0.25, "design-library": 0.25},
                "sub": [], "title": "Product Manager"},
    "design": {"n": 15, "cities": {"San Francisco": 1, "Berlin": 1},
               "apps": {"design-library": 0.9, "issue-tracker": 0.5}, "sub": [], "title": "Product Designer"},
    "finance": {"n": 35, "cities": {"San Francisco": 2, "New York": 1, "London": 1},
                "apps": {"finance-reports": 0.6, "expense": 0.4, "bi-dashboards": 0.3},
                "sub": [("finance-approvers", 6, {"billing-admin": 0.4})], "title": "Financial Analyst"},
    "hr": {"n": 25, "cities": {"San Francisco": 1, "London": 1, "Bangalore": 0.5},
           "apps": {"hr-system": 0.85, "recruiting": 0.55},
           "sub": [("payroll-admins", 6, {"payroll": 0.55})], "title": "People Partner"},
    "sales": {"n": 120, "cities": {"New York": 2, "Austin": 1, "Chicago": 1, "London": 1, "Berlin": 1},
              "apps": {"crm": 0.9, "contract-repo": 0.2, "customer-support": 0.15, "marketing-analytics": 0.08},
              "sub": [("sales-managers", 12, {})], "title": "Account Executive"},
    "support": {"n": 110, "cities": {"Austin": 2, "Dublin": 2, "Bangalore": 1},
                "apps": {"customer-support": 0.92, "crm": 0.35},
                "sub": [("support-tier2", 25, {"customer-db-console": 0.3})], "title": "Support Specialist"},
    "marketing": {"n": 45, "cities": {"New York": 1, "San Francisco": 1, "London": 1},
                  "apps": {"marketing-analytics": 0.8, "crm": 0.25, "design-library": 0.3}, "sub": [],
                  "title": "Marketing Manager"},
    "legal": {"n": 12, "cities": {"San Francisco": 1, "London": 1},
              "apps": {"contract-repo": 0.8, "legal-hold": 0.25, "board-portal": 0.08}, "sub": [], "title": "Counsel"},
    "exec": {"n": 10, "cities": {"San Francisco": 1, "New York": 0.5},
             "apps": {"board-portal": 0.35, "finance-reports": 0.35, "bi-dashboards": 0.45, "recruiting": 0.1},
             "sub": [], "title": "Executive"},
    "contractors-eng": {"n": 50, "cities": {"Bangalore": 3, "Toronto": 1, "Lisbon": 1}, "contractor": True,
                        "apps": {"source-code": 0.9, "ci-dashboard": 0.5, "issue-tracker": 0.7}, "sub": [],
                        "title": "Contract Engineer"},
    "contractors-support": {"n": 22, "cities": {"Lisbon": 1, "Dublin": 1}, "contractor": True,
                            "apps": {"customer-support": 0.9}, "sub": [], "title": "Contract Support Agent"},
}
# Share of requests per app that are writes, exports, or admin actions. Everything else is a read.
ACTION_MIX = {
    "crm": (0.3, 0.02, 0), "customer-support": (0.5, 0, 0), "issue-tracker": (0.4, 0, 0), "source-code": (0.3, 0, 0.01),
    "expense": (0.5, 0, 0), "hr-system": (0.2, 0.03, 0), "payroll": (0.25, 0.05, 0), "prod-admin": (0.35, 0, 0.05),
    "billing-admin": (0.35, 0.05, 0), "finance-reports": (0.05, 0.1, 0), "data-warehouse": (0.05, 0.08, 0),
    "feature-flags": (0.3, 0, 0), "recruiting": (0.3, 0, 0), "contract-repo": (0.1, 0.05, 0),
    "identity-admin": (0.3, 0, 0.2), "cloud-console": (0.3, 0, 0.05), "secrets-vault": (0.1, 0, 0.02),
    "customer-db-console": (0.2, 0.02, 0), "status-admin": (0.5, 0, 0), "siem": (0.05, 0.05, 0),
    "legal-hold": (0.2, 0.05, 0), "wiki": (0.1, 0, 0), "design-library": (0.1, 0.1, 0), "office-booking": (0.6, 0, 0),
    "it-helpdesk": (0.5, 0, 0),
}
FIRST = ["Ada", "Ben", "Chen", "Dara", "Eli", "Femi", "Gia", "Hugo", "Ines", "Jon", "Kai", "Lena", "Milo", "Nia",
         "Omar", "Priya", "Quinn", "Rosa", "Sami", "Tara", "Uma", "Viktor", "Wen", "Xavi", "Yara", "Zane", "Arjun",
         "Bea", "Cyrus", "Dev", "Esme", "Farid", "Greta", "Hana", "Ivo", "Jade", "Kofi", "Luca", "Maya", "Nils"]
LAST = ["Abara", "Brandt", "Castell", "Dorsey", "Ekwueme", "Falk", "Gallo", "Hart", "Ishii", "Jovic", "Kaur", "Lund",
        "Moreau", "Nakata", "Okafor", "Petrov", "Quist", "Rahman", "Sato", "Thorne", "Ueda", "Varga", "Weiss", "Xu",
        "Yilmaz", "Zielinski", "Amari", "Bauer", "Costa", "Duarte", "Engel", "Fonseca", "Grieg", "Holm", "Iqbal"]


@dataclass
class Dataset:
    company: str
    start: datetime
    as_of: datetime
    users: dict[str, User]
    groups: dict[str, Group]
    apps: dict[str, App]
    devices: dict[str, Device]
    attempts: list[Attempt]
    signals: list[Signal]
    planted: dict[str, Planted]
    threat_intel: dict[str, str]
    usage: dict[str, dict[str, float]] = field(default_factory=dict)  # user -> app -> daily probability

    def devices_of(self, user: str) -> list[Device]:
        return [d for d in self.devices.values() if d.owner == user]


def _pick(rng: random.Random, weights: dict[str, float]) -> str:
    return rng.choices(list(weights), list(weights.values()))[0]


def _laptop(rng: random.Random, did: str, owner: str, managed: bool = True) -> Device:
    os_name = rng.choices(["macOS", "Windows", "Ubuntu"], [70, 25, 5])[0]
    ver = {"macOS": "15.6", "Windows": "11 24H2", "Ubuntu": "24.04"}[os_name]
    if managed:
        age = rng.choices([rng.randint(0, 30), rng.randint(31, 60), rng.randint(61, 85)], [95, 4.4, 0.6])[0]
    else:
        age = rng.choices([rng.randint(0, 30), rng.randint(31, 90)], [70, 30])[0]
    return Device(did, owner, "laptop", os_name, ver, age, managed,
                  disk_encrypted=managed or rng.random() < 0.85, edr_running=managed and rng.random() < 0.995,
                  screen_lock=managed or rng.random() < 0.9, os_supported=rng.random() < 0.995)


def _phone(rng: random.Random, did: str, owner: str, managed: bool) -> Device:
    os_name = rng.choice(["iOS", "Android"])
    ver = {"iOS": "26.1", "Android": "16"}[os_name]
    age = rng.randint(0, 30) if managed else rng.choices([rng.randint(0, 30), rng.randint(31, 75)], [75, 25])[0]
    return Device(did, owner, "phone", os_name, ver, age, managed, disk_encrypted=True,
                  edr_running=managed, screen_lock=managed or rng.random() < 0.92)


def build_org(rng: random.Random):
    users: dict[str, User] = {}
    groups: dict[str, Group] = {
        "all-employees": Group("all-employees", "Every employee"),
        "contractors": Group("contractors", "Every contractor"),
    }
    devices: dict[str, Device] = {}
    usage: dict[str, dict[str, float]] = {}
    used_names: set[str] = set()
    n = 0
    for dept, spec in DEPTS.items():
        groups.setdefault(dept, Group(dept, f"{dept.replace('-', ' ').capitalize()} department"))
        members: list[str] = []
        for _ in range(spec["n"]):
            n += 1
            while True:
                first, last = rng.choice(FIRST), rng.choice(LAST)
                handle = f"{first.lower()}.{last.lower()}"
                if handle not in used_names:
                    used_names.add(handle)
                    break
            uid = f"u{n:04d}"
            contractor = spec.get("contractor", False)
            end = START + timedelta(days=rng.randint(120, 400)) if contractor else None
            u = User(uid, f"{first} {last}", f"{handle}@tallowmere.example", "contractor" if contractor else "employee",
                     dept, spec["title"], _pick(rng, spec["cities"]),
                     [dept, "contractors" if contractor else "all-employees"], end)
            users[uid] = u
            members.append(uid)
            profile = dict(spec["apps"])
            for app, p in COMMON.items():
                if contractor and app not in ("wiki",):
                    continue
                profile[app] = max(profile.get(app, 0), p * (0.6 if contractor else 1))
            usage[uid] = profile
            devices[f"lt-{uid}"] = _laptop(rng, f"lt-{uid}", uid)
            if not contractor and rng.random() < 0.6:
                did = f"ph-{uid}"
                devices[did] = _phone(rng, did, uid, managed=rng.random() < 0.7)
            if not contractor and rng.random() < 0.04:
                did = f"pl-{uid}"
                devices[did] = _laptop(rng, did, uid, managed=False)
        for sub, k, extra in spec["sub"]:
            groups.setdefault(sub, Group(sub, f"{sub.replace('-', ' ').capitalize()}"))
            for uid in rng.sample(members, k):
                users[uid].groups.append(sub)
                usage[uid].update(extra)
    for u in users.values():
        for g in u.groups:
            groups[g].members.append(u.id)
    return users, groups, devices, usage


def _day_window(rng: random.Random, tz: float) -> tuple[float, float]:
    start = rng.gauss(9.0, 0.8)
    return start, start + rng.uniform(7.5, 9.5)


def _local_to_utc(day: datetime, local_hour: float, tz: float) -> datetime:
    return day + timedelta(hours=local_hour - tz)


def generate(seed: int = 7) -> Dataset:
    rng = random.Random(seed)
    users, groups, devices, usage = build_org(rng)
    apps = {a[0]: App(*a) for a in APPS}
    attempts: list[Attempt] = []
    signals: list[Signal] = []
    planted: dict[str, Planted] = {}

    # Threat feed: anonymizer and proxy exits. Eight legitimate staff use a commercial VPN with an exit on the list.
    threat_intel: dict[str, str] = {}
    for city in ("Amsterdam", "Bucharest", "Jakarta", "Sao Paulo", "Singapore", "Lisbon"):
        for k in range(6):
            threat_intel[hosting_ip(city, k, anonymizer=True)] = rng.choice(
                ["anonymizer exit", "residential proxy network", "known botnet node"])
    vpn_users = set(rng.sample([u for u in users if users[u].kind == "employee"], 8))
    travellers = {u: rng.choice(["London", "New York", "San Francisco", "Berlin"])
                  for u in rng.sample(sorted(users), 24)}
    late_workers = set(rng.sample(sorted(users), 60))

    def add(ts, user, app, action, device, ip, **kw) -> Attempt:
        a = Attempt(0, ts, user, app, action, device, ip, **kw)
        attempts.append(a)
        return a

    def action_for(app: str) -> str:
        w, e, ad = ACTION_MIX.get(app, (0.05, 0, 0))
        r = rng.random()
        return "write" if r < w else "export" if r < w + e else "admin" if r < w + e + ad else "read"

    # ---------------- normal activity
    for uid, u in users.items():
        city = CITY_BY_NAME[u.city]
        devs = [d for d in (devices.get(f"lt-{uid}"), devices.get(f"ph-{uid}"), devices.get(f"pl-{uid}")) if d]
        laptop = devs[0]
        others = devs[1:]
        home = home_ip(u.city, int(uid[1:]))
        trip_day = rng.randint(5, 22) if uid in travellers else None
        for day_i in range(DAYS):
            day = START + timedelta(days=day_i)
            weekend = day.weekday() >= 5
            if rng.random() > (0.07 if weekend else 0.92):
                continue
            where, tz_city = u.city, city
            if trip_day is not None and trip_day <= day_i < trip_day + 4:
                where = travellers[uid] if travellers[uid] != u.city else "Toronto"
                tz_city = CITY_BY_NAME[where]
            s, e = _day_window(rng, tz_city.tz)
            if uid in late_workers and rng.random() < 0.08:
                e = rng.uniform(22.2, 23.9)
            remote = weekend or rng.random() < 0.35 or where != u.city
            if uid in vpn_users and rng.random() < 0.25:
                ip = rng.choice(list(threat_intel)[:12])
            elif remote:
                ip = home_ip(where, int(uid[1:]) + (0 if where == u.city else 97))
            else:
                ip = office_ip(where, int(uid[1:]))
            if weekend:
                ip = home
            events: list[tuple[float, str, str]] = []
            for app, p in usage[uid].items():
                if weekend:
                    p *= 0.3
                if rng.random() < p:
                    for _ in range(1 + (rng.random() < 0.3)):
                        events.append((rng.uniform(s, e), app, action_for(app)))
            # Occasional request to an app outside the person's job: an old bookmark or a link in a chat.
            if rng.random() < 0.015:
                app = rng.choice([a for a in apps if a not in usage[uid]])
                events.append((rng.uniform(s, e), app, "read"))
            if not events:
                continue
            events.sort()
            signed_in: set[str] = set()
            for h, app, action in events:
                dev = laptop
                if others and apps[app].sensitivity in ("low", "medium") and rng.random() < 0.15:
                    dev = rng.choice(others)
                    if not dev.managed and action != "read" and rng.random() < 0.8:
                        action = "read"
                ts = _local_to_utc(day, h, tz_city.tz)
                if ts >= AS_OF:
                    continue
                if dev.id not in signed_in:
                    if rng.random() < 0.02:
                        add(ts - timedelta(seconds=40), uid, app, action, dev.id, ip, fresh_auth=True,
                            password_ok=False)
                    add(ts, uid, app, action, dev.id, ip, fresh_auth=True)
                    signed_in.add(dev.id)
                else:
                    add(ts, uid, app, action, dev.id, ip, token_device=dev.id)

    # ---------------- planted risky events
    def pick(dept: str, need_group: str | None = None, exclude: set | None = None) -> User:
        pool = [u for u in users.values() if u.department == dept and (need_group is None or need_group in u.groups)
                and u.id not in (exclude or set()) and u.id not in travellers and u.id not in vpn_users
                and trust_of(devices[f"lt-{u.id}"]).level == "high"]
        return rng.choice(sorted(pool, key=lambda x: x.id))

    def plant(pid: str, kind: str, title: str, detail: str, user: User) -> None:
        planted[pid] = Planted(pid, kind, title, detail, user.id)

    chosen: set[str] = set()

    def victim(dept: str, group: str | None = None) -> User:
        u = pick(dept, group, chosen)
        chosen.add(u.id)
        return u

    def at(day: int, utc_hour: float) -> datetime:
        return START + timedelta(days=day, hours=utc_hour)

    # 1. Impossible travel: valid password and an MFA push approved by a tired user, from another continent.
    for i, (dept, app, where, gap, day) in enumerate(
        [("finance", "finance-reports", "London", 55, 8), ("engineering", "source-code", "Singapore", 40, 16)]
    ):
        u = victim(dept)
        t0 = at(day, 17.0 - CITY_BY_NAME[u.city].tz)  # 17:00 local at home
        ip_home = office_ip(u.city, int(u.id[1:]))
        add(t0, u.id, app, "read", f"lt-{u.id}", ip_home, fresh_auth=True)
        evil = hosting_ip(where, 3 + i)
        pid = f"P{i + 1}"
        a = add(t0 + timedelta(minutes=gap), u.id, app, "export" if dept == "finance" else "read", f"x-attk-{i}", evil,
                fresh_auth=True, stepup_capable=False, planted=pid)
        km = CITY_BY_NAME[u.city]
        plant(pid, "impossible_travel", f"Impossible travel: {km.name} to {where} in {gap} min",
              f"{u.name} signs in from {km.name}, then the same account signs in from {where} {gap} minutes later "
              f"and asks for {app}.", u)
        del a

    # 2. Stolen session cookie replayed from a new device.
    for i, (dept, app, where, day) in enumerate([("sales", "crm", "Bucharest", 11), ("support", "customer-support",
                                                                                     "Jakarta", 21)]):
        u = victim(dept)
        tz = CITY_BY_NAME[u.city].tz
        t0 = at(day, 10.0 - tz)
        ip = office_ip(u.city, int(u.id[1:]))
        add(t0, u.id, app, "read", f"lt-{u.id}", ip, fresh_auth=True)
        pid = f"P{3 + i}"
        for k in range(3):
            add(t0 + timedelta(minutes=35 + k * 4), u.id, app, ["read", "export", "write"][k], f"x-replay-{i}",
                hosting_ip(where, 6 + i), token_device=f"lt-{u.id}", stepup_capable=False, planted=pid)
        plant(pid, "stolen_session", f"Session cookie replayed from {where}",
              f"An infostealer copies {u.name}'s SSO cookie. 35 minutes later it is replayed from a new device in "
              f"{where}, with the victim's fresh MFA claim still inside.", u)

    # 3. Contractor accessing apps after the contract ended (the offboarding ticket was never closed).
    for i, (dept, app, end_day, days_after) in enumerate([("contractors-eng", "source-code", 17, (2, 5, 9)),
                                                          ("contractors-support", "customer-support", 20, (3, 6))]):
        u = victim(dept)
        u.contract_end = START + timedelta(days=end_day)
        tz = CITY_BY_NAME[u.city].tz
        pid = f"P{5 + i}"
        # Their normal activity stops at the end date, apart from these requests.
        attempts[:] = [a for a in attempts if not (a.user == u.id and a.ts >= u.contract_end)]
        for k, d in enumerate(days_after):
            ts = at(end_day + d, 11 + k - tz)
            add(ts, u.id, app, "read" if k else "export", f"lt-{u.id}", home_ip(u.city, int(u.id[1:])),
                fresh_auth=True, stepup_capable=True, planted=pid)
        plant(pid, "contractor_after_end", f"Contractor active {days_after[0]} days after contract end",
              f"{u.name}'s contract ended on {u.contract_end.date()}, but the account still works. "
              f"{len(days_after)} requests to {app} follow.", u)

    # 4. Unpatched laptop: four months without patches, OS out of support.
    for i, (dept, app, group, day) in enumerate([("engineering", "source-code", None, 13),
                                                 ("sre", "prod-admin", "prod-admins", 24)]):
        u = victim(dept, group)
        d = devices[f"lt-{u.id}"]
        d.patch_age_days, d.os_supported = 143 + 20 * i, False
        d.os_version = {"macOS": "13.2", "Windows": "10 21H2", "Ubuntu": "20.04"}[d.os]
        # Only the planted requests come from this laptop, so its other traffic does not blur the friction metric.
        attempts[:] = [a for a in attempts if a.device != d.id]
        tz = CITY_BY_NAME[u.city].tz
        pid = f"P{7 + i}"
        add(at(day, 9.5 - tz), u.id, app, "read", d.id, office_ip(u.city, int(u.id[1:])), fresh_auth=True,
            planted=pid)
        add(at(day, 9.7 - tz), u.id, app, "write", d.id, office_ip(u.city, int(u.id[1:])), token_device=d.id,
            planted=pid)
        plant(pid, "unpatched_device", f"Unpatched laptop ({d.patch_age_days} days) on {app}",
              f"{u.name}'s laptop missed patches for {d.patch_age_days} days and runs {d.os} {d.os_version}, "
              f"which is out of support. It asks for {app}.", u)

    # 5. Unusual hours: a payroll admin's account used at 03:10 local from home, then a 02:40 export.
    for i, (dept, group, app, hour, action, day) in enumerate([("hr", "payroll-admins", "payroll", 3.17, "write", 14),
                                                               ("finance", "finance-approvers", "billing-admin", 2.67,
                                                                "export", 26)]):
        u = victim(dept, group)
        tz = CITY_BY_NAME[u.city].tz
        pid = f"P{9 + i}"
        add(at(day, hour - tz), u.id, app, action, f"lt-{u.id}", home_ip(u.city, int(u.id[1:])),
            token_device=f"lt-{u.id}", stepup_capable=False, planted=pid)
        plant(pid, "unusual_hours", f"{app} {action} at {int(hour):02d}:{int(hour % 1 * 60):02d} local",
              f"{u.name}'s laptop, left unlocked at home, is used for a {app} {action} in the middle of the night. "
              "Password and MFA come from the saved browser session.", u)

    # 6. Credential stuffing: 70 accounts tried from one host in 12 minutes, three passwords work.
    pid = "P11"
    burst_ip = hosting_ip("Amsterdam", 9)
    t0 = at(19, 2.0)
    targets = rng.sample(sorted(u for u in users if u not in chosen), 70)
    for k, uid in enumerate(targets):
        add(t0 + timedelta(seconds=10 * k), uid, "wiki", "read", "x-stuffer", burst_ip, fresh_auth=True,
            password_ok=False, stepup_capable=False, planted=pid)
    for k, uid in enumerate(targets[-3:]):
        add(t0 + timedelta(seconds=10 * 70 + 20 * k), uid, ["wiki", "crm", "expense"][k], "read", "x-stuffer",
            burst_ip, fresh_auth=True, stepup_capable=False, planted=pid)
    planted[pid] = Planted(pid, "credential_stuffing", "Credential stuffing burst, 70 accounts in 12 min",
                           "One host in Amsterdam tries leaked passwords against 70 accounts. Three passwords work "
                           "and those sessions ask for apps.", targets[-1])

    # 7. Continuous evaluation: posture falls out of compliance and risk spikes in the middle of live sessions.
    u = victim("sre", "prod-admins")
    tz = CITY_BY_NAME[u.city].tz
    d = f"lt-{u.id}"
    ip = office_ip(u.city, int(u.id[1:]))
    t = at(27, 14.0 - tz)
    attempts[:] = [a for a in attempts if not (a.user == u.id and a.ts.date() == t.date())]
    add(t, u.id, "prod-admin", "read", d, ip, fresh_auth=True)
    add(t + timedelta(minutes=5), u.id, "cloud-console", "read", d, ip, token_device=d)
    pid = "P12"
    signals.append(Signal(t + timedelta(minutes=20), "device_posture", d, {"edr_running": False},
                          "EDR agent stopped reporting", planted=pid))
    signals.append(Signal(at(28, 7.0 - tz), "device_posture", d, {"edr_running": True}, "EDR agent restarted by IT"))
    plant(pid, "posture_drift", "EDR stops during a production session",
          f"20 minutes into {u.name}'s prod-admin and cloud-console sessions, the EDR agent on the laptop stops "
          "reporting. Continuous evaluation should end both sessions.", u)

    u = victim("finance", "finance-approvers")
    tz = CITY_BY_NAME[u.city].tz
    d = f"lt-{u.id}"
    ip = office_ip(u.city, int(u.id[1:]))
    t = at(22, 15.0 - tz)
    attempts[:] = [a for a in attempts if not (a.user == u.id and a.ts.date() == t.date())]
    add(t, u.id, "billing-admin", "read", d, ip, fresh_auth=True)
    add(t + timedelta(minutes=3), u.id, "finance-reports", "read", d, ip, token_device=d)
    pid = "P13"
    signals.append(Signal(t + timedelta(minutes=12), "user_risk", u.id,
                          {"points": 45, "hours": 3, "reason": "14 MFA pushes denied in 10 minutes (MFA fatigue)"},
                          "MFA fatigue pattern at the identity provider", planted=pid))
    plant(pid, "risk_spike", "MFA fatigue attack while sessions are open",
          f"Someone with {u.name}'s password floods the phone with MFA pushes. The identity provider raises user "
          "risk, and the open billing-admin session should be revoked.", u)

    attempts.sort(key=lambda a: (a.ts, a.user))
    for i, a in enumerate(attempts, 1):
        a.id = i
    signals.sort(key=lambda s: s.ts)
    return Dataset(COMPANY, START, AS_OF, users, groups, apps, devices, attempts, signals, planted, threat_intel,
                   usage)
