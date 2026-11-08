"""User risk scoring. Each component adds points with a plain-English reason; the total is capped at 100.

The engine keeps a little state per user and per IP (recent failures, known devices and countries, last successful
location) so it can be replayed over a log in time order, the same way it would run online.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .geo import UNKNOWN, City, locate, travel

POINTS = {
    "failed_logins": 6,  # per failure in the last hour, up to 30
    "failed_logins_max": 30,
    "unregistered_device": 25,
    "first_use_device": 5,
    "impossible_travel": 50,
    "new_country": 10,
    "threat_intel": 40,
    "ip_velocity": 45,
}
IP_VELOCITY_WINDOW = timedelta(minutes=15)
IP_VELOCITY_ACCOUNTS = 10  # failures against this many distinct accounts from one IP looks like credential stuffing
FAILED_WINDOW = timedelta(hours=1)
BANDS = [(30, "low"), (60, "medium"), (101, "high")]


def band(score: int) -> str:
    for limit, name in BANDS:
        if score < limit:
            return name
    return "high"


@dataclass
class RiskScore:
    score: int
    band: str
    components: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": self.score, "band": self.band, "components": self.components}


@dataclass
class Context:
    """Request context the risk engine and the policy need beyond identity and device."""

    ip: str
    city: City
    local_hour: float


def context_for(ip: str, ts: datetime) -> Context:
    city = locate(ip)
    local = ts + timedelta(hours=city.tz)
    return Context(ip, city, local.hour + local.minute / 60)


class RiskEngine:
    def __init__(self, threat_intel: dict[str, str] | None = None):
        self.threat_intel = dict(threat_intel or {})
        self.user_failures: dict[str, deque] = defaultdict(deque)
        self.ip_failures: dict[str, deque] = defaultdict(deque)
        self.known_devices: dict[str, set] = defaultdict(set)
        self.known_countries: dict[str, set] = defaultdict(set)
        self.last_seen: dict[str, tuple[datetime, City]] = {}
        self.events: dict[str, list[tuple[datetime, datetime, int, str]]] = defaultdict(list)

    # ----- state updates -----
    def seed(self, user: str, devices: list[str], country: str) -> None:
        self.known_devices[user].update(devices)
        self.known_countries[user].add(country)

    def record_failure(self, user: str, ip: str, ts: datetime) -> None:
        self.user_failures[user].append(ts)
        self.ip_failures[ip].append((ts, user))

    def record_success(self, user: str, device: str, ip: str, ts: datetime) -> None:
        city = locate(ip)
        self.known_devices[user].add(device)
        if city is not UNKNOWN:
            self.known_countries[user].add(city.country)
            self.last_seen[user] = (ts, city)

    def add_event(self, user: str, ts: datetime, points: int, reason: str, hours: float = 24) -> None:
        self.events[user].append((ts, ts + timedelta(hours=hours), points, reason))

    # ----- scoring -----
    def score(self, user: str, device: str, device_owner: str | None, ip: str, ts: datetime,
              city: City | None = None) -> RiskScore:
        """Score one request. `city` overrides IP geolocation (the simulator uses it)."""
        comps: list[dict] = []

        def add(name: str, points: int, detail: str) -> None:
            comps.append({"component": name, "points": points, "detail": detail})

        fails = self.user_failures[user]
        while fails and fails[0] < ts - FAILED_WINDOW * 24:
            fails.popleft()
        n = sum(1 for t in fails if ts - FAILED_WINDOW <= t <= ts)
        if n:
            add("failed_logins", min(POINTS["failed_logins_max"], POINTS["failed_logins"] * n),
                f"{n} failed sign-in{'s' if n > 1 else ''} in the last hour")

        if device not in self.known_devices[user]:
            if device_owner == user:
                add("new_device", POINTS["first_use_device"], "first use of a device registered to this user")
            else:
                add("new_device", POINTS["unregistered_device"],
                    "device is not registered to this user" if device_owner else "device is not in the inventory")

        city = city or locate(ip)
        last = self.last_seen.get(user)
        if last and city is not UNKNOWN and ts >= last[0]:
            minutes = (ts - last[0]).total_seconds() / 60
            km, kmh, impossible = travel(last[1], city, minutes)
            if impossible:
                add("impossible_travel", POINTS["impossible_travel"],
                    f"{last[1].name} to {city.name}: {km:,.0f} km in {minutes:.0f} min ({kmh:,.0f} km/h)")
        if city is not UNKNOWN and city.country not in self.known_countries[user]:
            add("new_country", POINTS["new_country"], f"first sign-in from {city.country}")

        if ip in self.threat_intel:
            add("threat_intel", POINTS["threat_intel"], f"{ip} is on the threat feed ({self.threat_intel[ip]})")

        ipf = self.ip_failures.get(ip)
        if ipf:
            while ipf and ipf[0][0] < ts - IP_VELOCITY_WINDOW * 8:
                ipf.popleft()
            accounts = {u for t, u in ipf if ts - IP_VELOCITY_WINDOW <= t <= ts}
            if len(accounts) >= IP_VELOCITY_ACCOUNTS:
                add("ip_velocity", POINTS["ip_velocity"],
                    f"{ip} failed sign-ins for {len(accounts)} accounts in the last 15 minutes")

        for start, end, points, reason in self.events.get(user, []):
            if start <= ts < end:
                add("signal", points, reason)

        total = min(100, sum(c["points"] for c in comps))
        return RiskScore(total, band(total), comps)
