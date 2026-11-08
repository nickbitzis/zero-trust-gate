"""Domain model: people, groups, apps, devices, access attempts, and posture or risk signals."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

SENSITIVITIES = ["low", "medium", "high", "critical"]
TRUST_LEVELS = ["untrusted", "low", "medium", "high"]
OUTCOMES = ["allow", "allow_restricted", "step_up", "deny"]


@dataclass
class User:
    id: str
    name: str
    email: str
    kind: str  # employee | contractor
    department: str
    title: str
    city: str
    groups: list[str]
    contract_end: datetime | None = None
    disabled: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["contract_end"] = self.contract_end.isoformat() if self.contract_end else None
        return d


@dataclass
class Group:
    name: str
    description: str
    members: list[str] = field(default_factory=list)


@dataclass
class App:
    id: str
    name: str
    sensitivity: str
    owner: str
    description: str


@dataclass
class Device:
    id: str
    owner: str
    kind: str  # laptop | phone
    os: str
    os_version: str
    patch_age_days: int
    managed: bool
    disk_encrypted: bool
    edr_running: bool
    screen_lock: bool
    os_supported: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Attempt:
    """One request to an app. `fresh_auth` means the user signed in with a password and MFA just now; otherwise the
    request rides an existing SSO session bound to `token_device`."""

    id: int
    ts: datetime
    user: str
    app: str
    action: str  # read | write | export | admin
    device: str
    ip: str
    fresh_auth: bool = False
    password_ok: bool = True
    token_device: str | None = None
    stepup_capable: bool = True  # a real user can answer an MFA challenge; most attackers cannot
    planted: str | None = None  # id of the planted risky event this attempt belongs to


@dataclass
class Signal:
    """A change in posture or risk that arrives between requests and triggers continuous evaluation."""

    ts: datetime
    kind: str  # device_posture | user_risk
    target: str  # device id or user id
    changes: dict
    reason: str
    planted: str | None = None


@dataclass
class Planted:
    id: str
    kind: str
    title: str
    detail: str
    user: str
