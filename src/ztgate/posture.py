"""Device trust levels from posture signals.

Each signal that fails caps the device at a level. The device's trust is the lowest cap, and every signal is reported
so the decision trace can say exactly why a laptop is "medium" and not "high".
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from .model import TRUST_LEVELS, Device

PATCH_MEDIUM_DAYS = 30  # older than this caps the device at medium
PATCH_LOW_DAYS = 90  # older than this caps it at low
PATCH_UNTRUSTED_DAYS = 180


@dataclass
class DeviceTrust:
    level: str
    signals: list[dict]

    def to_dict(self) -> dict:
        return {"level": self.level, "signals": self.signals}


def rank(level: str) -> int:
    return TRUST_LEVELS.index(level)


def trust_of(device: Device | None) -> DeviceTrust:
    """Trust level and per-signal explanation. Cached on the posture values, so a posture change is seen at once."""
    t = trust_cached(device)
    return DeviceTrust(t.level, [dict(s) for s in t.signals])


def trust_cached(device: Device | None) -> DeviceTrust:
    """The shared cached result. Callers must not modify it."""
    return _trust(tuple(device.__dict__.values()) if device else None)


@lru_cache(maxsize=8192)
def _trust(key: tuple | None) -> DeviceTrust:
    device = Device(*key) if key else None
    if device is None:
        return DeviceTrust("untrusted", [{"signal": "inventory", "ok": False, "cap": "untrusted",
                                          "detail": "device is not in the inventory"}])
    sig: list[dict] = []

    def check(name: str, ok: bool, cap: str, detail: str) -> None:
        sig.append({"signal": name, "ok": ok, "cap": None if ok else cap, "detail": detail})

    check("managed", device.managed, "low", "enrolled in MDM" if device.managed else "personal device, not in MDM")
    check("disk_encryption", device.disk_encrypted, "low" if device.managed else "untrusted",
          "disk encrypted" if device.disk_encrypted else "disk not encrypted")
    check("screen_lock", device.screen_lock, "low", "screen lock on" if device.screen_lock else "no screen lock")
    if device.managed:
        check("edr", device.edr_running, "low", "EDR agent running" if device.edr_running else "EDR agent not running")
    age = device.patch_age_days
    if age > PATCH_UNTRUSTED_DAYS:
        cap = "untrusted"
    elif age > PATCH_LOW_DAYS:
        cap = "low"
    else:
        cap = "medium"
    check("patch_age", age <= PATCH_MEDIUM_DAYS, cap, f"last OS patch {age} days ago (limit {PATCH_MEDIUM_DAYS})")
    check("os_version", device.os_supported, "low",
          f"{device.os} {device.os_version} " + ("is supported" if device.os_supported else "is out of support"))
    caps = [s["cap"] for s in sig if s["cap"]]
    level = min(caps, key=rank) if caps else "high"
    return DeviceTrust(level, sig)
