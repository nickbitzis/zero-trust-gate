from datetime import UTC, datetime, timedelta

import pytest

from ztgate.geo import CITY_BY_NAME, UNKNOWN, haversine_km, home_ip, hosting_ip, locate, office_ip, travel
from ztgate.model import Device
from ztgate.posture import trust_of
from ztgate.risk import RiskEngine, band, context_for

T = datetime(2026, 10, 10, 15, 0, tzinfo=UTC)


def dev(**over) -> Device:
    base = dict(id="lt-u1", owner="u1", kind="laptop", os="macOS", os_version="15.6", patch_age_days=5, managed=True,
                disk_encrypted=True, edr_running=True, screen_lock=True, os_supported=True)
    base.update(over)
    return Device(**base)


# ---------------------------------------------------------------- device trust


def test_compliant_managed_laptop_is_high():
    t = trust_of(dev())
    assert t.level == "high" and all(s["ok"] for s in t.signals)


@pytest.mark.parametrize(
    "over, level",
    [
        ({"patch_age_days": 45}, "medium"),
        ({"patch_age_days": 120}, "low"),
        ({"patch_age_days": 200}, "untrusted"),
        ({"edr_running": False}, "low"),
        ({"screen_lock": False}, "low"),
        ({"os_supported": False}, "low"),
        ({"managed": False}, "low"),
        ({"managed": False, "disk_encrypted": False}, "untrusted"),
    ],
)
def test_trust_levels(over, level):
    assert trust_of(dev(**over)).level == level


def test_lowest_cap_wins_and_every_failure_is_explained():
    t = trust_of(dev(patch_age_days=45, edr_running=False))
    assert t.level == "low"
    failed = {s["signal"] for s in t.signals if not s["ok"]}
    assert failed == {"patch_age", "edr"}


def test_unknown_device_is_untrusted():
    assert trust_of(None).level == "untrusted"


def test_trust_follows_posture_changes():
    d = dev()
    assert trust_of(d).level == "high"
    d.edr_running = False
    assert trust_of(d).level == "low"


# ---------------------------------------------------------------- geo and impossible travel


def test_haversine_known_distances():
    ny, ldn = CITY_BY_NAME["New York"], CITY_BY_NAME["London"]
    assert haversine_km(ny.lat, ny.lon, ldn.lat, ldn.lon) == pytest.approx(5570, rel=0.01)
    sf = CITY_BY_NAME["San Francisco"]
    assert haversine_km(sf.lat, sf.lon, ny.lat, ny.lon) == pytest.approx(4130, rel=0.01)
    assert haversine_km(1, 1, 1, 1) == 0


def test_travel_speed_and_thresholds():
    ny, ldn = CITY_BY_NAME["New York"], CITY_BY_NAME["London"]
    km, kmh, impossible = travel(ny, ldn, 60)
    assert kmh == pytest.approx(km) and impossible
    assert not travel(ny, ldn, 8 * 60)[2]  # an overnight flight is fine
    assert not travel(ny, UNKNOWN, 1)[2]


def test_short_hop_is_not_impossible():
    km, _, impossible = travel(CITY_BY_NAME["Amsterdam"], CITY_BY_NAME["London"], 10)
    assert km < 500 and not impossible


def test_synthetic_ip_ranges_locate():
    assert locate(home_ip("Berlin", 77)).name == "Berlin"
    assert locate(office_ip("Austin", 3)).name == "Austin"
    assert locate(hosting_ip("Jakarta", 2)).name == "Jakarta"
    assert locate(hosting_ip("Bucharest", 5, anonymizer=True)).name == "Bucharest"
    assert locate("8.8.8.8") is UNKNOWN and locate("garbage") is UNKNOWN


def test_context_local_hour():
    ctx = context_for(office_ip("Bangalore"), datetime(2026, 10, 1, 0, 0, tzinfo=UTC))
    assert ctx.local_hour == pytest.approx(5.5)


# ---------------------------------------------------------------- risk components


def engine() -> RiskEngine:
    r = RiskEngine({"198.51.100.10": "anonymizer exit"})
    r.seed("u1", ["lt-u1"], "US")
    return r


def comps(score) -> dict:
    return {c["component"]: c["points"] for c in score.components}


def test_clean_request_scores_zero():
    s = engine().score("u1", "lt-u1", "u1", office_ip("San Francisco"), T)
    assert s.score == 0 and s.band == "low"


def test_failed_logins_add_points_within_an_hour():
    r = engine()
    for k in range(3):
        r.record_failure("u1", "1.1.1.1", T - timedelta(minutes=10 + k))
    r.record_failure("u1", "1.1.1.1", T - timedelta(hours=3))
    assert comps(r.score("u1", "lt-u1", "u1", office_ip("San Francisco"), T)) == {"failed_logins": 18}


def test_new_device_registered_vs_unregistered():
    r = engine()
    assert comps(r.score("u1", "ph-u1", "u1", office_ip("San Francisco"), T)) == {"new_device": 5}
    assert comps(r.score("u1", "x-1", None, office_ip("San Francisco"), T)) == {"new_device": 25}
    assert comps(r.score("u1", "lt-u2", "u2", office_ip("San Francisco"), T))["new_device"] == 25


def test_impossible_travel_and_new_country():
    r = engine()
    r.record_success("u1", "lt-u1", office_ip("New York"), T - timedelta(minutes=50))
    s = r.score("u1", "lt-u1", "u1", hosting_ip("London", 1), T)
    c = comps(s)
    assert c["impossible_travel"] == 50 and c["new_country"] == 10
    assert "New York to London" in s.components[0]["detail"]


def test_threat_intel_hit():
    s = engine().score("u1", "lt-u1", "u1", "198.51.100.10", T)
    assert comps(s)["threat_intel"] == 40 and "anonymizer exit" in s.components[-1]["detail"]


def test_ip_velocity_flags_credential_stuffing():
    r = engine()
    ip = hosting_ip("Amsterdam", 9)
    for k in range(12):
        r.record_failure(f"v{k}", ip, T - timedelta(minutes=10) + timedelta(seconds=10 * k))
    assert comps(r.score("u1", "lt-u1", "u1", ip, T))["ip_velocity"] == 45
    assert "ip_velocity" not in comps(r.score("u1", "lt-u1", "u1", ip, T + timedelta(hours=1)))


def test_signal_events_expire_and_score_caps_at_100():
    r = engine()
    r.add_event("u1", T, 45, "MFA fatigue", hours=2)
    assert comps(r.score("u1", "lt-u1", "u1", office_ip("San Francisco"), T + timedelta(hours=1)))["signal"] == 45
    assert r.score("u1", "lt-u1", "u1", office_ip("San Francisco"), T + timedelta(hours=3)).score == 0
    r.add_event("u1", T, 90, "x")
    assert r.score("u1", "x-9", None, "198.51.100.10", T + timedelta(minutes=1)).score == 100


def test_bands():
    assert [band(x) for x in (0, 29, 30, 59, 60, 100)] == ["low", "low", "medium", "medium", "high", "high"]
