"""Synthetic IP geolocation, great-circle distance, and impossible travel.

IP addresses come from reserved ranges (CGNAT 100.64.0.0/10 and the RFC 5737 / RFC 2544 documentation and benchmark
ranges), so nothing here points at a real network.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import lru_cache

EARTH_RADIUS_KM = 6371.0088
# Commercial jets cruise near 900 km/h. Anything faster between two sign-ins is not a person travelling.
MAX_TRAVEL_KMH = 900.0
# Short hops are noise: IP geolocation is only accurate to a metro area, and VPN exits move between nearby cities.
MIN_TRAVEL_KM = 500.0


@dataclass(frozen=True)
class City:
    name: str
    country: str
    lat: float
    lon: float
    tz: float  # fixed UTC offset in hours, DST ignored


CITIES: list[City] = [
    City("San Francisco", "US", 37.7749, -122.4194, -8),
    City("New York", "US", 40.7128, -74.0060, -5),
    City("Austin", "US", 30.2672, -97.7431, -6),
    City("Toronto", "CA", 43.6532, -79.3832, -5),
    City("London", "GB", 51.5074, -0.1278, 0),
    City("Berlin", "DE", 52.5200, 13.4050, 1),
    City("Dublin", "IE", 53.3498, -6.2603, 0),
    City("Bangalore", "IN", 12.9716, 77.5946, 5.5),
    City("Singapore", "SG", 1.3521, 103.8198, 8),
    City("Sao Paulo", "BR", -23.5505, -46.6333, -3),
    City("Amsterdam", "NL", 52.3676, 4.9041, 1),
    City("Bucharest", "RO", 44.4268, 26.1025, 2),
    City("Jakarta", "ID", -6.2088, 106.8456, 7),
    City("Chicago", "US", 41.8781, -87.6298, -6),
    City("Lisbon", "PT", 38.7223, -9.1393, 0),
]
CITY_BY_NAME = {c.name: c for c in CITIES}
UNKNOWN = City("Unknown", "ZZ", 0.0, 0.0, 0)


def city_index(name: str) -> int:
    return [c.name for c in CITIES].index(name)


def home_ip(city: str, n: int) -> str:
    """A residential or mobile address in a city (CGNAT range, one /16 per city)."""
    i = city_index(city)
    return f"100.{64 + i}.{(n // 250) % 250}.{1 + n % 250}"


def office_ip(city: str, n: int = 0) -> str:
    """An office egress address (benchmark range 198.18.0.0/15, one /24 per city)."""
    return f"198.18.{city_index(city)}.{10 + n % 200}"


def hosting_ip(city: str, n: int, anonymizer: bool = False) -> str:
    """A hosting provider or VPN exit (documentation ranges, 16 addresses per city).

    203.0.113.0/24 is ordinary hosting and VPN. 198.51.100.0/24 is anonymizers and proxy networks, which is where the
    synthetic threat feed draws from."""
    net = "198.51.100" if anonymizer else "203.0.113"
    return f"{net}.{city_index(city) * 16 + n % 16}"


@lru_cache(maxsize=65536)
def locate(ip: str) -> City:
    parts = ip.split(".")
    if len(parts) != 4:
        return UNKNOWN
    try:
        a, b, c, d = (int(p) for p in parts)
    except ValueError:
        return UNKNOWN
    if a == 100 and 64 <= b < 64 + len(CITIES):
        return CITIES[b - 64]
    if a == 198 and b == 18 and c < len(CITIES):
        return CITIES[c]
    if (a, b, c) in ((203, 0, 113), (198, 51, 100)) and d // 16 < len(CITIES):
        return CITIES[d // 16]
    return UNKNOWN


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two points on a sphere."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = p2 - p1
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def travel(a: City, b: City, minutes: float) -> tuple[float, float, bool]:
    """Distance in km, implied speed in km/h, and whether the trip is impossible."""
    if a is UNKNOWN or b is UNKNOWN:
        return 0.0, 0.0, False
    km = haversine_km(a.lat, a.lon, b.lat, b.lon)
    hours = max(minutes, 1.0) / 60.0
    kmh = km / hours
    return km, kmh, km >= MIN_TRAVEL_KM and kmh > MAX_TRAVEL_KMH
