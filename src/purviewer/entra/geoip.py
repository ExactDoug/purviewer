# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""GeoIP service for IP address geolocation in Entra sign-in analysis."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from geopy.distance import geodesic

if TYPE_CHECKING:
    from logging import Logger


class GeoIPService:
    """Provide IP geolocation and distance calculations."""

    def __init__(self, logger: Logger, db_path: str | Path | None = None) -> None:
        """Initialize the GeoIP service.

        Args:
            logger: Logger instance.
            db_path: Optional path to MaxMind GeoLite2-City database.
        """
        self.logger = logger
        self._geoip_reader = None
        self._cache: dict[str, tuple[float, float] | None] = {}

        # Try to load MaxMind database if path provided
        if db_path:
            self._load_maxmind_db(Path(db_path))

    def _load_maxmind_db(self, db_path: Path) -> None:
        """Load MaxMind GeoLite2 database.

        Args:
            db_path: Path to the .mmdb file.
        """
        try:
            import geoip2.database

            if db_path.exists():
                self._geoip_reader = geoip2.database.Reader(str(db_path))
                self.logger.info("Loaded MaxMind GeoLite2 database: %s", db_path)
            else:
                self.logger.warning("GeoIP database not found: %s", db_path)
        except ImportError:
            self.logger.warning("geoip2 package not available for MaxMind database")
        except Exception as e:
            self.logger.error("Failed to load GeoIP database: %s", e)

    def get_coordinates(self, ip: str) -> tuple[float, float] | None:
        """Get coordinates for an IP address.

        Args:
            ip: IP address string.

        Returns:
            (latitude, longitude) tuple or None if not found.
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]

        coords = None

        # Try MaxMind database first
        if self._geoip_reader:
            coords = self._lookup_maxmind(ip)

        # Cache result (including None for failed lookups)
        self._cache[ip] = coords
        return coords

    def _lookup_maxmind(self, ip: str) -> tuple[float, float] | None:
        """Look up IP in MaxMind database.

        Args:
            ip: IP address string.

        Returns:
            (latitude, longitude) tuple or None if not found.
        """
        try:
            response = self._geoip_reader.city(ip)
            if response.location.latitude and response.location.longitude:
                return (response.location.latitude, response.location.longitude)
        except Exception as e:
            self.logger.debug("MaxMind lookup failed for %s: %s", ip, e)
        return None

    @staticmethod
    @lru_cache(maxsize=1000)
    def get_city_coordinates(city: str, country: str | None = None) -> tuple[float, float] | None:
        """Get coordinates for a city name using geocoding.

        Args:
            city: City name.
            country: Optional country for disambiguation.

        Returns:
            (latitude, longitude) tuple or None if not found.
        """
        # Built-in coordinates for common cities (fast fallback)
        known_cities = {
            "Seattle": (47.6062, -122.3321),
            "New York": (40.7128, -74.0060),
            "Los Angeles": (34.0522, -118.2437),
            "Chicago": (41.8781, -87.6298),
            "Houston": (29.7604, -95.3698),
            "Phoenix": (33.4484, -112.0740),
            "Philadelphia": (39.9526, -75.1652),
            "San Antonio": (29.4241, -98.4936),
            "San Diego": (32.7157, -117.1611),
            "Dallas": (32.7767, -96.7970),
            "San Jose": (37.3382, -121.8863),
            "Austin": (30.2672, -97.7431),
            "Jacksonville": (30.3322, -81.6557),
            "San Francisco": (37.7749, -122.4194),
            "Columbus": (39.9612, -82.9988),
            "Fort Worth": (32.7555, -97.3308),
            "Indianapolis": (39.7684, -86.1581),
            "Charlotte": (35.2271, -80.8431),
            "Seattle-Tacoma": (47.4502, -122.3088),
            "Denver": (39.7392, -104.9903),
            "Washington": (38.9072, -77.0369),
            "Boston": (42.3601, -71.0589),
            "El Paso": (31.7619, -106.4850),
            "Detroit": (42.3314, -83.0458),
            "Nashville": (36.1627, -86.7816),
            "Portland": (45.5152, -122.6784),
            "Memphis": (35.1495, -90.0490),
            "Oklahoma City": (35.4676, -97.5164),
            "Las Vegas": (36.1699, -115.1398),
            "Louisville": (38.2527, -85.7585),
            "Baltimore": (39.2904, -76.6122),
            "Milwaukee": (43.0389, -87.9065),
            "Albuquerque": (35.0844, -106.6504),
            "Tucson": (32.2226, -110.9747),
            "Fresno": (36.7378, -119.7871),
            "Sacramento": (38.5816, -121.4944),
            "Atlanta": (33.7490, -84.3880),
            "Kansas City": (39.0997, -94.5786),
            "Miami": (25.7617, -80.1918),
            "Raleigh": (35.7796, -78.6382),
            "Omaha": (41.2565, -95.9345),
            "Minneapolis": (44.9778, -93.2650),
            "Cleveland": (41.4993, -81.6944),
            "London": (51.5074, -0.1278),
            "Paris": (48.8566, 2.3522),
            "Berlin": (52.5200, 13.4050),
            "Madrid": (40.4168, -3.7038),
            "Rome": (41.9028, 12.4964),
            "Amsterdam": (52.3676, 4.9041),
            "Vienna": (48.2082, 16.3738),
            "Brussels": (50.8503, 4.3517),
            "Munich": (48.1351, 11.5820),
            "Milan": (45.4642, 9.1900),
            "Barcelona": (41.3851, 2.1734),
            "Prague": (50.0755, 14.4378),
            "Dublin": (53.3498, -6.2603),
            "Stockholm": (59.3293, 18.0686),
            "Oslo": (59.9139, 10.7522),
            "Copenhagen": (55.6761, 12.5683),
            "Helsinki": (60.1699, 24.9384),
            "Warsaw": (52.2297, 21.0122),
            "Zurich": (47.3769, 8.5417),
            "Geneva": (46.2044, 6.1432),
            "Moscow": (55.7558, 37.6173),
            "St. Petersburg": (59.9311, 30.3609),
            "Kyiv": (50.4501, 30.5234),
            "Istanbul": (41.0082, 28.9784),
            "Athens": (37.9838, 23.7275),
            "Tokyo": (35.6762, 139.6503),
            "Osaka": (34.6937, 135.5023),
            "Beijing": (39.9042, 116.4074),
            "Shanghai": (31.2304, 121.4737),
            "Hong Kong": (22.3193, 114.1694),
            "Singapore": (1.3521, 103.8198),
            "Seoul": (37.5665, 126.9780),
            "Taipei": (25.0330, 121.5654),
            "Bangkok": (13.7563, 100.5018),
            "Kuala Lumpur": (3.1390, 101.6869),
            "Jakarta": (6.2088, 106.8456),
            "Manila": (14.5995, 120.9842),
            "Ho Chi Minh City": (10.8231, 106.6297),
            "Delhi": (28.7041, 77.1025),
            "Mumbai": (19.0760, 72.8777),
            "Bangalore": (12.9716, 77.5946),
            "Chennai": (13.0827, 80.2707),
            "Kolkata": (22.5726, 88.3639),
            "Hyderabad": (17.3850, 78.4867),
            "Dubai": (25.2048, 55.2708),
            "Abu Dhabi": (24.4539, 54.3773),
            "Doha": (25.2854, 51.5310),
            "Riyadh": (24.7136, 46.6753),
            "Tel Aviv": (32.0853, 34.7818),
            "Cairo": (30.0444, 31.2357),
            "Johannesburg": (26.2041, 28.0473),
            "Cape Town": (33.9249, 18.4241),
            "Lagos": (6.5244, 3.3792),
            "Nairobi": (1.2921, 36.8219),
            "Sydney": (-33.8688, 151.2093),
            "Melbourne": (-37.8136, 144.9631),
            "Brisbane": (-27.4698, 153.0251),
            "Perth": (-31.9505, 115.8605),
            "Auckland": (-36.8485, 174.7633),
            "Toronto": (43.6532, -79.3832),
            "Vancouver": (49.2827, -123.1207),
            "Montreal": (45.5017, -73.5673),
            "Calgary": (51.0447, -114.0719),
            "Ottawa": (45.4215, -75.6972),
            "Mexico City": (19.4326, -99.1332),
            "Guadalajara": (20.6597, -103.3496),
            "Monterrey": (25.6866, -100.3161),
            "Sao Paulo": (-23.5505, -46.6333),
            "Rio de Janeiro": (-22.9068, -43.1729),
            "Buenos Aires": (-34.6037, -58.3816),
            "Santiago": (-33.4489, -70.6693),
            "Lima": (-12.0464, -77.0428),
            "Bogota": (4.7110, -74.0721),
        }

        if city in known_cities:
            return known_cities[city]

        return None

    def calculate_distance(
        self,
        coord1: tuple[float, float],
        coord2: tuple[float, float],
    ) -> float:
        """Calculate distance between two coordinates.

        Args:
            coord1: (latitude, longitude) of first point.
            coord2: (latitude, longitude) of second point.

        Returns:
            Distance in kilometers.
        """
        return geodesic(coord1, coord2).kilometers

    def close(self) -> None:
        """Close any open resources."""
        if self._geoip_reader:
            self._geoip_reader.close()
            self._geoip_reader = None
