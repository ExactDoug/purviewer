# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Detect impossible travel anomalies in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pandas import DataFrame

if TYPE_CHECKING:
    from logging import Logger


# Approximate coordinates for major cities (simplified approach without GeoIP)
# In production, use MaxMind GeoLite2 or similar
CITY_COORDINATES: dict[str, tuple[float, float]] = {
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
    "London": (51.5074, -0.1278),
    "Paris": (48.8566, 2.3522),
    "Berlin": (52.5200, 13.4050),
    "Moscow": (55.7558, 37.6173),
    "Tokyo": (35.6762, 139.6503),
    "Beijing": (39.9042, 116.4074),
    "Sydney": (-33.8688, 151.2093),
    "Toronto": (43.6532, -79.3832),
    "Mumbai": (19.0760, 72.8777),
    "Dubai": (25.2048, 55.2708),
}


@dataclass
class TravelAnomaly:
    """Represents an impossible travel detection."""

    user: str
    from_time: str
    to_time: str
    from_location: str
    to_location: str
    distance_km: float
    time_hours: float
    required_speed_kmh: float
    from_ip: str
    to_ip: str


class ImpossibleTravelDetector:
    """Detect impossible travel based on geographic distance and time."""

    def __init__(self, logger: Logger, max_speed_kmh: int = 900) -> None:
        """Initialize the detector.

        Args:
            logger: Logger instance.
            max_speed_kmh: Maximum realistic travel speed in km/h (default: 900, commercial flight).
        """
        self.logger = logger
        self.max_speed_kmh = max_speed_kmh

    def detect(self, df: DataFrame) -> list[TravelAnomaly]:
        """Detect impossible travel anomalies.

        Args:
            df: DataFrame with extracted sign-in data.

        Returns:
            List of detected travel anomalies.
        """
        anomalies: list[TravelAnomaly] = []

        if df.empty:
            return anomalies

        # Ensure sorted by time
        df = df.sort_values("createdDateTime")

        # Check each user separately
        for user in df["userPrincipalName"].unique():
            user_df = df[df["userPrincipalName"] == user].copy()
            user_anomalies = self._detect_for_user(user, user_df)
            anomalies.extend(user_anomalies)

        self.logger.info("Detected %d impossible travel anomalies", len(anomalies))
        return anomalies

    def _detect_for_user(self, user: str, df: DataFrame) -> list[TravelAnomaly]:
        """Detect impossible travel for a single user.

        Args:
            user: User principal name.
            df: DataFrame filtered to this user's sign-ins.

        Returns:
            List of anomalies for this user.
        """
        anomalies: list[TravelAnomaly] = []

        if len(df) < 2:
            return anomalies

        for i in range(1, len(df)):
            prev = df.iloc[i - 1]
            curr = df.iloc[i]

            # Get coordinates for both locations
            prev_coords = self._get_coordinates(prev.get("city"))
            curr_coords = self._get_coordinates(curr.get("city"))

            if prev_coords is None or curr_coords is None:
                continue

            # Calculate distance
            distance_km = self._haversine_distance(prev_coords, curr_coords)

            # Calculate time difference
            time_diff = curr["createdDateTime"] - prev["createdDateTime"]
            time_hours = time_diff.total_seconds() / 3600

            if time_hours <= 0:
                continue

            # Calculate required speed
            required_speed = distance_km / time_hours

            # Check if impossible
            if required_speed > self.max_speed_kmh and distance_km > 100:  # Ignore small distances
                anomaly = TravelAnomaly(
                    user=user,
                    from_time=str(prev["createdDateTime"]),
                    to_time=str(curr["createdDateTime"]),
                    from_location=f"{prev.get('city', 'Unknown')}, {prev.get('country', 'Unknown')}",
                    to_location=f"{curr.get('city', 'Unknown')}, {curr.get('country', 'Unknown')}",
                    distance_km=round(distance_km, 1),
                    time_hours=round(time_hours, 2),
                    required_speed_kmh=round(required_speed, 0),
                    from_ip=prev.get("ipAddress", "Unknown"),
                    to_ip=curr.get("ipAddress", "Unknown"),
                )
                anomalies.append(anomaly)
                self.logger.debug(
                    "Impossible travel: %s from %s to %s (%.0f km in %.1f hours = %.0f km/h)",
                    user,
                    anomaly.from_location,
                    anomaly.to_location,
                    distance_km,
                    time_hours,
                    required_speed,
                )

        return anomalies

    def _get_coordinates(self, city: str | None) -> tuple[float, float] | None:
        """Get coordinates for a city.

        Args:
            city: City name.

        Returns:
            (latitude, longitude) tuple or None if not found.
        """
        if not city:
            return None

        # Check our simple lookup table
        return CITY_COORDINATES.get(city)

    def _haversine_distance(
        self, coord1: tuple[float, float], coord2: tuple[float, float]
    ) -> float:
        """Calculate the Haversine distance between two points.

        Args:
            coord1: (latitude, longitude) of first point.
            coord2: (latitude, longitude) of second point.

        Returns:
            Distance in kilometers.
        """
        import math

        lat1, lon1 = coord1
        lat2, lon2 = coord2

        # Earth's radius in kilometers
        R = 6371.0

        # Convert to radians
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)

        # Haversine formula
        a = (
            math.sin(dlat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return R * c
