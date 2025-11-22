# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Detect impossible travel anomalies in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pandas import DataFrame

from purviewer.entra.geoip import GeoIPService

if TYPE_CHECKING:
    from logging import Logger


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

    def __init__(
        self,
        logger: Logger,
        max_speed_kmh: int = 900,
        geoip_db_path: str | Path | None = None,
    ) -> None:
        """Initialize the detector.

        Args:
            logger: Logger instance.
            max_speed_kmh: Maximum realistic travel speed in km/h (default: 900, commercial flight).
            geoip_db_path: Optional path to MaxMind GeoLite2-City database.
        """
        self.logger = logger
        self.max_speed_kmh = max_speed_kmh
        self._geoip = GeoIPService(logger, geoip_db_path)

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

            # Get coordinates - try IP first, then city
            prev_coords = self._get_coordinates_for_signin(prev)
            curr_coords = self._get_coordinates_for_signin(curr)

            if prev_coords is None or curr_coords is None:
                continue

            # Calculate distance using geopy
            distance_km = self._geoip.calculate_distance(prev_coords, curr_coords)

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

    def _get_coordinates_for_signin(self, row: dict) -> tuple[float, float] | None:
        """Get coordinates for a sign-in record.

        Priority order:
        1. Embedded lat/lon from Entra ID logs (most accurate)
        2. IP-based geolocation (if MaxMind database available)
        3. City name lookup (fallback)

        Args:
            row: Sign-in record with latitude, longitude, ipAddress, city fields.

        Returns:
            (latitude, longitude) tuple or None if not found.
        """
        # Try embedded coordinates first (real Entra ID logs have these)
        lat = row.get("latitude")
        lon = row.get("longitude")
        if lat is not None and lon is not None:
            try:
                lat_f = float(lat)
                lon_f = float(lon)
                if lat_f != 0 or lon_f != 0:  # Skip (0, 0) which means unknown
                    return (lat_f, lon_f)
            except (ValueError, TypeError):
                pass

        # Try IP-based lookup (if MaxMind database available)
        ip = row.get("ipAddress")
        if ip:
            coords = self._geoip.get_coordinates(ip)
            if coords:
                return coords

        # Fall back to city name lookup
        city = row.get("city")
        country = row.get("country")
        if city:
            coords = GeoIPService.get_city_coordinates(city, country)
            if coords:
                return coords

        return None

    def close(self) -> None:
        """Close any open resources."""
        self._geoip.close()
