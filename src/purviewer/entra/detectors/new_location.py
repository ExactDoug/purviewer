# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Detect new location anomalies in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pandas import DataFrame

from purviewer.entra.baseline import UserBaseline

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class LocationAnomaly:
    """Represents a new location detection."""

    user: str
    timestamp: str
    ip_address: str
    country: str
    city: str | None
    anomaly_type: str  # "new_country", "new_city", "new_ip"
    is_risky: bool


class NewLocationDetector:
    """Detect sign-ins from new locations based on user baseline."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the detector."""
        self.logger = logger

    def detect(
        self, df: DataFrame, baselines: dict[str, UserBaseline]
    ) -> list[LocationAnomaly]:
        """Detect new location anomalies.

        Args:
            df: DataFrame with extracted sign-in data.
            baselines: Dictionary of user baselines.

        Returns:
            List of detected location anomalies.
        """
        anomalies: list[LocationAnomaly] = []

        if df.empty:
            return anomalies

        for _, row in df.iterrows():
            user = row.get("userPrincipalName")
            if not user or user not in baselines:
                continue

            baseline = baselines[user]
            row_anomalies = self._check_location(row, baseline)
            anomalies.extend(row_anomalies)

        self.logger.info("Detected %d new location anomalies", len(anomalies))
        return anomalies

    def _check_location(
        self, row: dict, baseline: UserBaseline
    ) -> list[LocationAnomaly]:
        """Check a single sign-in for location anomalies.

        Args:
            row: Sign-in record.
            baseline: User's baseline profile.

        Returns:
            List of anomalies for this sign-in.
        """
        anomalies: list[LocationAnomaly] = []

        user = row.get("userPrincipalName", "Unknown")
        timestamp = str(row.get("createdDateTime", "Unknown"))
        ip = row.get("ipAddress", "Unknown")
        country = row.get("country", "")
        city = row.get("city", "")
        risk_level = str(row.get("riskLevel", "none")).lower()
        is_risky = risk_level in ["medium", "high"]

        # Check for new country
        if country and baseline.is_new_country(country):
            anomaly = LocationAnomaly(
                user=user,
                timestamp=timestamp,
                ip_address=ip,
                country=country,
                city=city,
                anomaly_type="new_country",
                is_risky=is_risky,
            )
            anomalies.append(anomaly)
            self.logger.debug(
                "New country for %s: %s (IP: %s)", user, country, ip
            )

        # Check for new city (only if country is known)
        elif city and baseline.is_new_city(city):
            anomaly = LocationAnomaly(
                user=user,
                timestamp=timestamp,
                ip_address=ip,
                country=country,
                city=city,
                anomaly_type="new_city",
                is_risky=is_risky,
            )
            anomalies.append(anomaly)
            self.logger.debug(
                "New city for %s: %s, %s (IP: %s)", user, city, country, ip
            )

        # Check for new IP address
        if ip and baseline.is_new_ip(ip):
            # Only add if we didn't already flag country/city
            if not anomalies:
                anomaly = LocationAnomaly(
                    user=user,
                    timestamp=timestamp,
                    ip_address=ip,
                    country=country,
                    city=city,
                    anomaly_type="new_ip",
                    is_risky=is_risky,
                )
                anomalies.append(anomaly)
                self.logger.debug("New IP for %s: %s", user, ip)

        return anomalies
