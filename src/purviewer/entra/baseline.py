# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Calculate per-user baseline profiles for Entra ID sign-in analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pandas import DataFrame

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class UserBaseline:
    """Baseline profile for a single user."""

    user_principal_name: str
    ip_addresses: list[str] = field(default_factory=list)
    countries: list[str] = field(default_factory=list)
    cities: list[str] = field(default_factory=list)
    operating_systems: list[str] = field(default_factory=list)
    browsers: list[str] = field(default_factory=list)
    device_ids: list[str] = field(default_factory=list)
    client_apps: list[str] = field(default_factory=list)
    typical_hours: list[int] = field(default_factory=list)
    sign_in_count: int = 0

    def is_new_ip(self, ip: str) -> bool:
        """Check if an IP address is new for this user."""
        return ip not in self.ip_addresses

    def is_new_country(self, country: str) -> bool:
        """Check if a country is new for this user."""
        if not country:
            return False
        return country not in self.countries

    def is_new_city(self, city: str) -> bool:
        """Check if a city is new for this user."""
        if not city:
            return False
        return city not in self.cities

    def is_new_device(self, os: str | None, browser: str | None, device_id: str | None) -> bool:
        """Check if a device combination is new for this user."""
        if device_id and device_id not in self.device_ids:
            return True
        if os and os not in self.operating_systems:
            return True
        if browser and browser not in self.browsers:
            return True
        return False


class BaselineCalculator:
    """Calculate baseline profiles from sign-in data."""

    def __init__(self, logger: Logger, top_n: int = 10) -> None:
        """Initialize the baseline calculator.

        Args:
            logger: Logger instance.
            top_n: Number of top values to include in baseline.
        """
        self.logger = logger
        self.top_n = top_n

    def calculate(self, df: DataFrame, user: str | None = None) -> dict[str, UserBaseline]:
        """Calculate baseline profiles for users.

        Args:
            df: DataFrame with extracted sign-in data.
            user: Optional specific user to calculate baseline for.

        Returns:
            Dictionary mapping user principal names to baselines.
        """
        if user:
            df = df[df["userPrincipalName"] == user]

        if df.empty:
            self.logger.warning("No sign-in data to calculate baseline")
            return {}

        baselines: dict[str, UserBaseline] = {}

        for upn in df["userPrincipalName"].unique():
            user_df = df[df["userPrincipalName"] == upn]
            baseline = self._calculate_user_baseline(upn, user_df)
            baselines[upn] = baseline
            self.logger.debug(
                "Calculated baseline for %s: %d sign-ins, %d IPs, %d countries",
                upn,
                baseline.sign_in_count,
                len(baseline.ip_addresses),
                len(baseline.countries),
            )

        return baselines

    def _calculate_user_baseline(self, upn: str, df: DataFrame) -> UserBaseline:
        """Calculate baseline for a single user.

        Args:
            upn: User principal name.
            df: DataFrame filtered to this user's sign-ins.

        Returns:
            UserBaseline for this user.
        """
        baseline = UserBaseline(user_principal_name=upn)
        baseline.sign_in_count = len(df)

        # Top IP addresses
        if "ipAddress" in df.columns:
            baseline.ip_addresses = self._top_values(df, "ipAddress")

        # Top countries
        if "country" in df.columns:
            baseline.countries = self._top_values(df, "country")

        # Top cities
        if "city" in df.columns:
            baseline.cities = self._top_values(df, "city")

        # Top operating systems
        if "operatingSystem" in df.columns:
            baseline.operating_systems = self._top_values(df, "operatingSystem")

        # Top browsers
        if "browser" in df.columns:
            baseline.browsers = self._top_values(df, "browser")

        # Device IDs
        if "deviceId" in df.columns:
            baseline.device_ids = self._top_values(df, "deviceId")

        # Client apps
        if "clientAppUsed" in df.columns:
            baseline.client_apps = self._top_values(df, "clientAppUsed")

        # Typical sign-in hours
        if "createdDateTime" in df.columns:
            hours = df["createdDateTime"].dt.hour.value_counts().head(self.top_n)
            baseline.typical_hours = hours.index.tolist()

        return baseline

    def _top_values(self, df: DataFrame, column: str) -> list[str]:
        """Get top N non-null values from a column.

        Args:
            df: DataFrame to analyze.
            column: Column name.

        Returns:
            List of top values.
        """
        values = df[column].dropna().value_counts().head(self.top_n)
        return [str(v) for v in values.index.tolist()]
