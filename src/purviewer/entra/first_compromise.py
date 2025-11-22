# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Identify the first compromised login in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pandas import DataFrame

from purviewer.entra.baseline import UserBaseline
from purviewer.entra.detectors.impossible_travel import TravelAnomaly
from purviewer.entra.detectors.new_location import LocationAnomaly

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class CompromiseCandidate:
    """Represents a potential first compromised login."""

    user: str
    timestamp: str
    ip_address: str
    location: str
    risk_level: str
    confidence: str  # "high", "medium", "low"
    reason: str
    error_code: int | None


class FirstCompromiseIdentifier:
    """Identify the likely first compromised login for a user."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the identifier."""
        self.logger = logger

    def identify(
        self,
        df: DataFrame,
        baselines: dict[str, UserBaseline],
        travel_anomalies: list[TravelAnomaly] | None = None,
        location_anomalies: list[LocationAnomaly] | None = None,
        user: str | None = None,
    ) -> dict[str, CompromiseCandidate | None]:
        """Identify first compromise candidates for users.

        Args:
            df: DataFrame with extracted sign-in data.
            baselines: Dictionary of user baselines.
            travel_anomalies: Optional list of impossible travel detections.
            location_anomalies: Optional list of new location detections.
            user: Optional specific user to analyze.

        Returns:
            Dictionary mapping users to their first compromise candidate.
        """
        results: dict[str, CompromiseCandidate | None] = {}

        if df.empty:
            return results

        # Filter to specific user if provided
        if user:
            df = df[df["userPrincipalName"] == user]

        # Sort by time
        df = df.sort_values("createdDateTime")

        # Analyze each user
        for upn in df["userPrincipalName"].unique():
            user_df = df[df["userPrincipalName"] == upn]
            baseline = baselines.get(upn)

            # Get user-specific anomalies
            user_travel = [a for a in (travel_anomalies or []) if a.user == upn]
            user_location = [a for a in (location_anomalies or []) if a.user == upn]

            candidate = self._identify_for_user(
                upn, user_df, baseline, user_travel, user_location
            )
            results[upn] = candidate

            if candidate:
                self.logger.info(
                    "First compromise for %s: %s (%s confidence) - %s",
                    upn,
                    candidate.timestamp,
                    candidate.confidence,
                    candidate.reason,
                )

        return results

    def _identify_for_user(
        self,
        user: str,
        df: DataFrame,
        baseline: UserBaseline | None,
        travel_anomalies: list[TravelAnomaly],
        location_anomalies: list[LocationAnomaly],
    ) -> CompromiseCandidate | None:
        """Identify first compromise for a single user.

        Args:
            user: User principal name.
            df: DataFrame filtered to this user's sign-ins.
            baseline: User's baseline profile.
            travel_anomalies: Travel anomalies for this user.
            location_anomalies: Location anomalies for this user.

        Returns:
            CompromiseCandidate or None if no compromise detected.
        """
        # Method 1: First successful login with high risk flag (highest confidence)
        candidate = self._find_first_risky_success(user, df)
        if candidate:
            return candidate

        # Method 2: First successful login from new IP after failures
        candidate = self._find_success_after_failures(user, df, baseline)
        if candidate:
            return candidate

        # Method 3: First successful login after impossible travel
        candidate = self._find_post_travel_success(user, df, travel_anomalies)
        if candidate:
            return candidate

        # Method 4: First successful login from new country
        candidate = self._find_new_country_success(user, df, location_anomalies)
        if candidate:
            return candidate

        return None

    def _find_first_risky_success(
        self, user: str, df: DataFrame
    ) -> CompromiseCandidate | None:
        """Find first successful sign-in with high risk level."""
        risky_success = df[
            (df["success"] == True) &  # noqa: E712
            (df["riskLevel"].isin(["medium", "high"]))
        ]

        if risky_success.empty:
            return None

        first = risky_success.iloc[0]
        return CompromiseCandidate(
            user=user,
            timestamp=str(first["createdDateTime"]),
            ip_address=first.get("ipAddress", "Unknown"),
            location=f"{first.get('city', 'Unknown')}, {first.get('country', 'Unknown')}",
            risk_level=first.get("riskLevel", "unknown"),
            confidence="high",
            reason="First successful login with risk flag",
            error_code=None,
        )

    def _find_success_after_failures(
        self, user: str, df: DataFrame, baseline: UserBaseline | None
    ) -> CompromiseCandidate | None:
        """Find first successful login from new IP after failed attempts."""
        failures = df[df["success"] == False]  # noqa: E712

        if failures.empty or baseline is None:
            return None

        last_failure_time = failures.iloc[-1]["createdDateTime"]

        # Find successful logins after last failure
        post_failure_success = df[
            (df["createdDateTime"] > last_failure_time) &
            (df["success"] == True)  # noqa: E712
        ]

        # Check for new IP
        for _, row in post_failure_success.iterrows():
            ip = row.get("ipAddress", "")
            if baseline.is_new_ip(ip):
                return CompromiseCandidate(
                    user=user,
                    timestamp=str(row["createdDateTime"]),
                    ip_address=ip,
                    location=f"{row.get('city', 'Unknown')}, {row.get('country', 'Unknown')}",
                    risk_level=row.get("riskLevel", "none"),
                    confidence="medium",
                    reason="Successful login from new IP after failed attempts",
                    error_code=None,
                )

        return None

    def _find_post_travel_success(
        self, user: str, df: DataFrame, travel_anomalies: list[TravelAnomaly]
    ) -> CompromiseCandidate | None:
        """Find first successful login after impossible travel."""
        if not travel_anomalies:
            return None

        # Get earliest travel anomaly
        earliest_travel = min(travel_anomalies, key=lambda x: x.to_time)

        # Find successful logins at or after the travel destination time
        from pandas import to_datetime
        travel_time = to_datetime(earliest_travel.to_time)

        post_travel = df[
            (df["createdDateTime"] >= travel_time) &
            (df["success"] == True)  # noqa: E712
        ]

        if post_travel.empty:
            return None

        first = post_travel.iloc[0]
        return CompromiseCandidate(
            user=user,
            timestamp=str(first["createdDateTime"]),
            ip_address=first.get("ipAddress", "Unknown"),
            location=f"{first.get('city', 'Unknown')}, {first.get('country', 'Unknown')}",
            risk_level=first.get("riskLevel", "none"),
            confidence="medium",
            reason=f"Successful login after impossible travel from {earliest_travel.from_location}",
            error_code=None,
        )

    def _find_new_country_success(
        self, user: str, df: DataFrame, location_anomalies: list[LocationAnomaly]
    ) -> CompromiseCandidate | None:
        """Find first successful login from new country."""
        # Filter to new country anomalies
        new_countries = [
            a for a in location_anomalies
            if a.anomaly_type == "new_country"
        ]

        if not new_countries:
            return None

        # Get earliest
        earliest = min(new_countries, key=lambda x: x.timestamp)

        # Find corresponding sign-in
        from pandas import to_datetime
        anomaly_time = to_datetime(earliest.timestamp)

        matching = df[
            (df["createdDateTime"] == anomaly_time) &
            (df["success"] == True)  # noqa: E712
        ]

        if matching.empty:
            return None

        first = matching.iloc[0]
        return CompromiseCandidate(
            user=user,
            timestamp=str(first["createdDateTime"]),
            ip_address=first.get("ipAddress", "Unknown"),
            location=f"{first.get('city', 'Unknown')}, {first.get('country', 'Unknown')}",
            risk_level=first.get("riskLevel", "none"),
            confidence="low",
            reason=f"First successful login from new country: {earliest.country}",
            error_code=None,
        )
