# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Detect failure spike anomalies in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np
from pandas import DataFrame

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class FailureSpike:
    """Represents a failure spike detection."""

    user: str
    date: str
    failure_count: int
    average_failures: float
    std_dev: float
    z_score: float
    ip_addresses: list[str]
    error_codes: list[int]


class FailureSpikeDetector:
    """Detect unusual spikes in failed sign-in attempts."""

    def __init__(self, logger: Logger, threshold_sigma: float = 3.0) -> None:
        """Initialize the detector.

        Args:
            logger: Logger instance.
            threshold_sigma: Z-score threshold for spike detection (default: 3.0).
        """
        self.logger = logger
        self.threshold_sigma = threshold_sigma

    def detect(self, df: DataFrame) -> list[FailureSpike]:
        """Detect failure spike anomalies.

        Args:
            df: DataFrame with extracted sign-in data.

        Returns:
            List of detected failure spikes.
        """
        anomalies: list[FailureSpike] = []

        if df.empty:
            return anomalies

        # Filter to failures only
        failures_df = df[df["success"] == False].copy()  # noqa: E712

        if failures_df.empty:
            self.logger.debug("No failed sign-ins to analyze")
            return anomalies

        # Add date column for grouping
        failures_df["date"] = failures_df["createdDateTime"].dt.date

        # Check each user
        for user in failures_df["userPrincipalName"].unique():
            user_df = failures_df[failures_df["userPrincipalName"] == user]
            user_anomalies = self._detect_for_user(user, user_df, df)
            anomalies.extend(user_anomalies)

        self.logger.info("Detected %d failure spike anomalies", len(anomalies))
        return anomalies

    def _detect_for_user(
        self, user: str, failures_df: DataFrame, all_df: DataFrame
    ) -> list[FailureSpike]:
        """Detect failure spikes for a single user.

        Args:
            user: User principal name.
            failures_df: DataFrame with user's failed sign-ins.
            all_df: DataFrame with all sign-ins (for context).

        Returns:
            List of failure spikes for this user.
        """
        anomalies: list[FailureSpike] = []

        # Count failures per day
        daily_counts = failures_df.groupby("date").size()

        if len(daily_counts) < 2:
            # Not enough data for statistical analysis
            return anomalies

        # Calculate statistics
        mean_failures = daily_counts.mean()
        std_failures = daily_counts.std()

        if std_failures == 0:
            # No variation
            return anomalies

        # Check each day for spikes
        for date, count in daily_counts.items():
            z_score = (count - mean_failures) / std_failures

            if z_score > self.threshold_sigma:
                # Get details for this spike
                day_df = failures_df[failures_df["date"] == date]
                ip_addresses = day_df["ipAddress"].unique().tolist()
                error_codes = [
                    int(code)
                    for code in day_df["errorCode"].dropna().unique()
                ]

                spike = FailureSpike(
                    user=user,
                    date=str(date),
                    failure_count=int(count),
                    average_failures=round(float(mean_failures), 2),
                    std_dev=round(float(std_failures), 2),
                    z_score=round(float(z_score), 2),
                    ip_addresses=ip_addresses,
                    error_codes=error_codes,
                )
                anomalies.append(spike)

                self.logger.debug(
                    "Failure spike for %s on %s: %d failures (z=%.2f, avg=%.1f)",
                    user,
                    date,
                    count,
                    z_score,
                    mean_failures,
                )

        return anomalies
