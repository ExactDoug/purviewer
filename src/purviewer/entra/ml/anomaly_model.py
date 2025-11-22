# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Isolation Forest anomaly detection for Entra sign-in analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np
from pandas import DataFrame
from sklearn.ensemble import IsolationForest

from purviewer.entra.ml.features import FeatureEngineer

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class MLAnomaly:
    """Represents an ML-detected anomaly."""

    user: str
    timestamp: str
    ip_address: str
    anomaly_score: float
    is_anomaly: bool
    contributing_factors: list[str]


class AnomalyDetector:
    """Detect anomalies using Isolation Forest algorithm."""

    def __init__(
        self,
        logger: Logger,
        contamination: float = 0.1,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        """Initialize the anomaly detector.

        Args:
            logger: Logger instance.
            contamination: Expected proportion of anomalies (0.0 to 0.5).
            n_estimators: Number of trees in the forest.
            random_state: Random seed for reproducibility.
        """
        self.logger = logger
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._feature_engineer = FeatureEngineer(logger)
        self._models: dict[str, IsolationForest] = {}

    def detect(self, df: DataFrame, user: str | None = None) -> list[MLAnomaly]:
        """Detect anomalies in sign-in data.

        Args:
            df: DataFrame with extracted sign-in data.
            user: Optional specific user to analyze.

        Returns:
            List of detected ML anomalies.
        """
        anomalies: list[MLAnomaly] = []

        if df.empty:
            return anomalies

        # Filter to specific user if provided
        if user:
            df = df[df["userPrincipalName"] == user]

        # Analyze each user
        for upn in df["userPrincipalName"].unique():
            user_df = df[df["userPrincipalName"] == upn].copy()
            user_anomalies = self._detect_for_user(upn, user_df)
            anomalies.extend(user_anomalies)

        self.logger.info("ML detection found %d anomalies", len(anomalies))
        return anomalies

    def _detect_for_user(self, user: str, df: DataFrame) -> list[MLAnomaly]:
        """Detect anomalies for a single user.

        Args:
            user: User principal name.
            df: DataFrame filtered to this user's sign-ins.

        Returns:
            List of anomalies for this user.
        """
        anomalies: list[MLAnomaly] = []

        if len(df) < 10:
            self.logger.debug(
                "Skipping ML detection for %s: insufficient data (%d records)",
                user,
                len(df),
            )
            return anomalies

        # Transform to features
        features = self._feature_engineer.transform(df)

        if features.size == 0:
            return anomalies

        # Train or get existing model
        if user not in self._models:
            model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=self.random_state,
                n_jobs=-1,
            )
            model.fit(features)
            self._models[user] = model
        else:
            model = self._models[user]

        # Predict anomalies (-1 = anomaly, 1 = normal)
        predictions = model.predict(features)
        scores = model.decision_function(features)

        # Normalize scores to 0-1 range (lower = more anomalous)
        min_score = scores.min()
        max_score = scores.max()
        if max_score > min_score:
            normalized_scores = (scores - min_score) / (max_score - min_score)
        else:
            normalized_scores = np.ones_like(scores) * 0.5

        # Collect anomalies
        for i, (pred, score, norm_score) in enumerate(zip(predictions, scores, normalized_scores)):
            if pred == -1:  # Anomaly
                row = df.iloc[i]

                # Identify contributing factors
                factors = self._identify_factors(row, df)

                anomaly = MLAnomaly(
                    user=user,
                    timestamp=str(row.get("createdDateTime", "Unknown")),
                    ip_address=row.get("ipAddress", "Unknown"),
                    anomaly_score=round(1 - norm_score, 3),  # Higher = more anomalous
                    is_anomaly=True,
                    contributing_factors=factors,
                )
                anomalies.append(anomaly)

                self.logger.debug(
                    "ML anomaly for %s at %s: score=%.3f, factors=%s",
                    user,
                    anomaly.timestamp,
                    anomaly.anomaly_score,
                    factors,
                )

        return anomalies

    def _identify_factors(self, row: dict, df: DataFrame) -> list[str]:
        """Identify factors contributing to anomaly score.

        Args:
            row: The anomalous sign-in record.
            df: Full user DataFrame for comparison.

        Returns:
            List of contributing factor descriptions.
        """
        factors = []

        # Check time-based factors
        if "createdDateTime" in df.columns:
            hour = row["createdDateTime"].hour
            typical_hours = df["createdDateTime"].dt.hour.mode()
            if len(typical_hours) > 0 and abs(hour - typical_hours.iloc[0]) > 6:
                factors.append(f"unusual_hour:{hour}")

            dow = row["createdDateTime"].dayofweek
            if dow >= 5:  # Weekend
                weekday_count = len(df[df["createdDateTime"].dt.dayofweek < 5])
                weekend_count = len(df[df["createdDateTime"].dt.dayofweek >= 5])
                if weekday_count > weekend_count * 3:
                    factors.append("weekend_access")

        # Check location factors
        if "country" in df.columns:
            country = row.get("country")
            if country:
                country_counts = df["country"].value_counts()
                if country not in country_counts.index or country_counts[country] < 2:
                    factors.append(f"rare_country:{country}")

        # Check device factors
        if "operatingSystem" in df.columns:
            os = row.get("operatingSystem")
            if os:
                os_counts = df["operatingSystem"].value_counts()
                if os not in os_counts.index or os_counts[os] < 2:
                    factors.append(f"rare_os:{os}")

        # Check risk level
        risk = row.get("riskLevel", "none")
        if risk in ["medium", "high"]:
            factors.append(f"risk_level:{risk}")

        # Check managed status
        if not row.get("isManaged", True):
            managed_count = df["isManaged"].sum() if "isManaged" in df.columns else 0
            if managed_count > len(df) * 0.8:
                factors.append("unmanaged_device")

        return factors if factors else ["multiple_small_deviations"]
