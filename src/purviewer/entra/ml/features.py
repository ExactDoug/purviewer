# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Feature engineering for ML-based anomaly detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np
from pandas import DataFrame
from sklearn.preprocessing import LabelEncoder

if TYPE_CHECKING:
    from logging import Logger


class FeatureEngineer:
    """Transform sign-in data into features for ML models."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the feature engineer."""
        self.logger = logger
        self._encoders: dict[str, LabelEncoder] = {}

    def transform(self, df: DataFrame) -> np.ndarray:
        """Transform sign-in data into feature matrix.

        Args:
            df: DataFrame with extracted sign-in data.

        Returns:
            Feature matrix as numpy array.
        """
        if df.empty:
            return np.array([])

        features = []

        # Time-based features
        if "createdDateTime" in df.columns:
            features.append(self._extract_time_features(df))

        # Categorical features
        categorical_cols = [
            "ipAddress",
            "country",
            "city",
            "operatingSystem",
            "browser",
            "clientAppUsed",
        ]

        for col in categorical_cols:
            if col in df.columns:
                encoded = self._encode_categorical(df, col)
                features.append(encoded.reshape(-1, 1))

        # Risk features
        if "riskLevel" in df.columns:
            risk_encoded = self._encode_risk_level(df)
            features.append(risk_encoded.reshape(-1, 1))

        # Success/failure feature
        if "success" in df.columns:
            success = df["success"].astype(int).to_numpy().reshape(-1, 1)
            features.append(success)

        # Managed/compliant device features
        if "isManaged" in df.columns:
            managed = df["isManaged"].fillna(False).astype(int).to_numpy().reshape(-1, 1)
            features.append(managed)

        if "isCompliant" in df.columns:
            compliant = df["isCompliant"].fillna(False).astype(int).to_numpy().reshape(-1, 1)
            features.append(compliant)

        if not features:
            self.logger.warning("No features extracted from data")
            return np.array([])

        # Combine all features
        feature_matrix = np.hstack(features)
        self.logger.debug("Created feature matrix: %s", feature_matrix.shape)

        return feature_matrix

    def _extract_time_features(self, df: DataFrame) -> np.ndarray:
        """Extract time-based features.

        Args:
            df: DataFrame with createdDateTime column.

        Returns:
            Array with time features (hour, day_of_week, is_weekend).
        """
        dt = df["createdDateTime"]

        hour = dt.dt.hour.to_numpy()
        day_of_week = dt.dt.dayofweek.to_numpy()
        is_weekend = (day_of_week >= 5).astype(int)

        # Cyclical encoding for hour (to capture that 23:00 is close to 00:00)
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)

        # Cyclical encoding for day of week
        dow_sin = np.sin(2 * np.pi * day_of_week / 7)
        dow_cos = np.cos(2 * np.pi * day_of_week / 7)

        return np.column_stack([hour_sin, hour_cos, dow_sin, dow_cos, is_weekend])

    def _encode_categorical(self, df: DataFrame, column: str) -> np.ndarray:
        """Encode categorical column using label encoding.

        Args:
            df: DataFrame with the column.
            column: Column name to encode.

        Returns:
            Encoded values as numpy array.
        """
        # Fill NaN with 'unknown'
        values = df[column].fillna("unknown").astype(str)

        # Get or create encoder for this column
        if column not in self._encoders:
            self._encoders[column] = LabelEncoder()
            encoded = self._encoders[column].fit_transform(values)
        else:
            # Handle unseen labels
            encoder = self._encoders[column]
            encoded = []
            for val in values:
                if val in encoder.classes_:
                    encoded.append(encoder.transform([val])[0])
                else:
                    # Assign new label
                    new_classes = np.append(encoder.classes_, val)
                    encoder.classes_ = new_classes
                    encoded.append(len(new_classes) - 1)
            encoded = np.array(encoded)

        return encoded

    def _encode_risk_level(self, df: DataFrame) -> np.ndarray:
        """Encode risk level as numeric value.

        Args:
            df: DataFrame with riskLevel column.

        Returns:
            Encoded risk levels (0=none, 1=low, 2=medium, 3=high).
        """
        risk_map = {
            "none": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "hidden": 1,  # Treat hidden as low
        }

        values = df["riskLevel"].fillna("none").str.lower()
        encoded = values.map(lambda x: risk_map.get(x, 0))

        return encoded.to_numpy()

    def get_feature_names(self) -> list[str]:
        """Get names of all features.

        Returns:
            List of feature names.
        """
        names = [
            "hour_sin",
            "hour_cos",
            "dow_sin",
            "dow_cos",
            "is_weekend",
        ]

        for col in self._encoders:
            names.append(f"{col}_encoded")

        names.extend([
            "risk_level",
            "success",
            "is_managed",
            "is_compliant",
        ])

        return names
