# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Extract and flatten nested fields from Entra ID sign-in data."""

from __future__ import annotations

import json
from typing import Any

import pandas as pd
from pandas import DataFrame


class EntraFieldExtractor:
    """Extract nested fields from Entra sign-in data into flat columns."""

    def extract_all(self, df: DataFrame) -> DataFrame:
        """Extract all nested fields into flat columns.

        Args:
            df: DataFrame with raw sign-in data.

        Returns:
            DataFrame with extracted fields.
        """
        df = df.copy()

        # Parse timestamps
        df = self._extract_timestamps(df)

        # Extract location fields
        df = self._extract_location(df)

        # Extract status fields
        df = self._extract_status(df)

        # Extract device detail fields
        df = self._extract_device_detail(df)

        # Normalize risk fields
        df = self._normalize_risk_fields(df)

        return df

    def _extract_timestamps(self, df: DataFrame) -> DataFrame:
        """Convert timestamp strings to datetime objects."""
        if "createdDateTime" in df.columns:
            df["createdDateTime"] = pd.to_datetime(df["createdDateTime"], utc=True)

        return df

    def _extract_location(self, df: DataFrame) -> DataFrame:
        """Extract nested location fields."""
        if "location" not in df.columns:
            df["country"] = None
            df["city"] = None
            df["state"] = None
            return df

        df["country"] = df["location"].apply(
            lambda x: self._safe_get(x, "countryOrRegion")
        )
        df["city"] = df["location"].apply(lambda x: self._safe_get(x, "city"))
        df["state"] = df["location"].apply(lambda x: self._safe_get(x, "state"))

        return df

    def _extract_status(self, df: DataFrame) -> DataFrame:
        """Extract nested status fields."""
        if "status" not in df.columns:
            df["errorCode"] = None
            df["failureReason"] = None
            df["success"] = True
            return df

        df["errorCode"] = df["status"].apply(lambda x: self._safe_get(x, "errorCode"))
        df["failureReason"] = df["status"].apply(
            lambda x: self._safe_get(x, "failureReason")
        )
        df["success"] = df["errorCode"].apply(lambda x: x == 0 if x is not None else True)

        return df

    def _extract_device_detail(self, df: DataFrame) -> DataFrame:
        """Extract nested device detail fields."""
        if "deviceDetail" not in df.columns:
            df["operatingSystem"] = None
            df["browser"] = None
            df["deviceId"] = None
            df["isManaged"] = None
            df["isCompliant"] = None
            return df

        df["operatingSystem"] = df["deviceDetail"].apply(
            lambda x: self._safe_get(x, "operatingSystem")
        )
        df["browser"] = df["deviceDetail"].apply(lambda x: self._safe_get(x, "browser"))
        df["deviceId"] = df["deviceDetail"].apply(
            lambda x: self._safe_get(x, "deviceId")
        )
        df["isManaged"] = df["deviceDetail"].apply(
            lambda x: self._safe_get(x, "isManaged")
        )
        df["isCompliant"] = df["deviceDetail"].apply(
            lambda x: self._safe_get(x, "isCompliant")
        )

        return df

    def _normalize_risk_fields(self, df: DataFrame) -> DataFrame:
        """Normalize risk level fields to consistent values."""
        if "riskLevel" in df.columns:
            df["riskLevel"] = df["riskLevel"].fillna("none").astype(str).str.lower()

        if "riskState" in df.columns:
            df["riskState"] = df["riskState"].fillna("none").astype(str).str.lower()

        return df

    def _safe_get(self, obj: Any, key: str) -> Any:
        """Safely get a value from a dict or JSON string.

        Args:
            obj: Dictionary, JSON string, or None.
            key: Key to extract.

        Returns:
            Value or None if not found.
        """
        if obj is None:
            return None

        # Handle JSON strings (from CSV exports)
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except (json.JSONDecodeError, TypeError):
                return None

        # Handle dicts
        if isinstance(obj, dict):
            return obj.get(key)

        return None
