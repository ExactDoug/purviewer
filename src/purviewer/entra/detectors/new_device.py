# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Detect new device anomalies in Entra ID sign-in data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pandas import DataFrame

from purviewer.entra.baseline import UserBaseline

if TYPE_CHECKING:
    from logging import Logger


@dataclass
class DeviceAnomaly:
    """Represents a new device detection."""

    user: str
    timestamp: str
    ip_address: str
    operating_system: str | None
    browser: str | None
    device_id: str | None
    is_managed: bool
    is_compliant: bool
    is_risky: bool


class NewDeviceDetector:
    """Detect sign-ins from new devices based on user baseline."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the detector."""
        self.logger = logger

    def detect(
        self, df: DataFrame, baselines: dict[str, UserBaseline]
    ) -> list[DeviceAnomaly]:
        """Detect new device anomalies.

        Args:
            df: DataFrame with extracted sign-in data.
            baselines: Dictionary of user baselines.

        Returns:
            List of detected device anomalies.
        """
        anomalies: list[DeviceAnomaly] = []

        if df.empty:
            return anomalies

        for _, row in df.iterrows():
            user = row.get("userPrincipalName")
            if not user or user not in baselines:
                continue

            baseline = baselines[user]
            anomaly = self._check_device(row, baseline)
            if anomaly:
                anomalies.append(anomaly)

        self.logger.info("Detected %d new device anomalies", len(anomalies))
        return anomalies

    def _check_device(
        self, row: dict, baseline: UserBaseline
    ) -> DeviceAnomaly | None:
        """Check a single sign-in for device anomalies.

        Args:
            row: Sign-in record.
            baseline: User's baseline profile.

        Returns:
            DeviceAnomaly if new device detected, None otherwise.
        """
        user = row.get("userPrincipalName", "Unknown")
        os = row.get("operatingSystem")
        browser = row.get("browser")
        device_id = row.get("deviceId")

        if not baseline.is_new_device(os, browser, device_id):
            return None

        timestamp = str(row.get("createdDateTime", "Unknown"))
        ip = row.get("ipAddress", "Unknown")
        is_managed = bool(row.get("isManaged", False))
        is_compliant = bool(row.get("isCompliant", False))
        risk_level = str(row.get("riskLevel", "none")).lower()
        is_risky = risk_level in ["medium", "high"]

        anomaly = DeviceAnomaly(
            user=user,
            timestamp=timestamp,
            ip_address=ip,
            operating_system=os,
            browser=browser,
            device_id=device_id,
            is_managed=is_managed,
            is_compliant=is_compliant,
            is_risky=is_risky,
        )

        self.logger.debug(
            "New device for %s: %s / %s (managed: %s, compliant: %s)",
            user,
            os or "Unknown OS",
            browser or "Unknown browser",
            is_managed,
            is_compliant,
        )

        return anomaly
