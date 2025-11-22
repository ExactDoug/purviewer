# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Sign-in analysis module for Microsoft Entra audit logs.

This module provides functionality for analyzing sign-in data from Microsoft Entra audit logs, including authentication failures, device types, location tracking, anomaly detection, and compromise identification.
"""  # noqa: D212, D415, W505

from __future__ import annotations

from .analyzer import EntraAnomalyAnalyzer
from .baseline import BaselineCalculator, UserBaseline
from .data_loader import EntraDataLoader
from .detectors import (
    FailureSpikeDetector,
    ImpossibleTravelDetector,
    NewDeviceDetector,
    NewLocationDetector,
)
from .entra_ops import EntraSignInOperations
from .field_extractor import EntraFieldExtractor
from .first_compromise import CompromiseCandidate, FirstCompromiseIdentifier
from .reporting import EntraReportGenerator

__all__ = [
    "BaselineCalculator",
    "CompromiseCandidate",
    "EntraAnomalyAnalyzer",
    "EntraDataLoader",
    "EntraFieldExtractor",
    "EntraReportGenerator",
    "EntraSignInOperations",
    "FailureSpikeDetector",
    "FirstCompromiseIdentifier",
    "ImpossibleTravelDetector",
    "NewDeviceDetector",
    "NewLocationDetector",
    "UserBaseline",
]
