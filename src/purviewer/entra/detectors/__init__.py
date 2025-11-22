# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Anomaly detectors for Entra ID sign-in analysis."""

from purviewer.entra.detectors.failure_spike import FailureSpikeDetector
from purviewer.entra.detectors.impossible_travel import ImpossibleTravelDetector
from purviewer.entra.detectors.new_device import NewDeviceDetector
from purviewer.entra.detectors.new_location import NewLocationDetector

__all__ = [
    "FailureSpikeDetector",
    "ImpossibleTravelDetector",
    "NewDeviceDetector",
    "NewLocationDetector",
]
