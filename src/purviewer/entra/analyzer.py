# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Main analyzer that orchestrates all Entra sign-in analysis components."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from purviewer.entra.baseline import BaselineCalculator, UserBaseline
from purviewer.entra.data_loader import EntraDataLoader
from purviewer.entra.detectors import (
    FailureSpikeDetector,
    ImpossibleTravelDetector,
    NewDeviceDetector,
    NewLocationDetector,
)
from purviewer.entra.field_extractor import EntraFieldExtractor
from purviewer.entra.first_compromise import CompromiseCandidate, FirstCompromiseIdentifier
from purviewer.entra.ml import AnomalyDetector
from purviewer.entra.reporting import EntraReportGenerator

if TYPE_CHECKING:
    from logging import Logger

    from pandas import DataFrame

    from purviewer.entra.detectors.failure_spike import FailureSpike
    from purviewer.entra.detectors.impossible_travel import TravelAnomaly
    from purviewer.entra.detectors.new_device import DeviceAnomaly
    from purviewer.entra.detectors.new_location import LocationAnomaly
    from purviewer.entra.ml.anomaly_model import MLAnomaly


class EntraAnomalyAnalyzer:
    """Main analyzer for Entra sign-in anomaly detection."""

    def __init__(self, logger: Logger, enable_ml: bool = False) -> None:
        """Initialize the analyzer with all components.

        Args:
            logger: Logger instance.
            enable_ml: Enable ML-based anomaly detection.
        """
        self.logger = logger
        self._enable_ml = enable_ml

        # Initialize components
        self.loader = EntraDataLoader(logger)
        self.extractor = EntraFieldExtractor()
        self.baseline_calculator = BaselineCalculator(logger)
        self.travel_detector = ImpossibleTravelDetector(logger)
        self.location_detector = NewLocationDetector(logger)
        self.device_detector = NewDeviceDetector(logger)
        self.failure_detector = FailureSpikeDetector(logger)
        self.compromise_identifier = FirstCompromiseIdentifier(logger)
        self.reporter = EntraReportGenerator(logger)

        # ML detector (optional)
        self.ml_detector: AnomalyDetector | None = None
        if enable_ml:
            self.ml_detector = AnomalyDetector(logger)

        # Analysis results
        self.df: DataFrame | None = None
        self.baselines: dict[str, UserBaseline] = {}
        self.travel_anomalies: list[TravelAnomaly] = []
        self.location_anomalies: list[LocationAnomaly] = []
        self.device_anomalies: list[DeviceAnomaly] = []
        self.failure_spikes: list[FailureSpike] = []
        self.ml_anomalies: list[MLAnomaly] = []
        self.compromises: dict[str, CompromiseCandidate | None] = {}

    def analyze(
        self,
        file_path: str | Path,
        user: str | None = None,
        filter_text: str | None = None,
        exclude_text: str | None = None,
    ) -> None:
        """Run complete anomaly analysis on sign-in data.

        Args:
            file_path: Path to JSON or CSV sign-in export.
            user: Optional specific user to analyze.
            filter_text: Optional text to filter sign-ins.
            exclude_text: Optional text to exclude sign-ins.
        """
        self.logger.info("Starting Entra anomaly analysis: %s", file_path)

        # Load data
        self.df = self.loader.load(file_path)

        # Apply filters
        if filter_text:
            mask = self.df.astype(str).apply(
                lambda row: row.str.contains(filter_text, case=False).any(),
                axis=1
            )
            self.df = self.df[mask]
            self.logger.info("Filtered to %d rows containing '%s'", len(self.df), filter_text)

        if exclude_text:
            mask = self.df.astype(str).apply(
                lambda row: row.str.contains(exclude_text, case=False).any(),
                axis=1
            )
            self.df = self.df[~mask]
            self.logger.info("Excluded rows containing '%s', %d remaining", exclude_text, len(self.df))

        if self.df.empty:
            self.logger.warning("No data to analyze after filtering")
            return

        # Extract fields
        self.df = self.extractor.extract_all(self.df)

        # Filter to specific user if provided
        if user:
            self.df = self.df[self.df["userPrincipalName"] == user]
            if self.df.empty:
                self.logger.warning("No data found for user: %s", user)
                return

        # Calculate baselines
        self.baselines = self.baseline_calculator.calculate(self.df)

        # Run detectors
        self.travel_anomalies = self.travel_detector.detect(self.df)
        self.location_anomalies = self.location_detector.detect(self.df, self.baselines)
        self.device_anomalies = self.device_detector.detect(self.df, self.baselines)
        self.failure_spikes = self.failure_detector.detect(self.df)

        # Run ML detection if enabled
        if self.ml_detector:
            self.ml_anomalies = self.ml_detector.detect(self.df, user)

        # Identify compromises
        self.compromises = self.compromise_identifier.identify(
            self.df,
            self.baselines,
            self.travel_anomalies,
            self.location_anomalies,
            user,
        )

        self.logger.info("Analysis complete")

    def print_summary(self) -> None:
        """Print a summary of the analysis results."""
        from polykit.text import color, print_color

        print_color("\n=== Entra Anomaly Analysis Summary ===", "blue")

        if self.df is None or self.df.empty:
            print("No data analyzed")
            return

        # Data summary
        print(f"\nTotal sign-ins: {len(self.df)}")
        print(f"Users analyzed: {len(self.baselines)}")

        # Date range
        min_date = self.df["createdDateTime"].min()
        max_date = self.df["createdDateTime"].max()
        print(f"Date range: {min_date} to {max_date}")

        # Anomaly counts
        print_color("\nAnomalies Detected:", "yellow")
        print(f"  Impossible Travel: {len(self.travel_anomalies)}")
        print(f"  New Locations: {len(self.location_anomalies)}")
        print(f"  New Devices: {len(self.device_anomalies)}")
        print(f"  Failure Spikes: {len(self.failure_spikes)}")
        if self._enable_ml:
            print(f"  ML-Detected: {len(self.ml_anomalies)}")

        total = (
            len(self.travel_anomalies)
            + len(self.location_anomalies)
            + len(self.device_anomalies)
            + len(self.failure_spikes)
            + len(self.ml_anomalies)
        )

        # First compromise
        compromised_users = [u for u, c in self.compromises.items() if c]
        if compromised_users:
            print_color("\nPotential Compromises:", "red")
            for user in compromised_users:
                candidate = self.compromises[user]
                if candidate:
                    print(f"  {user}: {candidate.timestamp} ({candidate.confidence} confidence)")
                    print(f"    Reason: {candidate.reason}")

        if total == 0 and not compromised_users:
            print_color("\nNo significant anomalies detected", "green")

    def generate_report(
        self,
        output_path: str | Path,
        user: str | None = None,
    ) -> None:
        """Generate a markdown report.

        Args:
            output_path: Path to write the report.
            user: Optional specific user for the report.
        """
        if self.df is None:
            self.logger.error("No analysis data - run analyze() first")
            return

        self.reporter.generate_markdown(
            output_path,
            self.df,
            self.baselines,
            self.travel_anomalies,
            self.location_anomalies,
            self.device_anomalies,
            self.failure_spikes,
            self.compromises,
            user,
        )

    def export_anomalies(self, output_path: str | Path) -> None:
        """Export anomalies to CSV.

        Args:
            output_path: Path to write the CSV.
        """
        if self.df is None:
            self.logger.error("No analysis data - run analyze() first")
            return

        self.reporter.export_anomalies_csv(
            output_path,
            self.df,
            self.travel_anomalies,
            self.location_anomalies,
            self.device_anomalies,
            self.failure_spikes,
        )

    def generate_json_report(
        self,
        output_path: str | Path,
        user: str | None = None,
    ) -> None:
        """Generate a JSON report.

        Args:
            output_path: Path to write the JSON report.
            user: Optional specific user for the report.
        """
        if self.df is None:
            self.logger.error("No analysis data - run analyze() first")
            return

        self.reporter.generate_json(
            output_path,
            self.df,
            self.baselines,
            self.travel_anomalies,
            self.location_anomalies,
            self.device_anomalies,
            self.failure_spikes,
            self.compromises,
            self.ml_anomalies if self._enable_ml else None,
            user,
        )
