# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Handler functions for Gradio web interface."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from polykit.log import Loggable

from purviewer.entra import (
    EntraAnomalyAnalyzer,
    EntraDataLoader,
    EntraReportGenerator,
)


class AnalysisHandler(Loggable):
    """Handle analysis requests from the web interface."""

    def __init__(self) -> None:
        """Initialize the analysis handler."""
        super().__init__()
        self._temp_dir = tempfile.mkdtemp(prefix="purviewer_")

    def analyze(
        self,
        file_path: str | None,
        enable_anomalies: bool = True,
        enable_ml: bool = False,
        user_filter: str = "",
        max_speed: int = 900,
        z_score_threshold: float = 3.0,
        geoip_db_path: str | None = None,
    ) -> tuple[str, str, dict[str, Any], str | None, str | None, str | None]:
        """Run analysis on uploaded sign-in logs.

        Args:
            file_path: Path to uploaded file.
            enable_anomalies: Enable anomaly detection.
            enable_ml: Enable ML-based detection.
            user_filter: Filter by specific user.
            max_speed: Max travel speed for impossible travel (km/h).
            z_score_threshold: Z-score threshold for failure spikes.
            geoip_db_path: Optional path to MaxMind GeoLite2 database.

        Returns:
            Tuple of (summary_md, report_md, json_data, md_path, json_path, csv_path).
        """
        if not file_path:
            return (
                "## Error\n\nNo file uploaded. Please upload a JSON or CSV file.",
                "",
                {},
                None,
                None,
                None,
            )

        try:
            # Load data
            loader = EntraDataLoader(self.logger)
            df = loader.load(file_path)

            if df.empty:
                return (
                    "## Error\n\nNo data found in uploaded file.",
                    "",
                    {},
                    None,
                    None,
                    None,
                )

            # Run analysis
            analyzer = EntraAnomalyAnalyzer(
                self.logger,
                enable_ml=enable_ml,
                max_speed_kmh=max_speed,
                z_score_threshold=z_score_threshold,
                geoip_db_path=geoip_db_path,
            )

            # Filter by user if specified
            filter_user = user_filter.strip() if user_filter else None

            # Run analysis
            results = analyzer.analyze(df, user=filter_user)

            # Generate reports
            reporter = EntraReportGenerator(self.logger)

            # Prepare output paths
            md_path = Path(self._temp_dir) / "report.md"
            json_path = Path(self._temp_dir) / "report.json"
            csv_path = Path(self._temp_dir) / "anomalies.csv"

            # Generate markdown report
            reporter.generate_markdown(
                md_path,
                results["df"],
                results["baselines"],
                results["travel_anomalies"],
                results["location_anomalies"],
                results["device_anomalies"],
                results["failure_spikes"],
                results["compromises"],
                user=filter_user,
            )

            # Generate JSON report
            reporter.generate_json(
                json_path,
                results["df"],
                results["baselines"],
                results["travel_anomalies"],
                results["location_anomalies"],
                results["device_anomalies"],
                results["failure_spikes"],
                results["compromises"],
                ml_anomalies=results.get("ml_anomalies"),
                user=filter_user,
            )

            # Export anomalies to CSV
            reporter.export_anomalies_csv(
                csv_path,
                results["df"],
                results["travel_anomalies"],
                results["location_anomalies"],
                results["device_anomalies"],
                results["failure_spikes"],
            )

            # Read markdown report for display
            report_md = md_path.read_text()

            # Create summary
            summary_md = self._create_summary(results)

            # Load JSON for display
            import json
            json_data = json.loads(json_path.read_text())

            return (
                summary_md,
                report_md,
                json_data,
                str(md_path),
                str(json_path),
                str(csv_path),
            )

        except Exception as e:
            self.logger.exception("Analysis failed")
            return (
                f"## Error\n\nAnalysis failed: {e!s}",
                "",
                {},
                None,
                None,
                None,
            )

    def _create_summary(self, results: dict[str, Any]) -> str:
        """Create a summary from analysis results.

        Args:
            results: Analysis results dictionary.

        Returns:
            Markdown summary string.
        """
        travel_count = len(results["travel_anomalies"])
        location_count = len(results["location_anomalies"])
        device_count = len(results["device_anomalies"])
        spike_count = len(results["failure_spikes"])
        ml_count = len(results.get("ml_anomalies", []))
        total = travel_count + location_count + device_count + spike_count + ml_count

        # Count high-confidence compromises
        high_confidence = sum(
            1 for c in results["compromises"].values()
            if c and c.confidence == "high"
        )

        # Build summary
        lines = ["## Analysis Summary\n"]

        # Status indicator
        if high_confidence > 0:
            lines.append(f"**CRITICAL**: {high_confidence} high-confidence compromise(s) detected.\n")
        elif total > 0:
            lines.append(f"**WARNING**: {total} anomalies detected.\n")
        else:
            lines.append("**OK**: No significant anomalies detected.\n")

        # Data info
        df = results["df"]
        if not df.empty:
            lines.append(f"**Records analyzed**: {len(df)}")
            lines.append(f"**Users analyzed**: {len(results['baselines'])}")
            min_date = df["createdDateTime"].min()
            max_date = df["createdDateTime"].max()
            lines.append(f"**Date range**: {min_date.date()} to {max_date.date()}\n")

        # Anomaly counts
        lines.append("### Anomaly Breakdown\n")
        lines.append(f"- Impossible Travel: **{travel_count}**")
        lines.append(f"- New Locations: **{location_count}**")
        lines.append(f"- New Devices: **{device_count}**")
        lines.append(f"- Failure Spikes: **{spike_count}**")
        if ml_count > 0:
            lines.append(f"- ML Detected: **{ml_count}**")

        # Compromises
        if any(results["compromises"].values()):
            lines.append("\n### Potential Compromises\n")
            for upn, candidate in results["compromises"].items():
                if candidate:
                    lines.append(f"- **{upn}**: {candidate.timestamp} ({candidate.confidence} confidence)")

        return "\n".join(lines)

    def cleanup(self) -> None:
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self._temp_dir)
        except Exception:
            pass
