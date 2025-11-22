# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Generate reports from Entra ID sign-in analysis."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pandas import DataFrame

from purviewer.entra.baseline import UserBaseline
from purviewer.entra.detectors.failure_spike import FailureSpike
from purviewer.entra.detectors.impossible_travel import TravelAnomaly
from purviewer.entra.detectors.new_device import DeviceAnomaly
from purviewer.entra.detectors.new_location import LocationAnomaly
from purviewer.entra.first_compromise import CompromiseCandidate

if TYPE_CHECKING:
    from logging import Logger

    from purviewer.entra.ml.anomaly_model import MLAnomaly


class EntraReportGenerator:
    """Generate analysis reports in various formats."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the report generator."""
        self.logger = logger

    def generate_markdown(
        self,
        output_path: str | Path,
        df: DataFrame,
        baselines: dict[str, UserBaseline],
        travel_anomalies: list[TravelAnomaly],
        location_anomalies: list[LocationAnomaly],
        device_anomalies: list[DeviceAnomaly],
        failure_spikes: list[FailureSpike],
        compromises: dict[str, CompromiseCandidate | None],
        user: str | None = None,
    ) -> None:
        """Generate a markdown report.

        Args:
            output_path: Path to write the report.
            df: DataFrame with sign-in data.
            baselines: User baselines.
            travel_anomalies: Impossible travel detections.
            location_anomalies: New location detections.
            device_anomalies: New device detections.
            failure_spikes: Failure spike detections.
            compromises: First compromise candidates.
            user: Optional specific user to report on.
        """
        lines: list[str] = []

        # Header
        if user:
            lines.append(f"# Security Incident Report: {user}")
        else:
            lines.append("# Entra Sign-In Analysis Report")

        lines.append("")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

        if not df.empty:
            min_date = df["createdDateTime"].min()
            max_date = df["createdDateTime"].max()
            lines.append(f"**Analysis Period**: {min_date} to {max_date}")
            lines.append(f"**Total Sign-Ins**: {len(df)}")

        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")

        total_anomalies = (
            len(travel_anomalies)
            + len(location_anomalies)
            + len(device_anomalies)
            + len(failure_spikes)
        )
        high_confidence_compromises = [
            c for c in compromises.values()
            if c and c.confidence == "high"
        ]

        if high_confidence_compromises:
            lines.append(f"**CRITICAL**: {len(high_confidence_compromises)} high-confidence compromise(s) detected.")
        elif total_anomalies > 0:
            lines.append(f"**WARNING**: {total_anomalies} anomalies detected across {len(baselines)} user(s).")
        else:
            lines.append("**OK**: No significant anomalies detected.")

        lines.append("")

        # Anomaly counts
        lines.append("### Anomaly Summary")
        lines.append("")
        lines.append(f"- Impossible Travel: {len(travel_anomalies)}")
        lines.append(f"- New Locations: {len(location_anomalies)}")
        lines.append(f"- New Devices: {len(device_anomalies)}")
        lines.append(f"- Failure Spikes: {len(failure_spikes)}")
        lines.append("")

        # First Compromise section
        if any(compromises.values()):
            lines.append("## First Compromise Identification")
            lines.append("")

            for upn, candidate in compromises.items():
                if candidate:
                    lines.append(f"### {upn}")
                    lines.append("")
                    lines.append(f"**Confidence**: {candidate.confidence.upper()}")
                    lines.append(f"**Timestamp**: {candidate.timestamp}")
                    lines.append(f"**IP Address**: {candidate.ip_address}")
                    lines.append(f"**Location**: {candidate.location}")
                    lines.append(f"**Risk Level**: {candidate.risk_level}")
                    lines.append(f"**Reason**: {candidate.reason}")
                    lines.append("")

        # Baselines section
        if baselines:
            lines.append("## User Baselines")
            lines.append("")

            for upn, baseline in baselines.items():
                lines.append(f"### {upn}")
                lines.append("")
                lines.append(f"- **Sign-ins**: {baseline.sign_in_count}")
                lines.append(f"- **Typical IPs**: {', '.join(baseline.ip_addresses[:5]) or 'None'}")
                lines.append(f"- **Typical Countries**: {', '.join(baseline.countries[:3]) or 'None'}")
                lines.append(f"- **Typical Cities**: {', '.join(baseline.cities[:3]) or 'None'}")
                lines.append(f"- **Typical OS**: {', '.join(baseline.operating_systems[:3]) or 'None'}")
                lines.append("")

        # Impossible Travel section
        if travel_anomalies:
            lines.append("## Impossible Travel Detections")
            lines.append("")

            for anomaly in travel_anomalies:
                lines.append(f"### {anomaly.user}")
                lines.append("")
                lines.append(f"- **From**: {anomaly.from_location} at {anomaly.from_time}")
                lines.append(f"- **To**: {anomaly.to_location} at {anomaly.to_time}")
                lines.append(f"- **Distance**: {anomaly.distance_km} km in {anomaly.time_hours} hours")
                lines.append(f"- **Required Speed**: {anomaly.required_speed_kmh} km/h")
                lines.append("")

        # New Location section
        if location_anomalies:
            lines.append("## New Location Detections")
            lines.append("")

            for anomaly in location_anomalies[:20]:  # Limit to 20
                location = f"{anomaly.city}, {anomaly.country}" if anomaly.city else anomaly.country
                risk = "RISKY" if anomaly.is_risky else "normal"
                lines.append(f"- **{anomaly.user}** - {anomaly.timestamp} - {location} ({anomaly.anomaly_type}, {risk})")

            if len(location_anomalies) > 20:
                lines.append(f"- ... and {len(location_anomalies) - 20} more")
            lines.append("")

        # New Device section
        if device_anomalies:
            lines.append("## New Device Detections")
            lines.append("")

            for anomaly in device_anomalies[:20]:  # Limit to 20
                device = f"{anomaly.operating_system or 'Unknown OS'} / {anomaly.browser or 'Unknown browser'}"
                managed = "managed" if anomaly.is_managed else "unmanaged"
                lines.append(f"- **{anomaly.user}** - {anomaly.timestamp} - {device} ({managed})")

            if len(device_anomalies) > 20:
                lines.append(f"- ... and {len(device_anomalies) - 20} more")
            lines.append("")

        # Failure Spikes section
        if failure_spikes:
            lines.append("## Failure Spike Detections")
            lines.append("")

            for spike in failure_spikes:
                lines.append(f"### {spike.user} - {spike.date}")
                lines.append("")
                lines.append(f"- **Failures**: {spike.failure_count} (avg: {spike.average_failures}, z-score: {spike.z_score})")
                lines.append(f"- **IPs**: {', '.join(spike.ip_addresses)}")
                lines.append(f"- **Error Codes**: {', '.join(str(c) for c in spike.error_codes)}")
                lines.append("")

        # Write report
        path = Path(output_path)
        path.write_text("\n".join(lines))
        self.logger.info("Markdown report generated: %s", path)

    def export_anomalies_csv(
        self,
        output_path: str | Path,
        df: DataFrame,
        travel_anomalies: list[TravelAnomaly],
        location_anomalies: list[LocationAnomaly],
        device_anomalies: list[DeviceAnomaly],
        failure_spikes: list[FailureSpike],
    ) -> None:
        """Export anomalies to CSV.

        Args:
            output_path: Path to write the CSV.
            df: DataFrame with sign-in data.
            travel_anomalies: Impossible travel detections.
            location_anomalies: New location detections.
            device_anomalies: New device detections.
            failure_spikes: Failure spike detections.
        """
        rows: list[dict] = []

        # Add travel anomalies
        for a in travel_anomalies:
            rows.append({
                "anomaly_type": "impossible_travel",
                "user": a.user,
                "timestamp": a.to_time,
                "ip_address": a.to_ip,
                "location": a.to_location,
                "detail": f"{a.distance_km}km in {a.time_hours}h ({a.required_speed_kmh}km/h)",
                "is_risky": True,
            })

        # Add location anomalies
        for a in location_anomalies:
            location = f"{a.city}, {a.country}" if a.city else a.country
            rows.append({
                "anomaly_type": a.anomaly_type,
                "user": a.user,
                "timestamp": a.timestamp,
                "ip_address": a.ip_address,
                "location": location,
                "detail": a.anomaly_type,
                "is_risky": a.is_risky,
            })

        # Add device anomalies
        for a in device_anomalies:
            device = f"{a.operating_system or 'Unknown'}/{a.browser or 'Unknown'}"
            rows.append({
                "anomaly_type": "new_device",
                "user": a.user,
                "timestamp": a.timestamp,
                "ip_address": a.ip_address,
                "location": "",
                "detail": device,
                "is_risky": a.is_risky,
            })

        # Add failure spikes
        for s in failure_spikes:
            rows.append({
                "anomaly_type": "failure_spike",
                "user": s.user,
                "timestamp": s.date,
                "ip_address": ", ".join(s.ip_addresses),
                "location": "",
                "detail": f"{s.failure_count} failures (z={s.z_score})",
                "is_risky": True,
            })

        # Write CSV
        import pandas as pd
        export_df = pd.DataFrame(rows)
        export_df.to_csv(output_path, index=False)
        self.logger.info("Anomalies exported to CSV: %s (%d rows)", output_path, len(rows))

    def generate_json(
        self,
        output_path: str | Path,
        df: DataFrame,
        baselines: dict[str, UserBaseline],
        travel_anomalies: list[TravelAnomaly],
        location_anomalies: list[LocationAnomaly],
        device_anomalies: list[DeviceAnomaly],
        failure_spikes: list[FailureSpike],
        compromises: dict[str, CompromiseCandidate | None],
        ml_anomalies: list[MLAnomaly] | None = None,
        user: str | None = None,
    ) -> None:
        """Generate a JSON report for programmatic consumption.

        Args:
            output_path: Path to write the JSON report.
            df: DataFrame with sign-in data.
            baselines: User baselines.
            travel_anomalies: Impossible travel detections.
            location_anomalies: New location detections.
            device_anomalies: New device detections.
            failure_spikes: Failure spike detections.
            compromises: First compromise candidates.
            ml_anomalies: ML-detected anomalies.
            user: Optional specific user to report on.
        """
        report: dict[str, Any] = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "version": "1.0",
                "user_filter": user,
            },
            "summary": {},
            "baselines": {},
            "anomalies": {
                "impossible_travel": [],
                "new_location": [],
                "new_device": [],
                "failure_spike": [],
                "ml_detected": [],
            },
            "compromises": {},
        }

        # Summary
        if not df.empty:
            report["metadata"]["analysis_period"] = {
                "start": str(df["createdDateTime"].min()),
                "end": str(df["createdDateTime"].max()),
            }
            report["metadata"]["total_signins"] = len(df)

        total_anomalies = (
            len(travel_anomalies)
            + len(location_anomalies)
            + len(device_anomalies)
            + len(failure_spikes)
            + (len(ml_anomalies) if ml_anomalies else 0)
        )

        high_confidence = [c for c in compromises.values() if c and c.confidence == "high"]

        report["summary"] = {
            "total_anomalies": total_anomalies,
            "impossible_travel_count": len(travel_anomalies),
            "new_location_count": len(location_anomalies),
            "new_device_count": len(device_anomalies),
            "failure_spike_count": len(failure_spikes),
            "ml_anomaly_count": len(ml_anomalies) if ml_anomalies else 0,
            "high_confidence_compromises": len(high_confidence),
            "users_analyzed": len(baselines),
        }

        # Baselines
        for upn, baseline in baselines.items():
            report["baselines"][upn] = {
                "sign_in_count": baseline.sign_in_count,
                "ip_addresses": baseline.ip_addresses[:10],
                "countries": baseline.countries,
                "cities": baseline.cities[:10],
                "operating_systems": baseline.operating_systems,
                "browsers": baseline.browsers,
                "client_apps": baseline.client_apps,
                "typical_hours": baseline.typical_hours,
                "device_ids": baseline.device_ids[:10],
            }

        # Impossible travel anomalies
        for a in travel_anomalies:
            report["anomalies"]["impossible_travel"].append({
                "user": a.user,
                "from_time": a.from_time,
                "to_time": a.to_time,
                "from_location": a.from_location,
                "to_location": a.to_location,
                "from_ip": a.from_ip,
                "to_ip": a.to_ip,
                "distance_km": a.distance_km,
                "time_hours": a.time_hours,
                "required_speed_kmh": a.required_speed_kmh,
            })

        # New location anomalies
        for a in location_anomalies:
            report["anomalies"]["new_location"].append({
                "user": a.user,
                "timestamp": a.timestamp,
                "ip_address": a.ip_address,
                "country": a.country,
                "city": a.city,
                "anomaly_type": a.anomaly_type,
                "is_risky": a.is_risky,
            })

        # New device anomalies
        for a in device_anomalies:
            report["anomalies"]["new_device"].append({
                "user": a.user,
                "timestamp": a.timestamp,
                "ip_address": a.ip_address,
                "operating_system": a.operating_system,
                "browser": a.browser,
                "is_managed": a.is_managed,
                "is_compliant": a.is_compliant,
                "is_risky": a.is_risky,
            })

        # Failure spikes
        for s in failure_spikes:
            report["anomalies"]["failure_spike"].append({
                "user": s.user,
                "date": s.date,
                "failure_count": s.failure_count,
                "average_failures": s.average_failures,
                "z_score": s.z_score,
                "ip_addresses": s.ip_addresses,
                "error_codes": s.error_codes,
            })

        # ML anomalies
        if ml_anomalies:
            for a in ml_anomalies:
                report["anomalies"]["ml_detected"].append({
                    "user": a.user,
                    "timestamp": a.timestamp,
                    "ip_address": a.ip_address,
                    "anomaly_score": a.anomaly_score,
                    "contributing_factors": a.contributing_factors,
                })

        # Compromises
        for upn, candidate in compromises.items():
            if candidate:
                report["compromises"][upn] = {
                    "timestamp": candidate.timestamp,
                    "ip_address": candidate.ip_address,
                    "location": candidate.location,
                    "risk_level": candidate.risk_level,
                    "confidence": candidate.confidence,
                    "reason": candidate.reason,
                }

        # Write JSON
        path = Path(output_path)
        path.write_text(json.dumps(report, indent=2))
        self.logger.info("JSON report generated: %s", path)
