# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Gradio web application for Purviewer Entra ID sign-in analysis."""

from __future__ import annotations

from typing import Any

import gradio as gr

from purviewer.web.handlers import AnalysisHandler


def create_app() -> gr.Blocks:
    """Create the Gradio application.

    Returns:
        Configured Gradio Blocks application.
    """
    handler = AnalysisHandler()

    def run_analysis(
        file: Any,
        enable_anomalies: bool,
        enable_ml: bool,
        user_filter: str,
        max_speed: int,
        z_score: float,
        geoip_file: Any,
    ) -> tuple[str, str, dict[str, Any], str | None, str | None, str | None]:
        """Run analysis with provided parameters."""
        file_path = file.name if file else None
        geoip_path = geoip_file.name if geoip_file else None

        return handler.analyze(
            file_path=file_path,
            enable_anomalies=enable_anomalies,
            enable_ml=enable_ml,
            user_filter=user_filter,
            max_speed=max_speed,
            z_score_threshold=z_score,
            geoip_db_path=geoip_path,
        )

    # Create the interface
    with gr.Blocks(
        title="Purviewer - Entra Sign-In Analysis",
        theme=gr.themes.Soft(),
    ) as app:
        gr.Markdown(
            """
            # Purviewer - Entra Sign-In Analysis

            Analyze Microsoft Entra ID sign-in logs for security anomalies and potential compromises.
            """
        )

        with gr.Row():
            with gr.Column(scale=1):
                # File upload
                file_input = gr.File(
                    label="Upload Sign-In Logs",
                    file_types=[".json", ".csv"],
                    type="filepath",
                )

                # Analysis options
                with gr.Accordion("Analysis Options", open=True):
                    enable_anomalies = gr.Checkbox(
                        label="Enable Anomaly Detection",
                        value=True,
                    )
                    enable_ml = gr.Checkbox(
                        label="Enable ML Detection (Isolation Forest)",
                        value=False,
                    )
                    user_filter = gr.Textbox(
                        label="Filter by User (optional)",
                        placeholder="john.doe@contoso.com",
                    )

                # Advanced settings
                with gr.Accordion("Advanced Settings", open=False):
                    max_speed = gr.Slider(
                        label="Max Travel Speed (km/h)",
                        minimum=500,
                        maximum=2000,
                        value=900,
                        step=50,
                        info="Speed threshold for impossible travel detection",
                    )
                    z_score = gr.Slider(
                        label="Failure Spike Threshold (σ)",
                        minimum=2.0,
                        maximum=5.0,
                        value=3.0,
                        step=0.5,
                        info="Z-score threshold for failed login spike detection",
                    )
                    geoip_file = gr.File(
                        label="MaxMind GeoLite2 Database (optional)",
                        file_types=[".mmdb"],
                        type="filepath",
                    )

                # Analyze button
                analyze_btn = gr.Button(
                    "Analyze Sign-In Logs",
                    variant="primary",
                    size="lg",
                )

            with gr.Column(scale=2):
                # Results tabs
                with gr.Tabs():
                    with gr.Tab("Summary"):
                        summary_output = gr.Markdown(
                            value="Upload a file and click 'Analyze' to see results."
                        )

                    with gr.Tab("Full Report"):
                        report_output = gr.Markdown()

                    with gr.Tab("Raw Data"):
                        json_output = gr.JSON()

                # Download section
                gr.Markdown("### Download Reports")
                with gr.Row():
                    md_download = gr.File(
                        label="Markdown Report",
                        interactive=False,
                    )
                    json_download = gr.File(
                        label="JSON Report",
                        interactive=False,
                    )
                    csv_download = gr.File(
                        label="Anomalies CSV",
                        interactive=False,
                    )

        # Connect button to handler
        analyze_btn.click(
            fn=run_analysis,
            inputs=[
                file_input,
                enable_anomalies,
                enable_ml,
                user_filter,
                max_speed,
                z_score,
                geoip_file,
            ],
            outputs=[
                summary_output,
                report_output,
                json_output,
                md_download,
                json_download,
                csv_download,
            ],
        )

    return app


def launch_app(port: int = 7860, share: bool = False) -> None:
    """Launch the Gradio application.

    Args:
        port: Port to run the server on.
        share: Whether to create a public share link.
    """
    app = create_app()
    app.launch(
        server_port=port,
        share=share,
        show_error=True,
    )
