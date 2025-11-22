# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Gradio web interface for Purviewer Entra ID sign-in analysis."""

from __future__ import annotations

from .app import create_app, launch_app

__all__ = [
    "create_app",
    "launch_app",
]
