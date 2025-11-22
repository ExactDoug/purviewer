# Copyright (c) 2025 Danny Stewart
# Licensed under the MIT License

"""Load and parse Entra ID sign-in log exports (JSON and CSV formats)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pandas as pd
from pandas import DataFrame

if TYPE_CHECKING:
    from logging import Logger


class EntraDataLoader:
    """Load Entra ID sign-in logs from JSON or CSV exports."""

    def __init__(self, logger: Logger) -> None:
        """Initialize the data loader."""
        self.logger = logger
        self._encodings = ["utf-8-sig", "utf-8", "iso-8859-1", "cp1252"]

    def load(self, file_path: str | Path) -> DataFrame:
        """Load sign-in data from a file.

        Args:
            file_path: Path to the JSON or CSV file.

        Returns:
            DataFrame with sign-in data.

        Raises:
            ValueError: If the file format is not supported.
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path)

        if not path.exists():
            msg = f"File not found: {file_path}"
            raise FileNotFoundError(msg)

        suffix = path.suffix.lower()

        if suffix == ".json":
            return self._load_json(path)
        elif suffix == ".csv":
            return self._load_csv(path)
        else:
            msg = f"Unsupported file format: {suffix}. Use .json or .csv"
            raise ValueError(msg)

    def _load_json(self, path: Path) -> DataFrame:
        """Load sign-in data from a JSON file."""
        self.logger.debug("Loading JSON file: %s", path)

        for encoding in self._encodings:
            try:
                with path.open(encoding=encoding) as f:
                    data = json.load(f)

                if isinstance(data, list):
                    df = pd.DataFrame(data)
                elif isinstance(data, dict) and "value" in data:
                    # Handle Graph API format with 'value' wrapper
                    df = pd.DataFrame(data["value"])
                else:
                    msg = "Invalid JSON format: expected array or object with 'value' key"
                    raise ValueError(msg)

                self.logger.info("Loaded %d sign-in records from JSON", len(df))
                return df

            except UnicodeDecodeError:
                continue
            except json.JSONDecodeError as e:
                msg = f"Invalid JSON file: {e}"
                raise ValueError(msg) from e

        msg = f"Could not decode file with any supported encoding: {self._encodings}"
        raise ValueError(msg)

    def _load_csv(self, path: Path) -> DataFrame:
        """Load sign-in data from a CSV file."""
        self.logger.debug("Loading CSV file: %s", path)

        for encoding in self._encodings:
            try:
                df = pd.read_csv(path, encoding=encoding)
                self.logger.info("Loaded %d sign-in records from CSV", len(df))
                return df

            except UnicodeDecodeError:
                continue
            except pd.errors.EmptyDataError as e:
                msg = f"Empty CSV file: {path}"
                raise ValueError(msg) from e
            except pd.errors.ParserError as e:
                msg = f"Invalid CSV format: {e}"
                raise ValueError(msg) from e

        msg = f"Could not decode file with any supported encoding: {self._encodings}"
        raise ValueError(msg)
