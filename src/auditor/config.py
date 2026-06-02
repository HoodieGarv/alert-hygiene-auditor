"""Application configuration.

Configuration is separated from code so that the same package can connect to
different infrastructure without modification — only the environment or config
file changes.  The resolution order is:

    1. Environment variable (highest priority)
    2. YAML config file (path controlled by the SETTINGS_FILE env var,
       defaulting to config/settings.yaml)
    3. Hard-coded default in the field declaration (lowest priority)

This makes the auditor usable both as a local development stack pointed at
docker-compose containers and as a production service pointed at real
infrastructure, without rebuilding images or changing source code.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource

# Path to the YAML config file.  Override by setting SETTINGS_FILE in the
# environment before starting the process.
_SETTINGS_FILE = os.environ.get("SETTINGS_FILE", "config/settings.yaml")


class _YamlSource(PydanticBaseSettingsSource):
    """Custom pydantic-settings source that reads from a YAML file.

    Keys in the YAML file are matched case-insensitively against pydantic
    field names, so both ``prometheus_url`` and ``PROMETHEUS_URL`` work.
    Missing files are silently ignored so that the service starts without
    a config file when all required values are supplied via environment
    variables.
    """

    def _load(self) -> dict[str, Any]:
        try:
            with open(_SETTINGS_FILE) as fh:
                return yaml.safe_load(fh) or {}
        except FileNotFoundError:
            return {}

    def get_field_value(
        self, field: Any, field_name: str
    ) -> tuple[Any, str, bool]:
        data = self._load()
        # Accept the field name in both lowercase and uppercase so that the
        # YAML file can use either convention.
        value = data.get(field_name) or data.get(field_name.upper())
        return value, field_name, False

    def __call__(self) -> dict[str, Any]:
        return {
            field_name: value
            for field_name in self.settings_cls.model_fields
            for value, _, _ in [self.get_field_value(None, field_name)]
            if value is not None
        }


class Settings(BaseSettings):
    """Central configuration object for the alert hygiene auditor."""

    prometheus_url: str = Field(default="http://localhost:9090")
    alertmanager_url: str = Field(default="http://localhost:9093")
    database_url: str = Field(
        default="postgresql://auditor:auditor_dev_only@localhost:5432/auditor"
    )
    # Number of days of alert history to fetch on the very first ingestion run.
    lookback_days: int = Field(default=30)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # env_settings takes precedence; the YAML file is the fallback.
        # init_settings, dotenv_settings, and secrets_dir are not used.
        return (env_settings, _YamlSource(settings_cls))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (constructed once, cached forever)."""
    return Settings()
