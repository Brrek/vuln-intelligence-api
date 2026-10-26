"""Explicit environment configuration. Credentials are never serialized to logs."""

import os
from pathlib import Path

from pydantic import Field, SecretStr

from .models import Model


class Settings(Model):
    database: Path = Path("data/vuln.db")
    live_enabled: bool = False
    tenable_access_key: SecretStr | None = Field(default=None, repr=False)
    tenable_secret_key: SecretStr | None = Field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database=os.getenv("VULN_DB", "data/vuln.db"),
            live_enabled=os.getenv("VULN_ENABLE_LIVE", "false"),
            tenable_access_key=os.getenv("TENABLE_ACCESS_KEY"),
            tenable_secret_key=os.getenv("TENABLE_SECRET_KEY"),
        )

    def require_live(self) -> None:
        if not self.live_enabled:
            raise ValueError("live integrations require VULN_ENABLE_LIVE=true")
