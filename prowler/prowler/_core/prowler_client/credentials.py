"""Secure temporary credential-file materialization."""

import os
import tempfile
from pathlib import Path

from pydantic import SecretStr


class SecureCredentialFileFactory:
    """Write credentials to an owner-only temporary file."""

    def create(self, content: SecretStr) -> Path:
        """Materialize a credential and remove partial files after write failures."""
        descriptor, filename = tempfile.mkstemp()
        path = Path(filename)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as credential_file:
                credential_file.write(content.get_secret_value())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return path
