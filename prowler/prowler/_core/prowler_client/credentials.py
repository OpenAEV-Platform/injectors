"""Cross-platform temporary credential leases."""

import os
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from pydantic import SecretStr


class CredentialCleanupError(RuntimeError):
    """Report failed credential cleanup without exposing credential details."""

    def __init__(self) -> None:
        super().__init__("temporary credential cleanup failed")


@dataclass
class TemporaryCredentialLease:
    """Own one credential path and its per-run temporary directory."""

    path: Path
    directory: Path
    _cleaned: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def cleanup(self) -> None:
        """Idempotently remove the credential file followed by its directory."""
        with self._lock:
            if self._cleaned:
                return
            failed = False
            try:
                self.path.unlink(missing_ok=True)
            except OSError:
                failed = True
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError:
                failed = True
            if failed:
                raise CredentialCleanupError() from None
            self._cleaned = True


@dataclass(frozen=True)
class TemporaryCredentialLeaseFactory:
    """Create closed credential files in unique per-run temporary directories."""

    platform_name: str = os.name
    temporary_root: Path | None = None

    def create(self, content: SecretStr, *, suffix: str) -> TemporaryCredentialLease:
        """Materialize one credential and clean partial resources on failure."""
        directory = Path(
            tempfile.mkdtemp(
                prefix="openaev-prowler-credential-",
                dir=self.temporary_root,
            )
        )
        path = directory / f"{secrets.token_hex(16)}{suffix}"
        lease = TemporaryCredentialLease(path=path, directory=directory)
        try:
            if self.platform_name != "nt":
                os.chmod(directory, 0o700)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if self.platform_name == "nt":
                descriptor = os.open(path, flags)
            else:
                descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as credential_file:
                credential_file.write(content.get_secret_value())
        except BaseException:
            try:
                lease.cleanup()
            except CredentialCleanupError:
                raise CredentialCleanupError() from None
            raise
        return lease
