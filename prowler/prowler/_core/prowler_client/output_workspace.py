"""Controlled temporary workspaces for Prowler OCSF output artifacts."""

import errno
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Literal

OUTPUT_ARTIFACT_BASENAME = "findings"
OUTPUT_ARTIFACT_FILENAME = "findings.ocsf.json"
DEFAULT_MAXIMUM_ARTIFACT_BYTES = 100 * 1024 * 1024
# Reserve space for Prowler's nested/temporary output beyond the accepted artifact.
DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024

OutputBackend = Literal["memory_tmpfs", "filesystem_temp"]
OutputArtifactErrorKind = Literal["missing", "nonregular", "unreadable", "oversized"]

_ARTIFACT_MESSAGES: dict[OutputArtifactErrorKind, str] = {
    "missing": "Prowler output artifact is missing",
    "nonregular": "Prowler output artifact is not a regular file",
    "unreadable": "Prowler output artifact could not be read",
    "oversized": "Prowler output artifact exceeds the accepted size",
}


class OutputArtifactError(RuntimeError):
    """Report a closed artifact failure without filesystem details."""

    def __init__(
        self, kind: OutputArtifactErrorKind, *, command_result: object | None = None
    ) -> None:
        self.kind = kind
        self.command_result = command_result
        super().__init__(_ARTIFACT_MESSAGES[kind])


class OutputWorkspacePreparationError(RuntimeError):
    """Report output-workspace creation failure without filesystem details."""

    def __init__(self) -> None:
        self.command_result: object | None = None
        super().__init__("temporary output workspace preparation failed")


class OutputWorkspaceCleanupError(RuntimeError):
    """Report output-workspace cleanup failure without filesystem details."""

    def __init__(self, *, command_result: object | None = None) -> None:
        self.command_result = command_result
        super().__init__("temporary output workspace cleanup failed")


@dataclass
class TemporaryOutputWorkspace:
    """Own one unique temporary directory and its exact OCSF artifact path."""

    directory: Path
    backend: OutputBackend
    _temporary_directory: tempfile.TemporaryDirectory[str] = field(repr=False)
    _cleaned: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def artifact_path(self) -> Path:
        """Return the one accepted artifact path inside this workspace."""
        return self.directory / OUTPUT_ARTIFACT_FILENAME

    def read_artifact(
        self, *, maximum_bytes: int = DEFAULT_MAXIMUM_ARTIFACT_BYTES
    ) -> bytes:
        """Read only the exact regular, non-symlink artifact up to its bound."""
        if maximum_bytes < 0:
            raise ValueError("maximum artifact bytes must be nonnegative")

        try:
            path_status = self.artifact_path.lstat()
        except FileNotFoundError:
            raise OutputArtifactError("missing") from None
        except OSError:
            raise OutputArtifactError("unreadable") from None
        if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISREG(path_status.st_mode):
            raise OutputArtifactError("nonregular")

        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.artifact_path, flags)
        except FileNotFoundError:
            raise OutputArtifactError("missing") from None
        except OSError as error:
            kind: OutputArtifactErrorKind = (
                "nonregular" if error.errno == errno.ELOOP else "unreadable"
            )
            raise OutputArtifactError(kind) from None

        chunks: list[bytes] = []
        total = 0
        read_failed = False
        try:
            try:
                opened_status = os.fstat(descriptor)
            except OSError:
                raise OutputArtifactError("unreadable") from None
            if not stat.S_ISREG(opened_status.st_mode):
                raise OutputArtifactError("nonregular")
            if (opened_status.st_dev, opened_status.st_ino) != (
                path_status.st_dev,
                path_status.st_ino,
            ):
                raise OutputArtifactError("nonregular")

            while total <= maximum_bytes:
                requested = min(_READ_CHUNK_BYTES, maximum_bytes + 1 - total)
                try:
                    chunk = os.read(descriptor, requested)
                except OSError:
                    read_failed = True
                    raise OutputArtifactError("unreadable") from None
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
            raise OutputArtifactError("oversized")
        finally:
            try:
                os.close(descriptor)
            except OSError:
                if not read_failed:
                    raise OutputArtifactError("unreadable") from None

    def cleanup(self) -> None:
        """Idempotently remove only this workspace's recursively owned tree."""
        with self._lock:
            if self._cleaned:
                return
            try:
                self._temporary_directory.cleanup()
            except BaseException:
                raise OutputWorkspaceCleanupError() from None
            self._cleaned = True


@dataclass(frozen=True)
class TemporaryOutputWorkspaceFactory:
    """Create private memory-first workspaces with a portable temp fallback."""

    platform_name: str = os.name
    memory_root: Path = Path("/dev/shm")  # noqa: S108 - approved Linux tmpfs root
    temporary_root: Path | None = None

    def create(self) -> TemporaryOutputWorkspace:
        """Create one unique controlled output workspace."""
        root, backend = self._select_root()
        try:
            temporary_directory = tempfile.TemporaryDirectory(
                prefix="openaev-prowler-output-", dir=root
            )
        except BaseException:
            if backend != "memory_tmpfs":
                raise OutputWorkspacePreparationError() from None
            root, backend = self.temporary_root, "filesystem_temp"
            try:
                temporary_directory = tempfile.TemporaryDirectory(
                    prefix="openaev-prowler-output-", dir=root
                )
            except BaseException:
                raise OutputWorkspacePreparationError() from None

        directory = Path(temporary_directory.name)
        try:
            if self.platform_name != "nt":
                os.chmod(directory, 0o700)
        except BaseException:
            try:
                temporary_directory.cleanup()
            except BaseException:  # noqa: S110 - preserve the safe primary error
                pass
            raise OutputWorkspacePreparationError() from None
        return TemporaryOutputWorkspace(
            directory=directory,
            backend=backend,
            _temporary_directory=temporary_directory,
        )

    def _select_root(self) -> tuple[Path | None, OutputBackend]:
        if self.platform_name != "nt":
            try:
                required_capacity = (
                    DEFAULT_MAXIMUM_ARTIFACT_BYTES
                    + DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES
                )
                memory_is_usable = (
                    self.memory_root.exists()
                    and self.memory_root.is_dir()
                    and os.access(self.memory_root, os.W_OK)
                    and shutil.disk_usage(self.memory_root).free >= required_capacity
                )
            except Exception:
                memory_is_usable = False
            if memory_is_usable:
                return self.memory_root, "memory_tmpfs"
        return self.temporary_root, "filesystem_temp"
