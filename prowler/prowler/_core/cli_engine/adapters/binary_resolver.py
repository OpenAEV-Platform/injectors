"""Executable availability validation adapter."""

import shutil
from pathlib import Path

from ..contracts import ExecutionSpecification
from ..errors import ResolutionError


class WhichBinaryResolver:
    """Validate the exact executable without replacing it."""

    def validate(self, specification: ExecutionSpecification) -> ResolutionError | None:
        """Check the executable using only the specification environment."""
        path = dict(specification.environment).get("PATH")
        if path is not None and not isinstance(path, str):
            return ResolutionError(
                "PATH must be an ordinary non-blank string when provided"
            )
        if not Path(specification.executable).is_absolute() and (
            not path or not path.strip()
        ):
            return ResolutionError(
                "relative executable requires a non-blank PATH in the specification"
            )
        if shutil.which(specification.executable, path=path or "") is None:
            return ResolutionError(
                f"executable is unavailable: {specification.executable}"
            )
        return None
