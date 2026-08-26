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
        if not Path(specification.executable).is_absolute() and not path:
            return ResolutionError(
                "relative executable requires a non-blank PATH in the specification"
            )
        if shutil.which(specification.executable, path=path or "") is None:
            return ResolutionError(
                f"executable is unavailable: {specification.executable}"
            )
        return None
