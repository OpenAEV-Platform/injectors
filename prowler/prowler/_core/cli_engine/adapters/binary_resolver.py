"""Executable availability validation adapter."""

import shutil

from ..contracts import ExecutionSpecification
from ..errors import ResolutionError


class WhichBinaryResolver:
    """Validate the exact executable without replacing it."""

    def validate(self, specification: ExecutionSpecification) -> ResolutionError | None:
        """Check PATH from the exact environment when supplied."""
        path = dict(specification.environment).get("PATH")
        if shutil.which(specification.executable, path=path) is None:
            return ResolutionError(
                f"executable is unavailable: {specification.executable}"
            )
        return None
