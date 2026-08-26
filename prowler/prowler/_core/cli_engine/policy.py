"""Default execution policy."""

from collections.abc import Callable
from dataclasses import dataclass

from .contracts import ExecutionSpecification
from .errors import PolicyError


@dataclass(frozen=True)
class ExecutionPolicy:
    """Authorize specifications with an optional predicate."""

    allow: Callable[[ExecutionSpecification], bool] | None = None

    def check(self, specification: ExecutionSpecification) -> PolicyError | None:
        """Return a policy result without raising expected failures."""
        if self.allow is None:
            return None
        try:
            permitted = self.allow(specification)
        except Exception:  # predicates are untrusted policy extensions
            return PolicyError(
                "policy evaluation failed", kind="policy_evaluation_failed"
            )
        if not permitted:
            return PolicyError("execution specification rejected")
        return None
