"""Synchronous dispatch over the immutable CHK.006 route catalog."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .catalog import ROUTE_CATALOG, RouteDescriptor

RouteHandler = Callable[[RouteDescriptor, object], Any]


class RouteNotFoundError(LookupError):
    """Raised before delegation when a route name is not canonical."""

    def __init__(self, route_name: str) -> None:
        """Identify only the rejected route name."""
        self.route_name = route_name
        super().__init__(f"Unknown Prowler route: {route_name}")


class ContractDispatcher:
    """Resolve one canonical route and delegate synchronously exactly once."""

    def __init__(self, handlers: Mapping[str, RouteHandler]) -> None:
        """Copy the bounded route-to-handler mapping."""
        self._handlers = dict(handlers)

    def filter_routes(self, route_names: Sequence[str]) -> tuple[RouteDescriptor, ...]:
        """Return known requested routes once, in canonical order."""
        requested = frozenset(route_names)
        return tuple(route for route in ROUTE_CATALOG if route.route_name in requested)

    def dispatch(self, route_name: str, request: object) -> Any:
        """Reject unknown/unimplemented routes before invoking a handler."""
        route = next(
            (item for item in ROUTE_CATALOG if item.route_name == route_name), None
        )
        if route is None or route_name not in self._handlers:
            raise RouteNotFoundError(route_name)
        return self._handlers[route_name](route, request)
