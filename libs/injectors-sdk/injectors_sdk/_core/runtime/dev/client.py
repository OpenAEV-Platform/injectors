"""Dev client: a local stand-in for the platform client of injectors.

It offers the resource managers an injector calls, and writes each call to the dev sink
instead of sending it; the sink checks it against the payload the platform accepts and
refuses it with a 400 when the platform would. A call only the platform can answer (a
document download, a target search, any manager it does not offer) raises a
``NeedsPlatformError`` naming it. It never opens a network connection.
"""

from typing import Any

from xtm_oaev_sdk import DevSinkPort, NeedsPlatformError, SignatureCallbackPayload

__all__ = ["DevPlatformClient"]

_INJECTS = "/api/injects"


class _InjectorManager:
    """``injector``: the registration, kept in-process (no broker in dev mode)."""

    def create(self, data: Any = None, icon: Any = None, **_: Any) -> dict[str, Any]:
        return {}


class _InjectManager:
    """``inject``: the execution reception and callbacks of an inject."""

    def __init__(self, sink: DevSinkPort) -> None:
        self._sink = sink

    def execution_reception(
        self, inject_id: str, data: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        self._sink.record("POST", f"{_INJECTS}/execution/reception/{inject_id}", data)
        return {}

    def execution_callback(
        self, inject_id: str, data: dict[str, Any], **_: Any
    ) -> dict[str, Any]:
        self._sink.record("POST", f"{_INJECTS}/execution/callback/{inject_id}", data)
        return {}


class _SignatureManager:
    """``signature``: the signatures an injector sends, as the callback carrying them."""

    def __init__(self, sink: DevSinkPort) -> None:
        self._sink = sink

    def send_signatures(
        self, inject_id: str, sig_output: Any, execution_details: Any, **_: Any
    ) -> None:
        # The envelope the platform client posts (``SignatureApiManager``).
        sig_output.normalize_signature_payload()
        body = SignatureCallbackPayload.build_from_models(
            sig_output, execution_details
        ).model_dump(mode="json", exclude_none=True)
        self._sink.record("POST", f"{_INJECTS}/execution/callback/{inject_id}", body)


class _DocumentManager:
    """``document``: documents live on the platform."""

    def download(self, *_: Any, **__: Any) -> bytes:
        raise NeedsPlatformError("document.download")


class _EndpointManager:
    """``endpoint``: resolving targets needs the platform's assets."""

    def searchTargets(self, *_: Any, **__: Any) -> dict[str, Any]:  # noqa: N802
        raise NeedsPlatformError("endpoint.searchTargets")


class DevPlatformClient:
    """The resource managers injectors use, writing to ``sink`` instead of sending.

    Any other manager raises ``NeedsPlatformError`` naming it.
    """

    def __init__(self, sink: DevSinkPort, tape: Any = None) -> None:
        self.sink = sink
        #: The call tape recording or replaying the run's outside calls, if any.
        self.tape = tape
        self.injector = _InjectorManager()
        self.inject = _InjectManager(sink)
        self.signature = _SignatureManager(sink)
        self.document = _DocumentManager()
        self.endpoint = _EndpointManager()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        raise NeedsPlatformError(name)
