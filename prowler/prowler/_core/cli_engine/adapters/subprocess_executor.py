"""Safe subprocess execution adapter."""

import subprocess
import threading
import time
from typing import IO

from pydantic import SecretStr

from ..contracts import ExecutionSpecification, ProcessOutcome
from ..errors import ExecutionError

_READ_CHUNK_BYTES = 64 * 1024


class _BoundedCapture:
    """Collect stdout and stderr under one combined byte budget."""

    def __init__(self, process: subprocess.Popen[bytes], limit: int) -> None:
        self._process = process
        self._remaining = limit
        self._lock = threading.Lock()
        self.exceeded = False
        self.stdout = bytearray()
        self.stderr = bytearray()

    def drain(self, stream: IO[bytes], sink: bytearray) -> None:
        """Keep bytes until the shared budget is spent, then stop the process."""
        while chunk := stream.read1(_READ_CHUNK_BYTES):  # type: ignore[attr-defined]
            with self._lock:
                kept = chunk[: self._remaining]
                sink.extend(kept)
                self._remaining -= len(kept)
                if len(kept) < len(chunk):
                    self.exceeded = True
            if self.exceeded:
                self._process.kill()
                return


def _feed(stream: IO[bytes], input_bytes: bytes) -> None:
    """Write stdin like subprocess.run, tolerating a child that exits early."""
    try:
        stream.write(input_bytes)
    except BrokenPipeError:
        pass
    finally:
        try:
            stream.close()
        except BrokenPipeError:
            pass


class SubprocessExecutor:
    """Execute structured argv with shell disabled and bounded output capture."""

    def execute(
        self, specification: ExecutionSpecification
    ) -> ProcessOutcome | ExecutionError:
        """Capture exact bytes within the accepted size and envelope failures."""
        environment = {
            name: value.get_secret_value() if isinstance(value, SecretStr) else value
            for name, value in specification.environment
        }
        deadline = time.monotonic() + specification.timeout_seconds
        try:
            process = subprocess.Popen(  # noqa: S603 - policy-approved structured argv
                specification.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=specification.working_directory,
                env=environment,
                shell=False,
            )
        except (OSError, ValueError) as error:
            # ValueError covers arguments, environment or paths that the OS
            # cannot accept, such as embedded NUL characters.
            return ExecutionError(
                "process could not be started",
                kind="process_start_failed",
                cause=type(error).__name__,
            )
        capture = _BoundedCapture(process, specification.maximum_accepted_output_bytes)
        workers = [
            threading.Thread(
                target=capture.drain, args=(process.stdout, capture.stdout), daemon=True
            ),
            threading.Thread(
                target=capture.drain, args=(process.stderr, capture.stderr), daemon=True
            ),
            threading.Thread(
                target=_feed,
                args=(process.stdin, specification.input_bytes),
                daemon=True,
            ),
        ]
        for worker in workers:
            worker.start()
        timed_out = False
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        for worker in workers:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            timed_out = True
        stdout, stderr = bytes(capture.stdout), bytes(capture.stderr)
        if capture.exceeded:
            return ExecutionError(
                "captured process output exceeds the accepted size",
                kind="output_too_large_after_capture",
                stdout=stdout,
                stderr=stderr,
            )
        if timed_out:
            return ExecutionError(
                "process timed out",
                kind="timeout",
                stdout=stdout,
                stderr=stderr,
                cause=subprocess.TimeoutExpired.__name__,
            )
        return ProcessOutcome(process.returncode, stdout, stderr)
