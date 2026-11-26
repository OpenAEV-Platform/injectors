"""Run nmap and hand each finished host to the caller while the scan goes on.

nmap writes the ``<host>`` element of its XML report (``-oX -``) as soon as the
host (its host group) is finished. Reading stdout as it comes lets the injector
report each host at once instead of waiting for the whole run: a large asset group
no longer gets all its results only at exit, and a run cut by the scan time limit
has already reported every host it finished.

``run_nmap`` keeps the contract of ``subprocess.run(args, capture_output=True,
timeout=...)``: it returns a ``subprocess.CompletedProcess`` with the whole stdout
and stderr, and raises ``subprocess.TimeoutExpired`` (output and stderr attached)
once the time limit is reached, after killing nmap. ``on_host`` is called from the
calling thread, never from a reader thread, so it may use the platform client.
"""

import queue
import re
import subprocess
import threading
import time
from typing import Callable, List, Optional, Tuple

# The start of a <host> element (never <hosthint> nor <hostnames>).
_HOST_START = re.compile(rb"<host[\s>]")
_HOST_END = b"</host>"
# How often the loop wakes up to check the time limit when nmap writes nothing.
_POLL_SECONDS = 0.5
_READ_SIZE = 65536


def split_hosts(buffer: bytes, cursor: int) -> Tuple[List[bytes], int]:
    """The complete <host> elements of ``buffer`` after ``cursor``, and the
    position after the last one (where the next search starts)."""
    hosts: List[bytes] = []
    while True:
        end = buffer.find(_HOST_END, cursor)
        if end < 0:
            return hosts, cursor
        end += len(_HOST_END)
        start = _HOST_START.search(buffer, cursor, end)
        if start is not None:
            hosts.append(buffer[start.start() : end])
        cursor = end


def _pump(stream, sink: "queue.Queue[Optional[bytes]]") -> None:
    try:
        while True:
            chunk = stream.read1(_READ_SIZE)
            if not chunk:
                break
            sink.put(chunk)
    finally:
        sink.put(None)


def _drain(stream, chunks: List[bytes]) -> None:
    for chunk in iter(lambda: stream.read(_READ_SIZE), b""):
        chunks.append(chunk)


def run_nmap(
    args: List[str],
    timeout: Optional[float] = None,
    on_host: Optional[Callable[[bytes], None]] = None,
) -> subprocess.CompletedProcess:
    """Run nmap, call ``on_host`` with each finished <host> element as nmap writes
    it, and return the completed process. Raises subprocess.TimeoutExpired once
    ``timeout`` seconds have passed (nmap killed, what it wrote attached). Any
    error raised by ``on_host`` kills nmap and propagates."""
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline = time.monotonic() + timeout if timeout else None
    chunks: "queue.Queue[Optional[bytes]]" = queue.Queue()
    stderr_chunks: List[bytes] = []
    readers = [
        threading.Thread(target=_pump, args=(process.stdout, chunks), daemon=True),
        threading.Thread(
            target=_drain, args=(process.stderr, stderr_chunks), daemon=True
        ),
    ]
    for reader in readers:
        reader.start()
    buffer = b""
    cursor = 0
    timed_out = False
    try:
        while True:
            wait = _POLL_SECONDS
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                wait = min(wait, remaining)
            try:
                chunk = chunks.get(timeout=wait)
            except queue.Empty:
                continue
            if chunk is None:
                break
            buffer += chunk
            if on_host is not None:
                hosts, cursor = split_hosts(buffer, cursor)
                for host in hosts:
                    on_host(host)
    except BaseException:
        process.kill()
        process.wait()
        raise
    if timed_out:
        process.kill()
    returncode = process.wait()
    for reader in readers:
        reader.join(timeout=5)
    # What the readers got after the loop stopped (a kill, the last chunks).
    while True:
        try:
            chunk = chunks.get_nowait()
        except queue.Empty:
            break
        if chunk is not None:
            buffer += chunk
    stderr = b"".join(stderr_chunks)
    if timed_out:
        raise subprocess.TimeoutExpired(args, timeout, output=buffer, stderr=stderr)
    return subprocess.CompletedProcess(args, returncode, buffer, stderr)
