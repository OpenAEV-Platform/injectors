"""Coordination primitives between Nuclei scans and template maintenance.

The injector runs scans in consumer threads of the main process, while the
periodic template refresh (``nuclei -update-templates``) runs in a forked
child process and rewrites the shared templates directory in place. Without
coordination, a scan that overlaps a refresh reads a half-written template
tree and errors out, returns empty results, or hangs - the root cause of the
"same asset: sometimes green in a minute, sometimes red on timeout" pattern.
"""

import multiprocessing
from contextlib import contextmanager


class TemplateAccessLock:
    """Cross-process readers-writer lock for the shared templates directory.

    Scans are readers: any number of them may run concurrently. The template
    refresh is the writer: it waits for in-flight scans to finish, blocks new
    scans while it rewrites the directory, and releases them once the tree is
    complete again.

    Built on ``multiprocessing`` primitives so it works across the boundary
    the injector actually has: reader threads live in the main process, the
    writer runs in a child process forked from it (the primitives are shared
    through fork inheritance, which is the default start method on Linux
    where the injector container runs).
    """

    def __init__(self):
        self._readers = multiprocessing.Value("i", 0)
        self._readers_lock = multiprocessing.Lock()
        # Held by the writer, or by the group of readers (acquired by the
        # first reader in, released by the last reader out).
        self._resource_lock = multiprocessing.Lock()

    @contextmanager
    def read(self):
        """Shared access: scans hold this while a Nuclei subprocess runs."""
        with self._readers_lock:
            self._readers.value += 1
            if self._readers.value == 1:
                self._resource_lock.acquire()
        try:
            yield
        finally:
            with self._readers_lock:
                self._readers.value -= 1
                if self._readers.value == 0:
                    self._resource_lock.release()

    @contextmanager
    def write(self):
        """Exclusive access: the template refresh holds this while rewriting."""
        self._resource_lock.acquire()
        try:
            yield
        finally:
            self._resource_lock.release()
