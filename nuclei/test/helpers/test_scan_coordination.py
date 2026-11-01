import threading
import time

from nuclei.helpers.scan_coordination import TemplateAccessLock


def test_multiple_readers_can_hold_the_lock_at_once():
    # Scans are readers: they must not serialize against each other. A nested
    # read acquisition must not deadlock.
    lock = TemplateAccessLock()
    with lock.read():
        with lock.read():
            pass


def test_writer_waits_for_an_active_reader_then_runs():
    # The refresh (writer) must wait for an in-flight scan (reader) to finish
    # before it rewrites the templates directory, and run once the reader exits.
    lock = TemplateAccessLock()
    events = []
    reader_holding = threading.Event()
    release_reader = threading.Event()

    def reader():
        with lock.read():
            events.append("read-start")
            reader_holding.set()
            release_reader.wait(2)
            events.append("read-end")

    def writer():
        reader_holding.wait(2)
        with lock.write():
            events.append("write")

    t_reader = threading.Thread(target=reader)
    t_writer = threading.Thread(target=writer)
    t_reader.start()
    reader_holding.wait(2)
    t_writer.start()

    # Give the writer a chance to (wrongly) acquire while the reader still holds.
    time.sleep(0.1)
    assert "write" not in events

    release_reader.set()
    t_reader.join(2)
    t_writer.join(2)

    assert events == ["read-start", "read-end", "write"]
