"""Self-test for `tests/live_server.py` (spec 0022 Phase 0).

A harness that leaks a process or a port is worse than no harness: every
later failure in this spec would look like a bug in whatever feature
happened to be under test, rather than in the thing actually responsible.
This is the Phase-0 acceptance criterion from the spec 0022 work split
(§2.3/§3): start and stop ten instances in a row, then prove nothing was
left behind.
"""

import os
import socket
from pathlib import Path

from live_server import LiveCabin, live_cabin, plain_get


def _process_is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # We could signal it, so it exists and belongs to someone else --
        # should never happen for our own child, but "alive" is the safe
        # answer either way.
        return True
    return True


def _port_is_free(port: int) -> bool:
    with socket.socket() as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
        return True


def test_ten_instances_leave_no_process_and_every_port_rebinds(tmp_path: Path) -> None:
    handles: list[LiveCabin] = []
    for i in range(10):
        with live_cabin(data_dir=tmp_path / f"instance-{i}") as handle:
            handles.append(handle)
            # The demonstration the harness exists to make possible: a real
            # request against a real process, answered correctly.
            resp = plain_get("127.0.0.1", handle.port, "/healthz")
            assert resp.status == 200
            assert b'"status":"ok"' in resp.body or b'"status": "ok"' in resp.body

    for handle in handles:
        assert not _process_is_alive(handle.pid), f"pid {handle.pid} survived teardown"
    for handle in handles:
        assert _port_is_free(handle.port), f"port {handle.port} was not released"
