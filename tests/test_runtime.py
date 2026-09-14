from __future__ import annotations

import atexit
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from qprover.runtime import ExecutionCancelled, ExecutionRuntime


def test_pending_signal_during_activation_restores_process_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prior = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    original_register = atexit.register
    sent = False

    def register_with_pending_signal(callback):
        nonlocal sent
        if not sent:
            sent = True
            os.kill(os.getpid(), signal.SIGTERM)
        return original_register(callback)

    monkeypatch.setattr(atexit, "register", register_with_pending_signal)

    with (
        pytest.raises(ExecutionCancelled, match="execution cancelled"),
        ExecutionRuntime.activate(),
    ):
        pytest.fail("a pending activation signal must cancel before user code")

    assert {number: signal.getsignal(number) for number in prior} == prior


def test_owned_path_rolls_back_when_creator_mutates_then_raises(tmp_path: Path) -> None:
    target = tmp_path / "partially-created"

    def create(path: Path) -> Path:
        path.mkdir()
        (path / "partial").write_text("partial")
        raise OSError("creator failed after mutation")

    with (
        ExecutionRuntime.activate() as runtime,
        pytest.raises(OSError, match="creator failed"),
    ):
        runtime.own_resource(lambda: create(target), lambda: shutil.rmtree(target))

    assert not target.exists()


def test_failed_explicit_cleanup_remains_owned_for_runtime_retry(
    tmp_path: Path,
) -> None:
    target = tmp_path / "retry-cleanup"
    target.mkdir()
    calls = 0

    def cleanup() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("transient cleanup failure")
        target.rmdir()

    with ExecutionRuntime.activate() as runtime:
        token = runtime.register(cleanup)
        with pytest.raises(OSError, match="transient cleanup failure"):
            runtime.release(token)
        assert target.is_dir()

    assert calls == 2
    assert not target.exists()


@pytest.mark.parametrize("phase", ["build", "search", "minimization", "replay"])
def test_pipeline_sigterm_removes_exact_owned_listener_process_and_temp(
    tmp_path: Path, phase: str
) -> None:
    owned_temp = tmp_path / f"owned-{phase}"
    output = tmp_path / f"output-{phase}"
    script = """
import shutil, sys, time
from pathlib import Path
from qprover.evm import LocalAnvil
from qprover.models import SearchLimits
from qprover.pipeline import prove_violation
from qprover.runtime import current_runtime
from qprover.search.annealing import SimulatedAnnealingBackend
from qprover.search.qubo import QuboStrategy
import qprover.pipeline as pipeline
import qprover.artifacts as artifacts

owned = Path(sys.argv[1])
output = Path(sys.argv[2])
phase = sys.argv[3]

def block():
    runtime = current_runtime()
    assert runtime is not None
    owned.mkdir(mode=0o700)
    runtime.register(lambda: shutil.rmtree(owned, ignore_errors=True))
    with LocalAnvil() as anvil:
        print(f"{anvil.process_id} {anvil.rpc_url.rsplit(':', 1)[1]}", flush=True)
        time.sleep(60)

class BlockingSearch(QuboStrategy):
    def propose(self, remaining_transactions):
        del remaining_transactions
        block()

strategy = QuboStrategy(
    backend=SimulatedAnnealingBackend(), reads=128, resample_attempts=0
)
if phase == "search":
    strategy = BlockingSearch(
        backend=SimulatedAnnealingBackend(), reads=1, resample_attempts=0
    )
elif phase == "build":
    artifacts._build_target_in_workspace = lambda *args, **kwargs: block()
elif phase == "minimization":
    pipeline.minimize = lambda *args, **kwargs: block()
elif phase == "replay":
    pipeline.cold_verify = lambda *args, **kwargs: block()

prove_violation(
    Path.cwd() / "benchmarks/scenario_reentrancy_a.json",
    strategy=strategy,
    seed=7,
    output=output,
    workspace_root=Path.cwd(),
    limits=SearchLimits(
        max_sequence_length=3,
        transaction_budget=3,
        candidate_budget=1,
        wall_seconds=20,
    ),
)
"""
    child = subprocess.Popen(
        (sys.executable, "-c", script, str(owned_temp), str(output), phase),
        cwd=Path(__file__).parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert child.stdout is not None
    identity = child.stdout.readline().strip()
    assert identity, child.stderr.read() if child.stderr is not None else ""
    pid_text, port_text = identity.split()
    owned_pid = int(pid_text)
    owned_port = int(port_text)

    child.send_signal(signal.SIGTERM)
    child.communicate(timeout=10)

    assert child.returncode != 0
    with pytest.raises(ProcessLookupError):
        os.kill(owned_pid, 0)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.1)
        assert probe.connect_ex(("127.0.0.1", owned_port)) != 0
    assert not owned_temp.exists()
    assert not tuple((output / "runs").glob(".*.staging"))


def test_runtime_nesting_restores_handlers_and_cleans_once() -> None:
    prior = {
        number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)
    }
    cleaned: list[str] = []

    with ExecutionRuntime.activate() as outer:
        outer.register(lambda: cleaned.append("owned"))
        with ExecutionRuntime.activate() as inner:
            assert inner is outer

    assert cleaned == ["owned"]
    assert {number: signal.getsignal(number) for number in prior} == prior


def test_top_level_runtime_rejects_non_main_thread() -> None:
    errors: list[BaseException] = []

    def activate_in_worker() -> None:
        try:
            with ExecutionRuntime.activate():
                pass
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=activate_in_worker)
    worker.start()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], RuntimeError)
    assert "main thread" in str(errors[0])
