"""Cooperative lifetime boundary for exact-owned processes and resources."""

from __future__ import annotations

import atexit
import contextvars
import os
import signal
import subprocess
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from pathlib import Path


class ExecutionCancelled(BaseException):
    """SIGINT/SIGTERM requested cancellation of the active local execution."""


_ACTIVE: contextvars.ContextVar[ExecutionRuntime | None] = contextvars.ContextVar(
    "qprover_execution_runtime", default=None
)


class ExecutionRuntime:
    """Own cancellation and LIFO cleanup for one top-level QProver operation."""

    def __init__(self) -> None:
        self._cancelled = False
        self._signal_number: int | None = None
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._next_token = 0
        self._lock = threading.RLock()
        self._cleaned = False

    @classmethod
    @contextmanager
    def activate(cls) -> Iterator[ExecutionRuntime]:
        existing = _ACTIVE.get()
        if existing is not None:
            yield existing
            return
        runtime = cls()
        token = _ACTIVE.set(runtime)
        prior_handlers: dict[int, object] = {}
        is_main = threading.current_thread() is threading.main_thread()
        if is_main:
            for number in (signal.SIGINT, signal.SIGTERM):
                prior_handlers[number] = signal.getsignal(number)
                signal.signal(number, runtime._handle_signal)
        atexit.register(runtime.cleanup)
        try:
            yield runtime
            runtime.checkpoint()
        finally:
            runtime.cleanup()
            with suppress(Exception):
                atexit.unregister(runtime.cleanup)
            if is_main:
                for number, handler in prior_handlers.items():
                    signal.signal(number, handler)
            _ACTIVE.reset(token)

    def _handle_signal(self, number: int, frame: object) -> None:
        del frame
        self._cancelled = True
        self._signal_number = number
        # Raising from the main-thread handler is required to unwind Python code
        # that is blocked outside runtime.run (for example a strategy plugin).
        raise ExecutionCancelled(f"execution cancelled by signal {number}")

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def checkpoint(self) -> None:
        if self._cancelled:
            number = self._signal_number if self._signal_number is not None else 0
            raise ExecutionCancelled(f"execution cancelled by signal {number}")

    def register(self, cleanup: Callable[[], None]) -> int:
        if not callable(cleanup):
            raise TypeError("cleanup must be callable")
        with self._lock:
            if self._cleaned:
                raise RuntimeError("execution runtime is already cleaned")
            token = self._next_token
            self._next_token += 1
            self._callbacks[token] = cleanup
            return token

    def unregister(self, token: int) -> None:
        with self._lock:
            self._callbacks.pop(token, None)

    def cleanup(self) -> None:
        with self._lock:
            if self._cleaned:
                return
            callbacks = tuple(reversed(tuple(self._callbacks.values())))
            self._callbacks.clear()
            self._cleaned = True
        for callback in callbacks:
            with suppress(BaseException):
                callback()

    @staticmethod
    def _terminate_process(process: subprocess.Popen[str]) -> None:
        if process.poll() is not None:
            with suppress(BaseException):
                process.wait(timeout=0)
            return
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            with suppress(BaseException):
                process.wait(timeout=2)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run an exact-owned process group with cooperative cancellation."""

        self.checkpoint()
        process = subprocess.Popen(
            tuple(command),
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        cleanup_token = self.register(lambda: self._terminate_process(process))
        try:
            while True:
                self.checkpoint()
                try:
                    stdout, stderr = process.communicate(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    if timeout is not None:
                        timeout -= 0.1
                        if timeout <= 0:
                            raise subprocess.TimeoutExpired(command, 0) from None
            self.checkpoint()
            return subprocess.CompletedProcess(
                tuple(command), process.returncode, stdout, stderr
            )
        except BaseException:
            self._terminate_process(process)
            raise
        finally:
            self.unregister(cleanup_token)


def current_runtime() -> ExecutionRuntime | None:
    return _ACTIVE.get()


__all__ = ["ExecutionCancelled", "ExecutionRuntime", "current_runtime"]
