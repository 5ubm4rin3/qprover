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
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("top-level execution runtime requires the main thread")
        runtime = cls()
        prior_handlers: dict[int, object] = {}
        token: contextvars.Token[ExecutionRuntime | None] | None = None
        try:
            with runtime._blocked_signals():
                token = _ACTIVE.set(runtime)
                for number in (signal.SIGINT, signal.SIGTERM):
                    prior_handlers[number] = signal.getsignal(number)
                    signal.signal(number, runtime._handle_signal)
                atexit.register(runtime.cleanup)
        except BaseException:
            with runtime._blocked_signals():
                runtime.cleanup()
                with suppress(Exception):
                    atexit.unregister(runtime.cleanup)
                for number, handler in prior_handlers.items():
                    signal.signal(number, handler)
                if token is not None:
                    _ACTIVE.reset(token)
            raise
        try:
            yield runtime
            runtime.checkpoint()
        finally:
            with runtime._blocked_signals():
                runtime.cleanup()
                with suppress(Exception):
                    atexit.unregister(runtime.cleanup)
                for number, handler in prior_handlers.items():
                    signal.signal(number, handler)
                assert token is not None
                _ACTIVE.reset(token)

    @contextmanager
    def _blocked_signals(self) -> Iterator[None]:
        """Defer cooperative cancellation across ownership hand-off windows."""

        if not hasattr(signal, "pthread_sigmask"):
            yield
            return
        blocked = {signal.SIGINT, signal.SIGTERM}
        prior = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            yield
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior)

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

    def own_path(
        self, create: Callable[[], Path], cleanup: Callable[[Path], None]
    ) -> tuple[Path, int]:
        """Create and register one exact cleanup target while signals are blocked."""

        with self._blocked_signals():
            self.checkpoint()
            path = create()
            try:
                token = self.register(lambda owned=path: cleanup(owned))
            except BaseException:
                with suppress(BaseException):
                    cleanup(path)
                raise
        return path, token

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

    def spawn(
        self,
        command: Sequence[str],
        **kwargs: object,
    ) -> tuple[subprocess.Popen[object], int]:
        """Spawn and register exactly one new-session process group atomically."""

        with self._blocked_signals():
            self.checkpoint()
            process = subprocess.Popen(
                tuple(command), start_new_session=True, **kwargs  # type: ignore[arg-type]
            )
            try:
                token = self.register(lambda: self._terminate_process(process))
            except BaseException:
                self._terminate_process(process)
                raise
        return process, token

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
        process, cleanup_token = self.spawn(
            command,
            cwd=cwd,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
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
