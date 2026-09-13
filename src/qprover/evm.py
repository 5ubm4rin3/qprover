"""Deterministic, process-owned local Anvil execution.

The adapter deliberately exposes a small RPC allow-list.  It cannot attach to a
public endpoint and never requests or returns account private keys.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from types import MappingProxyType
from typing import Any, Self
from urllib.parse import urlsplit


class EVMError(RuntimeError):
    """A local process, guarded RPC, snapshot, or transaction failure."""


_RPC_METHODS = frozenset(
    {
        "anvil_setBalance",
        "debug_traceTransaction",
        "eth_accounts",
        "eth_call",
        "eth_chainId",
        "eth_getBalance",
        "eth_getBlockByNumber",
        "eth_getTransactionReceipt",
        "eth_gasPrice",
        "eth_sendTransaction",
        "evm_revert",
        "evm_snapshot",
        "trace_transaction",
    }
)
_CHAIN_ID = 31_337
_GENESIS_TIMESTAMP = 1_700_000_000


def _loopback_port(rpc_url: str | None) -> int | None:
    if rpc_url is None:
        return None
    try:
        parsed = urlsplit(rpc_url)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except (ValueError, TypeError) as error:
        raise ValueError("rpc_url must be a loopback HTTP endpoint") from error
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or address.version != 4
        or parsed.hostname != "127.0.0.1"
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("rpc_url must be a loopback HTTP endpoint")
    return port


def _ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def _quantity(value: int) -> str:
    if type(value) is not int or value < 0:
        raise ValueError("RPC quantities must be nonnegative exact integers")
    return hex(value)


class LocalAnvil:
    """Own one deterministic Anvil process bound exclusively to IPv4 loopback."""

    def __init__(
        self,
        rpc_url: str | None = None,
        *,
        binary: str = "anvil",
        readiness_timeout: float = 5.0,
    ) -> None:
        port = _loopback_port(rpc_url)
        if not isinstance(binary, str) or not binary:
            raise ValueError("binary must be a nonempty string")
        if type(readiness_timeout) not in (int, float):
            raise ValueError("readiness_timeout must be positive")
        try:
            timeout = float(readiness_timeout)
        except OverflowError as error:
            raise ValueError("readiness_timeout must be positive") from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("readiness_timeout must be positive")
        self._port = port
        self._binary = binary
        self._readiness_timeout = timeout
        self._process: subprocess.Popen[bytes] | None = None
        self._rpc_id = 0
        self._accounts: tuple[str, ...] = ()
        self._baseline_snapshot_id: str | None = None
        self._metadata: Mapping[str, object] = MappingProxyType({})

    @property
    def rpc_url(self) -> str:
        if self._port is None:
            raise EVMError("Anvil has not been started")
        return f"http://127.0.0.1:{self._port}"

    @property
    def process_id(self) -> int | None:
        return self._process.pid if self._process is not None else None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def accounts(self) -> tuple[str, ...]:
        return self._accounts

    @property
    def chain_id(self) -> int:
        return int(self._metadata["chain_id"])

    @property
    def genesis_timestamp(self) -> int:
        return int(self._metadata["genesis_timestamp"])

    @property
    def base_fee_wei(self) -> int:
        return int(self._metadata["base_fee_wei"])

    @property
    def gas_price_wei(self) -> int:
        return int(self._metadata["gas_price_wei"])

    @property
    def metadata(self) -> Mapping[str, object]:
        return self._metadata

    @property
    def baseline_snapshot_id(self) -> str | None:
        return self._baseline_snapshot_id

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def start(self) -> Self:
        if self._process is not None:
            raise EVMError("Anvil instance has already been started")
        if self._port is None:
            self._port = _ephemeral_port()
        command = (
            self._binary,
            "--host",
            "127.0.0.1",
            "--port",
            str(self._port),
            "--silent",
            "--steps-tracing",
            "--chain-id",
            str(_CHAIN_ID),
            "--timestamp",
            str(_GENESIS_TIMESTAMP),
            "--block-base-fee-per-gas",
            "0",
            "--gas-price",
            "0",
            "--disable-min-priority-fee",
        )
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            self._process = None
            raise EVMError("could not start local Anvil") from error

        try:
            deadline = time.monotonic() + self._readiness_timeout
            while time.monotonic() < deadline:
                if self._process.poll() is not None:
                    break
                try:
                    if int(self._rpc("eth_chainId"), 16) == _CHAIN_ID:
                        self._load_metadata()
                        return self
                except EVMError:
                    time.sleep(0.01)
        except BaseException:
            self.close()
            raise
        self.close()
        raise EVMError("local Anvil readiness timeout")

    def close(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            else:
                process.wait(timeout=0)
        finally:
            self._process = None
            self._accounts = ()
            self._baseline_snapshot_id = None
            self._metadata = MappingProxyType({})

    def _load_metadata(self) -> None:
        accounts = self._rpc("eth_accounts")
        genesis = self._rpc("eth_getBlockByNumber", ["0x0", False])
        latest = self._rpc("eth_getBlockByNumber", ["latest", False])
        if (
            not isinstance(accounts, list)
            or not all(isinstance(item, str) for item in accounts)
            or not isinstance(genesis, dict)
            or not isinstance(latest, dict)
        ):
            raise EVMError("local Anvil returned malformed chain metadata")
        self._accounts = tuple(item.lower() for item in accounts)
        self._metadata = MappingProxyType(
            {
                "rpc_url": self.rpc_url,
                "chain_id": int(self._rpc("eth_chainId"), 16),
                "accounts": self._accounts,
                "genesis_timestamp": int(genesis["timestamp"], 16),
                "base_fee_wei": int(latest.get("baseFeePerGas", "0x0"), 16),
                "gas_price_wei": int(self._rpc("eth_gasPrice"), 16),
                "steps_tracing": True,
            }
        )

    def _rpc(self, method: str, params: list[object] | None = None) -> Any:
        if method not in _RPC_METHODS:
            raise EVMError(f"RPC method is not permitted: {method}")
        if self._process is None or self._process.poll() is not None:
            raise EVMError("local Anvil process is not running")
        self._rpc_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._rpc_id,
                "method": method,
                "params": params or [],
            },
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=1) as response:
                decoded = json.loads(response.read())
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise EVMError(f"local RPC request failed for {method}") from error
        if not isinstance(decoded, dict):
            raise EVMError(f"local RPC returned malformed response for {method}")
        error = decoded.get("error")
        if error is not None:
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else None
            raise EVMError(f"local RPC {method} failed ({code}): {message}")
        if "result" not in decoded:
            raise EVMError(f"local RPC omitted result for {method}")
        return decoded["result"]

    def create_baseline(self) -> str:
        snapshot_id = self._rpc("evm_snapshot")
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise EVMError("local RPC returned invalid snapshot identifier")
        self._baseline_snapshot_id = snapshot_id
        return snapshot_id

    def revert_snapshot(self, snapshot_id: str) -> None:
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise EVMError("snapshot identifier must be a nonempty string")
        if self._rpc("evm_revert", [snapshot_id]) is not True:
            raise EVMError("could not revert local snapshot")
        if snapshot_id == self._baseline_snapshot_id:
            self._baseline_snapshot_id = None

    def reset(self) -> str:
        snapshot_id = self._baseline_snapshot_id
        if snapshot_id is None:
            raise EVMError("baseline snapshot is not available")
        self.revert_snapshot(snapshot_id)
        return self.create_baseline()

    def set_balance(self, address: str, value: int) -> None:
        self._rpc("anvil_setBalance", [address, _quantity(value)])

    def balance(self, address: str) -> int:
        result = self._rpc("eth_getBalance", [address, "latest"])
        if not isinstance(result, str):
            raise EVMError("local RPC returned invalid account balance")
        return int(result, 16)

    def send_transaction(self, transaction: Mapping[str, object]) -> str:
        allowed = {"from", "to", "data", "value", "gas"}
        if set(transaction) - allowed:
            raise EVMError("transaction contains unsupported fields")
        payload = dict(transaction)
        for key in ("value", "gas"):
            value = payload.get(key)
            if value is not None:
                payload[key] = _quantity(value)  # type: ignore[arg-type]
        result = self._rpc("eth_sendTransaction", [payload])
        if not isinstance(result, str) or not result.startswith("0x"):
            raise EVMError("local RPC returned invalid transaction hash")
        return result

    def wait_for_receipt(self, transaction_hash: str, timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self._rpc("eth_getTransactionReceipt", [transaction_hash])
            if isinstance(result, dict):
                return result
            time.sleep(0.01)
        raise EVMError("timed out waiting for local transaction receipt")

    def call(self, transaction: Mapping[str, object]) -> str:
        payload = dict(transaction)
        if "value" in payload:
            payload["value"] = _quantity(payload["value"])  # type: ignore[arg-type]
        result = self._rpc("eth_call", [payload, "latest"])
        if not isinstance(result, str):
            raise EVMError("local RPC returned invalid call data")
        return result

    def debug_trace(self, transaction_hash: str) -> Mapping[str, object] | None:
        try:
            result = self._rpc("debug_traceTransaction", [transaction_hash, {}])
        except EVMError as error:
            if "(-32601)" in str(error):
                return None
            raise
        return result if isinstance(result, dict) else None

    def transaction_trace(
        self, transaction_hash: str
    ) -> tuple[Mapping[str, object], ...] | None:
        try:
            result = self._rpc("trace_transaction", [transaction_hash])
        except EVMError as error:
            if "(-32601)" in str(error):
                return None
            raise
        if not isinstance(result, list):
            return None
        return tuple(item for item in result if isinstance(item, dict))
