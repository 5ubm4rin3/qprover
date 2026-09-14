"""Deterministic, process-owned local Anvil execution."""

from __future__ import annotations

import json
import math
import os
import re
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import suppress
from types import MappingProxyType
from typing import Any, Self

from qprover.runtime import current_runtime


class EVMError(RuntimeError):
    """A local process, guarded RPC, snapshot, or transaction failure."""


class RPCError(EVMError):
    """A structurally valid JSON-RPC error returned by owned Anvil."""

    def __init__(self, method: str, code: int) -> None:
        self.method = method
        self.code = code
        super().__init__(f"local RPC {method} failed with code {code}")


class TransactionRejected(EVMError):
    """Anvil deterministically rejected an unlocked local transaction."""


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
_EXPECTED_ACCOUNTS = (
    "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
)
_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)")
_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_MAX_UINT256 = (1 << 256) - 1


def _ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def _quantity(value: int, label: str = "RPC quantity") -> str:
    if type(value) is not int or not 0 <= value <= _MAX_UINT256:
        raise EVMError(f"{label} must be an exact uint256")
    return hex(value)


def _read_quantity(value: object, label: str) -> int:
    if type(value) is not str or _QUANTITY.fullmatch(value) is None:
        raise EVMError(f"local RPC returned invalid {label}")
    parsed = int(value, 16)
    if parsed > _MAX_UINT256:
        raise EVMError(f"local RPC returned invalid {label}")
    return parsed


def _read_bytes(value: object, label: str) -> str:
    if type(value) is not str or _BYTES.fullmatch(value) is None:
        raise EVMError(f"local RPC returned invalid {label}")
    return value


def _read_address(value: object, label: str) -> str:
    if type(value) is not str or _ADDRESS.fullmatch(value) is None:
        raise EVMError(f"local RPC returned invalid {label}")
    return value.lower()


def _read_hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise EVMError(f"local RPC returned invalid {label}")
    return value.lower()


class LocalAnvil:
    """Own one deterministic Anvil process bound exclusively to IPv4 loopback."""

    def __init__(
        self,
        *,
        binary: str = "anvil",
        readiness_timeout: float = 5.0,
        _port_allocator: Callable[[], int] = _ephemeral_port,
        _startup_attempts: int = 3,
    ) -> None:
        if type(binary) is not str or not binary:
            raise ValueError("binary must be a nonempty string")
        if type(readiness_timeout) not in (int, float):
            raise ValueError("readiness_timeout must be positive")
        try:
            timeout = float(readiness_timeout)
        except OverflowError as error:
            raise ValueError("readiness_timeout must be positive") from error
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("readiness_timeout must be positive")
        if not callable(_port_allocator):
            raise ValueError("internal port allocator must be callable")
        if type(_startup_attempts) is not int or _startup_attempts <= 0:
            raise ValueError("internal startup attempts must be positive")
        self._binary = binary
        self._readiness_timeout = timeout
        self._port_allocator = _port_allocator
        self._startup_attempts = _startup_attempts
        self._port: int | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._rpc_id = 0
        self._accounts: tuple[str, ...] = ()
        self._baseline_snapshot_id: str | None = None
        self._metadata: Mapping[str, object] = MappingProxyType({})
        self._runtime_cleanup_token: int | None = None

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

    def _allocate_port(self) -> int:
        port = self._port_allocator()
        if type(port) is not int or not 1 <= port <= 65_535:
            raise EVMError("internal port allocator returned invalid port")
        return port

    def _spawn(self, port: int) -> None:
        command = (
            self._binary,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
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
            runtime = current_runtime()
            if runtime is not None:
                self._runtime_cleanup_token = runtime.register(self.close)
        except OSError as error:
            self._process = None
            self._port = None
            raise EVMError("could not start local Anvil") from error

    def start(self) -> Self:
        if self._process is not None:
            raise EVMError("Anvil instance has already been started")
        foreign_response = False
        for _ in range(self._startup_attempts):
            self._port = self._allocate_port()
            self._spawn(self._port)
            try:
                deadline = time.monotonic() + self._readiness_timeout
                while time.monotonic() < deadline:
                    process = self._process
                    if process is None or process.poll() is not None:
                        break
                    try:
                        chain_id = self._read_chain_id()
                    except EVMError:
                        time.sleep(0.01)
                        continue
                    if chain_id != _CHAIN_ID:
                        foreign_response = True
                        break
                    foreign_response = True
                    try:
                        self._load_metadata()
                    except EVMError:
                        time.sleep(0.01)
                        continue
                    # A responder already bound to the selected port can answer
                    # before the spawned child reports its bind failure.  Require
                    # the child to survive that failure window, then correlate a
                    # second request while it is still alive.
                    time.sleep(0.05)
                    if process.poll() is None and self._read_chain_id() == _CHAIN_ID:
                        return self
                    break
            except BaseException:
                self.close()
                raise
            self.close()
        if foreign_response:
            raise EVMError("could not establish an owned Anvil endpoint")
        raise EVMError("local Anvil readiness timeout")

    def close(self) -> None:
        process = self._process
        if process is None:
            self._clear_runtime()
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
            self._clear_runtime()

    def _clear_runtime(self) -> None:
        runtime = current_runtime()
        if runtime is not None and self._runtime_cleanup_token is not None:
            runtime.unregister(self._runtime_cleanup_token)
        self._runtime_cleanup_token = None
        self._process = None
        self._port = None
        self._accounts = ()
        self._baseline_snapshot_id = None
        self._metadata = MappingProxyType({})

    def _request(self, method: str, params: list[object] | None = None) -> Any:
        if method not in _RPC_METHODS:
            raise EVMError(f"RPC method is not permitted: {method}")
        if self._process is None or self._process.poll() is not None:
            raise EVMError("local Anvil process is not running")
        self._rpc_id += 1
        request_id = self._rpc_id
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
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
        except (
            OSError,
            urllib.error.URLError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise EVMError(f"local RPC request failed for {method}") from error
        if type(decoded) is not dict:
            raise EVMError("malformed JSON-RPC response envelope")
        has_result = "result" in decoded
        has_error = "error" in decoded
        expected_keys = {"jsonrpc", "id", "result" if has_result else "error"}
        if (
            decoded.get("jsonrpc") != "2.0"
            or type(decoded.get("id")) is not int
            or decoded.get("id") != request_id
            or has_result == has_error
            or set(decoded) != expected_keys
        ):
            raise EVMError("malformed JSON-RPC response envelope")
        if has_error:
            error = decoded["error"]
            if (
                type(error) is not dict
                or not {"code", "message"}.issubset(error)
                or set(error) - {"code", "message", "data"}
                or type(error["code"]) is not int
                or type(error["message"]) is not str
            ):
                raise EVMError("malformed JSON-RPC error envelope")
            raise RPCError(method, error["code"])
        return decoded["result"]

    # Kept private as a compatibility spelling for existing scoped tests.
    def _rpc(self, method: str, params: list[object] | None = None) -> Any:
        return self._request(method, params)

    def _read_chain_id(self) -> int:
        return _read_quantity(self._request("eth_chainId"), "chain ID")

    def _load_metadata(self) -> None:
        accounts = self._request("eth_accounts")
        genesis = self._request("eth_getBlockByNumber", ["0x0", False])
        latest = self._request("eth_getBlockByNumber", ["latest", False])
        if type(accounts) is not list:
            raise EVMError("local RPC returned invalid account list")
        normalized_accounts = tuple(
            _read_address(item, "account address") for item in accounts
        )
        if (
            len(normalized_accounts) < len(_EXPECTED_ACCOUNTS)
            or len(set(normalized_accounts)) != len(normalized_accounts)
            or normalized_accounts[: len(_EXPECTED_ACCOUNTS)] != _EXPECTED_ACCOUNTS
        ):
            raise EVMError("local RPC returned nondeterministic account list")
        if type(genesis) is not dict or type(latest) is not dict:
            raise EVMError("local RPC returned invalid block metadata")
        timestamp = _read_quantity(genesis.get("timestamp"), "genesis timestamp")
        base_fee = _read_quantity(latest.get("baseFeePerGas"), "base fee")
        gas_price = _read_quantity(self._request("eth_gasPrice"), "gas price")
        chain_id = self._read_chain_id()
        if (
            chain_id != _CHAIN_ID
            or timestamp != _GENESIS_TIMESTAMP
            or base_fee != 0
            or gas_price != 0
        ):
            raise EVMError("local Anvil metadata is not deterministic")
        self._accounts = normalized_accounts
        self._metadata = MappingProxyType(
            {
                "rpc_url": self.rpc_url,
                "chain_id": chain_id,
                "accounts": self._accounts,
                "genesis_timestamp": timestamp,
                "base_fee_wei": base_fee,
                "gas_price_wei": gas_price,
                "steps_tracing": True,
            }
        )

    def create_baseline(self) -> str:
        snapshot_id = self._request("evm_snapshot")
        _read_quantity(snapshot_id, "snapshot identifier")
        self._baseline_snapshot_id = snapshot_id
        return snapshot_id

    def revert_snapshot(self, snapshot_id: str) -> None:
        _read_quantity(snapshot_id, "snapshot identifier")
        result = self._request("evm_revert", [snapshot_id])
        if type(result) is not bool or not result:
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
        normalized = _read_address(address, "account address")
        result = self._request(
            "anvil_setBalance", [normalized, _quantity(value, "balance")]
        )
        if result is not None:
            raise EVMError("local RPC returned invalid set-balance result")

    def balance(self, address: str) -> int:
        normalized = _read_address(address, "account address")
        return _read_quantity(
            self._request("eth_getBalance", [normalized, "latest"]),
            "account balance",
        )

    def send_transaction(self, transaction: Mapping[str, object]) -> str:
        if type(transaction) is not dict:
            raise EVMError("transaction must be an exact mapping")
        allowed = {"from", "to", "data", "value", "gas"}
        if set(transaction) - allowed or "from" not in transaction:
            raise EVMError("transaction contains unsupported or missing fields")
        sender = _read_address(transaction["from"], "transaction sender")
        if sender not in self._accounts:
            raise EVMError("transaction sender is not an unlocked Anvil account")
        payload: dict[str, object] = {"from": sender}
        if "to" in transaction:
            payload["to"] = _read_address(transaction["to"], "transaction target")
        payload["data"] = _read_bytes(transaction.get("data", "0x"), "calldata")
        for key in ("value", "gas"):
            if key in transaction:
                payload[key] = _quantity(transaction[key], key)  # type: ignore[arg-type]
        try:
            result = self._request("eth_sendTransaction", [payload])
        except RPCError as error:
            if error.code == -32_003:
                raise TransactionRejected("local transaction was rejected") from error
            raise
        return _read_hash(result, "transaction hash")

    def wait_for_receipt(
        self, transaction_hash: str, timeout: float = 5.0
    ) -> dict[str, object]:
        expected_hash = _read_hash(transaction_hash, "transaction hash")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self._request("eth_getTransactionReceipt", [expected_hash])
            if result is None:
                time.sleep(0.01)
                continue
            return self._validate_receipt(result, expected_hash)
        raise EVMError("timed out waiting for local transaction receipt")

    def _validate_receipt(self, value: object, expected_hash: str) -> dict[str, object]:
        if type(value) is not dict:
            raise EVMError("local RPC returned invalid transaction receipt")
        status = _read_quantity(value.get("status"), "receipt status")
        if status not in {0, 1}:
            raise EVMError("local RPC returned invalid receipt status")
        _read_quantity(value.get("gasUsed"), "receipt gas used")
        _read_quantity(value.get("effectiveGasPrice"), "receipt gas price")
        _read_quantity(value.get("blockNumber"), "receipt block number")
        _read_quantity(value.get("transactionIndex"), "receipt transaction index")
        if (
            _read_hash(value.get("transactionHash"), "receipt transaction hash")
            != expected_hash
        ):
            raise EVMError("local RPC returned mismatched receipt transaction hash")
        _read_hash(value.get("blockHash"), "receipt block hash")
        _read_address(value.get("from"), "receipt sender")
        for field in ("to", "contractAddress"):
            if value.get(field) is not None:
                _read_address(value[field], f"receipt {field}")
        return dict(value)

    def call(self, transaction: Mapping[str, object]) -> str:
        if type(transaction) is not dict:
            raise EVMError("call must be an exact mapping")
        allowed = {"from", "to", "data", "value"}
        if set(transaction) - allowed or "to" not in transaction:
            raise EVMError("call contains unsupported or missing fields")
        payload: dict[str, object] = {
            "to": _read_address(transaction["to"], "call target"),
            "data": _read_bytes(transaction.get("data", "0x"), "call data"),
        }
        if "from" in transaction:
            payload["from"] = _read_address(transaction["from"], "call sender")
        if "value" in transaction:
            payload["value"] = _quantity(transaction["value"], "call value")  # type: ignore[arg-type]
        return _read_bytes(self._request("eth_call", [payload, "latest"]), "call data")

    def debug_trace(self, transaction_hash: str) -> Mapping[str, object] | None:
        expected_hash = _read_hash(transaction_hash, "transaction hash")
        try:
            result = self._request("debug_traceTransaction", [expected_hash, {}])
        except RPCError as error:
            if error.code == -32_601:
                return None
            raise
        if type(result) is not dict:
            raise EVMError("local RPC returned invalid debug trace")
        if type(result.get("failed")) is not bool:
            raise EVMError("local RPC returned invalid debug trace failure flag")
        return_value = result.get("returnValue")
        if type(return_value) is not str:
            raise EVMError("local RPC returned invalid debug trace return data")
        prefixed_return = (
            return_value if return_value.startswith("0x") else f"0x{return_value}"
        )
        _read_bytes(prefixed_return, "debug trace return data")
        logs = result.get("structLogs")
        if type(logs) is not list:
            raise EVMError("local RPC returned invalid debug trace struct logs")
        for record in logs:
            if type(record) is not dict:
                raise EVMError("local RPC returned invalid debug trace struct log")
            if (
                type(record.get("depth")) is not int
                or record["depth"] < 0
                or type(record.get("pc")) is not int
                or record["pc"] < 0
                or type(record.get("op")) is not str
                or not record["op"]
            ):
                raise EVMError("local RPC returned invalid debug trace struct log")
        return result

    def transaction_trace(
        self, transaction_hash: str
    ) -> tuple[Mapping[str, object], ...] | None:
        expected_hash = _read_hash(transaction_hash, "transaction hash")
        try:
            result = self._request("trace_transaction", [expected_hash])
        except RPCError as error:
            if error.code == -32_601:
                return None
            raise
        if type(result) is not list:
            raise EVMError("local RPC returned invalid transaction trace")
        records: list[Mapping[str, object]] = []
        for record in result:
            if type(record) is not dict:
                raise EVMError("local RPC returned invalid transaction trace entry")
            action = record.get("action")
            if action is not None:
                if type(action) is not dict:
                    raise EVMError(
                        "local RPC returned invalid transaction trace action"
                    )
                target = action.get("to")
                data = action.get("input")
                if target is not None:
                    _read_address(target, "transaction trace target")
                if data is not None:
                    _read_bytes(data, "transaction trace input")
            records.append(record)
        return tuple(records)
