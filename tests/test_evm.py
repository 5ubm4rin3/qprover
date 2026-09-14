from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from qprover.evm import EVMError, LocalAnvil, RPCError, TransactionRejected
from qprover.runtime import ExecutionRuntime


class _LiveProcess:
    pid = 1

    def poll(self) -> None:
        return None


@contextmanager
def _fake_loopback_rpc(
    responder: Callable[[dict], dict | bytes],
) -> Iterator[tuple[int, list[dict]]]:
    requests: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
            length = int(self.headers["content-length"])
            request = json.loads(self.rfile.read(length))
            requests.append(request)
            response = responder(request)
            payload = (
                response
                if isinstance(response, bytes)
                else json.dumps(response).encode()
            )
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _attach_fake_process(anvil: LocalAnvil, port: int) -> None:
    anvil._port = port
    anvil._process = _LiveProcess()  # type: ignore[assignment]


def _unused_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


@pytest.fixture
def anvil() -> Iterator[LocalAnvil]:
    with LocalAnvil() as instance:
        yield instance


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def test_anvil_is_deterministic_local_and_does_not_expose_keys(
    anvil: LocalAnvil,
) -> None:
    assert anvil.rpc_url.startswith("http://127.0.0.1:")
    assert anvil.chain_id == 31337
    assert len(anvil.accounts) >= 2
    assert anvil.accounts[:2] == (
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    )
    assert anvil.genesis_timestamp == 1_700_000_000
    assert anvil.base_fee_wei == 0
    assert anvil.gas_price_wei == 0
    rendered = repr(anvil.metadata).lower()
    assert "private" not in rendered
    assert "mnemonic" not in rendered
    assert "key" not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "https://mainnet.example.invalid",
        "http://192.0.2.1:8545",
        "http://localhost.example.invalid:8545",
        "ws://127.0.0.1:8545",
    ],
)
def test_anvil_rejects_external_or_non_http_rpc_endpoints(url: str) -> None:
    with pytest.raises(TypeError, match="rpc_url"):
        LocalAnvil(rpc_url=url)  # type: ignore[call-arg]


def test_snapshot_revert_immediately_replaces_one_use_baseline(
    anvil: LocalAnvil,
) -> None:
    first = anvil.create_baseline()
    anvil.set_balance(anvil.accounts[0], 123)

    second = anvil.reset()

    assert second != first
    assert anvil.baseline_snapshot_id == second
    assert anvil.balance(anvil.accounts[0]) != 123
    with pytest.raises(EVMError, match="snapshot"):
        anvil.revert_snapshot(first)


def test_anvil_process_group_is_cleaned_after_normal_exit() -> None:
    with LocalAnvil() as instance:
        pid = instance.process_id
        assert pid is not None and _process_exists(pid)

    assert not _process_exists(pid)
    assert not instance.running


def test_anvil_process_group_is_cleaned_when_context_body_raises() -> None:
    instance: LocalAnvil | None = None
    with pytest.raises(RuntimeError, match="body failed"), LocalAnvil() as running:
        instance = running
        pid = running.process_id
        raise RuntimeError("body failed")

    assert instance is not None
    assert not _process_exists(pid)
    assert not instance.running


def test_anvil_failed_runtime_cleanup_is_retried_at_runtime_exit() -> None:
    class StoppedProcess:
        pid = 123

        def poll(self):
            return 0

        def wait(self, timeout=None):
            del timeout
            return 0

    instance = LocalAnvil()
    calls = 0

    def cleanup() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("transient process cleanup")

    with ExecutionRuntime.activate() as runtime:
        token = runtime.register(cleanup)
        instance._process = StoppedProcess()  # type: ignore[assignment]
        instance._runtime_cleanup_token = token
        instance._runtime_owner = runtime
        with pytest.raises(OSError, match="transient process cleanup"):
            instance.close()

    assert calls == 2


def test_anvil_start_failure_is_normalized_and_leaves_no_process() -> None:
    instance = LocalAnvil(binary="/usr/bin/false", readiness_timeout=0.2)

    with pytest.raises(EVMError, match="readiness"):
        instance.start()

    assert instance.process_id is None
    assert not instance.running


def test_anvil_metadata_failure_cleans_started_process_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = LocalAnvil()
    process_ids: list[int] = []
    original_close = instance.close

    def record_close() -> None:
        if instance.process_id is not None:
            process_ids.append(instance.process_id)
        original_close()

    monkeypatch.setattr(instance, "close", record_close)
    monkeypatch.setattr(
        instance,
        "_load_metadata",
        lambda: (_ for _ in ()).throw(ValueError("malformed metadata")),
    )

    with pytest.raises(ValueError, match="malformed metadata"):
        instance.start()

    assert len(process_ids) == 1
    assert not _process_exists(process_ids[0])
    assert instance.process_id is None


@pytest.mark.parametrize("timeout", [True, 0, -1, float("nan"), float("inf"), 10**1000])
def test_anvil_rejects_invalid_readiness_timeouts(timeout: object) -> None:
    with pytest.raises(ValueError, match="readiness_timeout"):
        LocalAnvil(readiness_timeout=timeout)  # type: ignore[arg-type]


def test_anvil_rpc_surface_rejects_unapproved_methods(anvil: LocalAnvil) -> None:
    with pytest.raises(EVMError, match="not permitted"):
        anvil._rpc("eth_sendRawTransaction", ["0x00"])

    with pytest.raises(EVMError, match="not permitted"):
        anvil._rpc("anvil_setCode", [anvil.accounts[0], "0x00"])


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request: {"jsonrpc": "1.0", "id": request["id"], "result": "0x1"},
        lambda request: {"jsonrpc": "2.0", "id": request["id"] + 1, "result": "0x1"},
        lambda request: {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": "0x1",
            "error": {"code": -1, "message": "both"},
        },
        lambda request: {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": True, "message": 7},
        },
    ],
)
def test_rpc_rejects_uncorrelated_or_malformed_envelopes(mutate) -> None:
    with _fake_loopback_rpc(mutate) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)

        with pytest.raises(EVMError, match="JSON-RPC"):
            anvil._request("eth_chainId")


def test_consumed_chain_id_rejects_non_hex_quantity() -> None:
    def respond(request: dict) -> dict:
        results = {
            "eth_chainId": ["0x7a69"],
            "eth_accounts": [],
            "eth_getBlockByNumber": {},
            "eth_gasPrice": "0x0",
        }
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": results[request["method"]],
        }

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)

        with pytest.raises(EVMError, match="chain ID"):
            anvil._read_chain_id()


def test_rpc_rejects_non_utf8_response_body() -> None:
    with _fake_loopback_rpc(lambda request: b"\xff") as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)

        with pytest.raises(EVMError, match="request failed"):
            anvil._request("eth_chainId")


def test_consumed_balance_rejects_quantity_above_uint256() -> None:
    def respond(request: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": "0x1" + "0" * 64,
        }

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)

        with pytest.raises(EVMError, match="account balance"):
            anvil.balance("0x" + "11" * 20)


def test_receipt_and_traces_reject_malformed_local_rpc_results() -> None:
    transaction_hash = "0x" + "11" * 32

    def respond(request: dict) -> dict:
        results = {
            "eth_getTransactionReceipt": {"status": "0x1", "gasUsed": "wat"},
            "debug_traceTransaction": {
                "failed": False,
                "returnValue": "0x",
                "structLogs": [{"depth": True, "pc": 0, "op": "STOP"}],
            },
            "trace_transaction": [{"action": {"to": "not-an-address", "input": "0x"}}],
        }
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": results[request["method"]],
        }

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)

        with pytest.raises(EVMError, match="receipt"):
            anvil.wait_for_receipt(transaction_hash, timeout=0.1)
        with pytest.raises(EVMError, match="debug trace"):
            anvil.debug_trace(transaction_hash)
        with pytest.raises(EVMError, match="transaction trace"):
            anvil.transaction_trace(transaction_hash)


def test_prebound_foreign_responder_is_not_accepted_as_spawned_anvil() -> None:
    def respond(request: dict) -> dict:
        method = request["method"]
        result = {
            "eth_chainId": "0x7a69",
            "eth_accounts": [
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            ],
            "eth_getBlockByNumber": {
                "timestamp": "0x6553f100",
                "baseFeePerGas": "0x0",
            },
            "eth_gasPrice": "0x0",
        }[method]
        return {"jsonrpc": "2.0", "id": request["id"], "result": result}

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil(
            readiness_timeout=0.3,
            _port_allocator=lambda: port,
            _startup_attempts=1,
        )

        with pytest.raises(EVMError, match="owned Anvil"):
            anvil.start()

        assert anvil.process_id is None
        assert not anvil.running


def test_anvil_retries_a_port_collision_with_a_new_ephemeral_port() -> None:
    def respond(request: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request["id"], "result": "0x7a69"}

    with _fake_loopback_rpc(respond) as (occupied_port, _):
        available_port = _unused_port()
        ports = iter((occupied_port, available_port))
        with LocalAnvil(
            readiness_timeout=0.3,
            _port_allocator=lambda: next(ports),
            _startup_attempts=2,
        ) as anvil:
            pid = anvil.process_id
            assert anvil.rpc_url == f"http://127.0.0.1:{available_port}"
            assert pid is not None and _process_exists(pid)

    assert not _process_exists(pid)


@pytest.mark.parametrize(
    ("code", "expected"),
    [(-32_003, TransactionRejected), (-32_000, RPCError)],
)
def test_transaction_rejection_uses_only_narrow_rpc_code(
    code: int, expected: type[Exception]
) -> None:
    def respond(request: dict) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": code, "message": "untrusted server text"},
        }

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)
        anvil._accounts = ("0x" + "11" * 20,)

        with pytest.raises(expected):
            anvil.send_transaction(
                {
                    "from": anvil._accounts[0],
                    "to": "0x" + "22" * 20,
                    "data": "0x",
                    "value": 0,
                    "gas": 21_000,
                }
            )


def test_consumed_transaction_hash_must_be_exact_hex() -> None:
    def respond(request: dict) -> dict:
        return {"jsonrpc": "2.0", "id": request["id"], "result": "0x12"}

    with _fake_loopback_rpc(respond) as (port, _):
        anvil = LocalAnvil()
        _attach_fake_process(anvil, port)
        anvil._accounts = ("0x" + "11" * 20,)

        with pytest.raises(EVMError, match="transaction hash"):
            anvil.send_transaction(
                {"from": anvil._accounts[0], "data": "0x", "gas": 21_000}
            )
