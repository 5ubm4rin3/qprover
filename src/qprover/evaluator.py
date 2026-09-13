"""Concrete candidate execution against a QProver-owned local Anvil node."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from eth_abi.exceptions import DecodingError, EncodingError
from eth_utils.abi import abi_to_signature, collapse_if_tuple
from web3 import Web3
from web3.exceptions import Web3Exception

from qprover.artifacts import ArtifactBundle, ContractArtifact
from qprover.evm import EVMError, LocalAnvil, TransactionRejected
from qprover.expression import ExpressionError, evaluate_expression
from qprover.models import (
    ActionSpec,
    Candidate,
    ObservationSnapshot,
    Outcome,
    TargetManifest,
)
from qprover.search.base import Evaluation


class EvaluatorError(RuntimeError):
    """The manifest/bundle cannot establish a trustworthy local baseline."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest_hash(manifest: TargetManifest) -> str:
    payload = json.dumps(
        manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    return _sha256(payload)


def _state_snapshot(values: Mapping[str, int | bool]) -> ObservationSnapshot:
    payload = json.dumps(dict(values), sort_keys=True, separators=(",", ":")).encode()
    return ObservationSnapshot(values=values, state_hash=_sha256(payload))


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise EvaluatorError(f"{label} must produce one integer value")
    return value


class ScenarioEvaluator:
    """Deploy a manifest baseline once and evaluate isolated candidate sequences."""

    def __init__(
        self,
        manifest: TargetManifest,
        bundle: ArtifactBundle,
        anvil: LocalAnvil,
    ) -> None:
        if not isinstance(manifest, TargetManifest):
            raise TypeError("manifest must be a TargetManifest")
        if not isinstance(bundle, ArtifactBundle) or bundle.closed:
            raise EvaluatorError("artifact bundle must be live")
        if not isinstance(anvil, LocalAnvil) or not anvil.running:
            raise EvaluatorError("LocalAnvil must be running")
        if bundle.manifest_sha256 != _manifest_hash(manifest):
            raise EvaluatorError("artifact bundle does not match manifest")
        if len(anvil.accounts) <= max(actor.slot for actor in manifest.actors):
            raise EvaluatorError("Anvil does not provide every actor slot")

        self.manifest = manifest
        self.bundle = bundle
        self.anvil = anvil
        self._codec = Web3().codec
        self.actors = MappingProxyType(
            {actor.slot: anvil.accounts[actor.slot] for actor in manifest.actors}
        )
        self._actor_ids = MappingProxyType(
            {actor.id: self.actors[actor.slot] for actor in manifest.actors}
        )
        self.deployments: Mapping[str, str] = MappingProxyType({})
        self.deployment_artifacts: Mapping[str, str] = MappingProxyType({})
        self._deployment_abis: Mapping[str, tuple[Mapping[str, Any], ...]] = (
            MappingProxyType({})
        )
        self._actions = {action.id: action for action in manifest.actions}

        try:
            for actor in manifest.actors:
                anvil.set_balance(self.actors[actor.slot], actor.balance_wei)
            self._deploy_all()
            self.initial_observations = self._observe()
            self.current_observations = self.initial_observations
            anvil.create_baseline()
        except (EVMError, EvaluatorError, ValueError, TypeError) as error:
            raise EvaluatorError(
                "could not establish local scenario baseline"
            ) from error

    def _artifact(self, reference: str) -> ContractArtifact:
        matches = [
            artifact
            for artifact in self.bundle.artifacts
            if artifact.compilation_target == reference
        ]
        if len(matches) != 1:
            raise EvaluatorError(
                f"deployment artifact must resolve exactly once: {reference}"
            )
        return matches[0]

    def _resolve_constructor_value(self, value: object) -> object:
        if isinstance(value, Mapping):
            if set(value) == {"actor"} and isinstance(value["actor"], str):
                try:
                    return self._actor_ids[value["actor"]]
                except KeyError as error:
                    raise EvaluatorError(
                        "unknown constructor actor reference"
                    ) from error
            if set(value) == {"deployment"} and isinstance(value["deployment"], str):
                try:
                    return self.deployments[value["deployment"]]
                except KeyError as error:
                    raise EvaluatorError(
                        "constructor deployment reference is not prior"
                    ) from error
            raise EvaluatorError("invalid constructor reference")
        if isinstance(value, tuple):
            return tuple(self._resolve_constructor_value(item) for item in value)
        return value

    def _deploy_all(self) -> None:
        deployed: dict[str, str] = {}
        artifact_refs: dict[str, str] = {}
        abis: dict[str, tuple[Mapping[str, Any], ...]] = {}
        for deployment in self.manifest.deployments:
            self.deployments = MappingProxyType(dict(deployed))
            artifact = self._artifact(deployment.artifact)
            constructor_args = tuple(
                self._resolve_constructor_value(value)
                for value in deployment.constructor_args
            )
            contract = Web3().eth.contract(
                abi=list(artifact.abi), bytecode=artifact.bytecode
            )
            try:
                data = contract.constructor(*constructor_args).data_in_transaction
            except (TypeError, ValueError, Web3Exception) as error:
                raise EvaluatorError(
                    "constructor arguments are not ABI encodable"
                ) from error
            transaction_hash = self.anvil.send_transaction(
                {
                    "from": self.actors[deployment.sender_slot],
                    "data": data,
                    "value": deployment.value_wei,
                    "gas": 30_000_000,
                }
            )
            receipt = self.anvil.wait_for_receipt(transaction_hash)
            if int(receipt.get("status", "0x0"), 16) != 1:
                raise EvaluatorError(f"deployment reverted: {deployment.id}")
            address = receipt.get("contractAddress")
            if not isinstance(address, str) or not address.startswith("0x"):
                raise EvaluatorError("deployment receipt omitted contract address")
            deployed[deployment.id] = address.lower()
            artifact_refs[deployment.id] = deployment.artifact
            abis[deployment.id] = artifact.abi
        self.deployments = MappingProxyType(deployed)
        self.deployment_artifacts = MappingProxyType(artifact_refs)
        self._deployment_abis = MappingProxyType(abis)

    def _abi_function(self, target_id: str, signature: str) -> Mapping[str, Any]:
        matches = [
            entry
            for entry in self._deployment_abis[target_id]
            if entry.get("type") == "function"
            and abi_to_signature(dict(entry)) == signature
        ]
        if len(matches) != 1:
            raise EvaluatorError(
                f"function must resolve exactly once: {target_id}:{signature}"
            )
        return matches[0]

    def _calldata(
        self, target_id: str, signature: str, args: tuple[object, ...]
    ) -> str:
        entry = self._abi_function(target_id, signature)
        selector = Web3.keccak(text=signature)[:4]
        types = [collapse_if_tuple(dict(item)) for item in entry.get("inputs", ())]
        try:
            encoded = self._codec.encode(types, list(args))
        except (TypeError, ValueError, EncodingError) as error:
            raise EvaluatorError("arguments are not ABI encodable") from error
        return f"0x{(selector + encoded).hex()}"

    def _observe(self) -> ObservationSnapshot:
        values: dict[str, int | bool] = {}
        for observation in self.manifest.observations:
            if observation.kind == "native_balance":
                address = self._actor_ids[observation.actor_id or ""]
                values[observation.id] = self.anvil.balance(address)
                continue
            target_id = observation.target_id or ""
            entry = self._abi_function(target_id, observation.signature or "")
            calldata = self._calldata(
                target_id, observation.signature or "", observation.args
            )
            raw = self.anvil.call({"to": self.deployments[target_id], "data": calldata})
            output_types = [
                collapse_if_tuple(dict(item)) for item in entry.get("outputs", ())
            ]
            if len(output_types) != 1:
                raise EvaluatorError("observations must return exactly one value")
            try:
                decoded = self._codec.decode(output_types, bytes.fromhex(raw[2:]))
            except (TypeError, ValueError, DecodingError) as error:
                raise EvaluatorError(
                    "observation return data is not ABI decodable"
                ) from error
            value = decoded[0]
            if type(value) not in (int, bool):
                raise EvaluatorError("observation must decode to an integer or boolean")
            values[observation.id] = value
        return _state_snapshot(values)

    def _validate_candidate(self, candidate: Candidate) -> str | None:
        if not isinstance(candidate, Candidate) or not candidate.steps:
            return "candidate must contain at least one action"
        return None

    def _validate_step(self, step: object) -> str | None:
        action_id = getattr(step, "action_id", None)
        action = self._actions.get(action_id)
        if action is None:
            return "candidate references unknown action"
        sender_slot = getattr(step, "sender_slot", None)
        value_wei = getattr(step, "value_wei", None)
        if type(sender_slot) is not int:
            return "candidate sender slot must be an exact integer"
        if type(value_wei) is not int:
            return "candidate value must be an exact integer"
        if not 0 <= value_wei < 1 << 256:
            return "candidate value must be an exact uint256"
        args = getattr(step, "args", ())
        if (
            getattr(step, "target_id", None) != action.target_id
            or getattr(step, "signature", None) != action.signature
            or sender_slot not in action.sender_slots
            or not any(
                type(value_wei) is type(allowed) and value_wei == allowed
                for allowed in action.value_domain.values
            )
            or len(args) != len(action.arguments)
        ):
            return "candidate action does not match manifest allow-list"
        for argument, value in zip(action.arguments, args, strict=True):
            domain = argument.domain
            if domain.kind == "finite" and not any(
                type(value) is type(allowed) and value == allowed
                for allowed in domain.values
            ):
                return "candidate argument is outside finite domain"
            if domain.kind == "integer" and (
                type(value) is not int or not domain.minimum <= value <= domain.maximum
            ):
                return "candidate argument is outside integer domain"
        constraint_values = {
            f"arg{index}": value
            for index, value in enumerate(args)
            if type(value) in (int, bool)
        }
        for argument in action.arguments:
            domain = argument.domain
            if domain.kind != "integer":
                continue
            for expression in domain.constraints:
                try:
                    result = evaluate_expression(expression, constraint_values)
                except ExpressionError:
                    return "candidate integer constraint is invalid"
                if result.status != "evaluated" or not bool(result.value):
                    return "candidate argument violates integer constraint"
        try:
            self._calldata(action.target_id, action.signature, args)
        except EvaluatorError:
            return "candidate arguments are not ABI encodable"
        return None

    @staticmethod
    def _receipt_fields(receipt: object) -> tuple[int, int, int]:
        if type(receipt) is not dict:
            raise EVMError("malformed local receipt")

        def quantity(field: str) -> int:
            value = receipt.get(field)
            if type(value) is not str or not value.startswith("0x") or not value[2:]:
                raise EVMError("malformed local receipt")
            try:
                return int(value, 16)
            except ValueError as error:
                raise EVMError("malformed local receipt") from error

        status = quantity("status")
        if status not in {0, 1}:
            raise EVMError("malformed local receipt")
        return status, quantity("gasUsed"), quantity("effectiveGasPrice")

    def _candidate_inconclusive(
        self,
        *,
        submitted: int,
        current: ObservationSnapshot,
        features: set[str],
        steps: list[dict[str, object]],
        index: int,
        reason: str,
    ) -> Evaluation:
        return Evaluation(
            outcome=Outcome.INCONCLUSIVE,
            transaction_count=submitted,
            trace_features=frozenset(features),
            state_fingerprint=current.state_hash,
            metadata={
                "category": "candidate",
                "reason": reason,
                "invalid_step": index,
                "steps": steps,
            },
        )

    def _invariants(
        self, current: ObservationSnapshot
    ) -> tuple[list[dict[str, object]], bool, bool]:
        values = dict(current.values)
        values.update(
            {
                f"initial_{name}": value
                for name, value in self.initial_observations.values.items()
            }
        )
        records: list[dict[str, object]] = []
        any_false = False
        any_inconclusive = False
        for invariant in self.manifest.invariants:
            try:
                result = evaluate_expression(invariant.expression, values)
            except ExpressionError as error:
                records.append(
                    {
                        "invariant_id": invariant.id,
                        "expression": invariant.expression,
                        "status": "inconclusive",
                        "value": None,
                        "reason": type(error).__name__,
                    }
                )
                any_inconclusive = True
                continue
            value = bool(result.value) if result.status == "evaluated" else None
            records.append(
                {
                    "invariant_id": invariant.id,
                    "expression": invariant.expression,
                    "status": result.status,
                    "value": value,
                    "reason": result.reason,
                }
            )
            any_false |= value is False
            any_inconclusive |= value is None
        return records, any_false, any_inconclusive

    def _impact(self, current: ObservationSnapshot) -> dict[str, object]:
        attacker_id = self.manifest.impact.attacker_asset_observation
        protocol_id = self.manifest.impact.protocol_asset_observation
        attacker_delta = _integer(
            current.values[attacker_id], "attacker asset observation"
        ) - _integer(
            self.initial_observations.values[attacker_id],
            "initial attacker asset observation",
        )
        protocol_delta = _integer(
            current.values[protocol_id], "protocol asset observation"
        ) - _integer(
            self.initial_observations.values[protocol_id],
            "initial protocol asset observation",
        )
        return {
            "attacker_delta": attacker_delta,
            "protocol_delta": protocol_delta,
            "unit": self.manifest.impact.unit,
            "admissible": attacker_delta > 0 and protocol_delta < 0,
        }

    def _trace_features(
        self, action: ActionSpec, transaction_hash: str, calldata: str
    ) -> tuple[set[str], int, int, bool | None, str | None]:
        features = {
            f"call:{action.id}:{self.deployments[action.target_id]}:{calldata[:10].lower()}"
        }
        debug = self.anvil.debug_trace(transaction_hash)
        struct_logs = debug.get("structLogs", ()) if debug is not None else ()
        trace_failed = (
            debug.get("failed")
            if debug is not None and type(debug.get("failed")) is bool
            else None
        )
        return_data = debug.get("returnValue") if debug is not None else None
        if isinstance(return_data, str) and not return_data.startswith("0x"):
            return_data = f"0x{return_data}"
        if not isinstance(return_data, str):
            return_data = None
        struct_count = 0
        if isinstance(struct_logs, list):
            for record in struct_logs:
                if not isinstance(record, dict):
                    continue
                depth, pc, opcode = (
                    record.get("depth"),
                    record.get("pc"),
                    record.get("op"),
                )
                if type(depth) is int and type(pc) is int and isinstance(opcode, str):
                    struct_count += 1
                    features.add(f"opcode:{action.id}:{depth}:{pc}:{opcode}")

        calls = self.anvil.transaction_trace(transaction_hash)
        call_count = 0
        for record in calls or ():
            call = record.get("action")
            if not isinstance(call, dict):
                continue
            target = call.get("to")
            data = call.get("input")
            if isinstance(target, str) and isinstance(data, str):
                call_count += 1
                features.add(f"call:{action.id}:{target.lower()}:{data[:10].lower()}")
        return features, struct_count, call_count, trace_failed, return_data

    def evaluate(self, candidate: Candidate) -> Evaluation:
        try:
            self.anvil.reset()
        except EVMError:
            return Evaluation(
                outcome=Outcome.INFRA_ERROR,
                transaction_count=0,
                metadata={"category": "snapshot", "reason": "reset failed"},
            )

        invalid = self._validate_candidate(candidate)
        if invalid is not None:
            self.current_observations = self.initial_observations
            return Evaluation(
                outcome=Outcome.INCONCLUSIVE,
                transaction_count=0,
                state_fingerprint=self.initial_observations.state_hash,
                metadata={"category": "candidate", "reason": invalid},
            )

        features: set[str] = set()
        step_records: list[dict[str, object]] = []
        current = self.initial_observations
        self.current_observations = current
        final_invariants, any_false, any_inconclusive = self._invariants(current)
        final_impact = self._impact(current)
        violation_prefix: int | None = None
        submitted = 0

        for index, step in enumerate(candidate.steps, start=1):
            invalid = self._validate_step(step)
            if invalid is not None:
                return self._candidate_inconclusive(
                    submitted=submitted,
                    current=current,
                    features=features,
                    steps=step_records,
                    index=index,
                    reason=invalid,
                )
            action = self._actions[step.action_id]
            calldata = self._calldata(step.target_id, step.signature, step.args)
            try:
                sender_balance = self.anvil.balance(self.actors[step.sender_slot])
            except EVMError:
                return Evaluation(
                    outcome=Outcome.INFRA_ERROR,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "rpc",
                        "reason": "could not read candidate sender balance",
                        "steps": step_records,
                    },
                )
            if sender_balance < step.value_wei:
                return self._candidate_inconclusive(
                    submitted=submitted,
                    current=current,
                    features=features,
                    steps=step_records,
                    index=index,
                    reason="insufficient local sender balance",
                )
            try:
                transaction_hash = self.anvil.send_transaction(
                    {
                        "from": self.actors[step.sender_slot],
                        "to": self.deployments[step.target_id],
                        "data": calldata,
                        "value": step.value_wei,
                        "gas": 30_000_000,
                    }
                )
            except TransactionRejected:
                return self._candidate_inconclusive(
                    submitted=submitted,
                    current=current,
                    features=features,
                    steps=step_records,
                    index=index,
                    reason="local transaction deterministically rejected",
                )
            except EVMError:
                return Evaluation(
                    outcome=Outcome.INFRA_ERROR,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "rpc",
                        "reason": "local transaction submission failed",
                        "steps": step_records,
                    },
                )
            submitted += 1
            try:
                receipt = self.anvil.wait_for_receipt(transaction_hash)
                status, gas_used, effective_gas_price = self._receipt_fields(receipt)
            except (EVMError, TypeError, ValueError):
                return Evaluation(
                    outcome=Outcome.INFRA_ERROR,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "receipt",
                        "reason": "malformed or unavailable local receipt",
                        "steps": step_records,
                    },
                )
            try:
                (
                    traced,
                    struct_count,
                    call_count,
                    trace_failed,
                    return_data,
                ) = self._trace_features(action, transaction_hash, calldata)
                features.update(traced)
            except (EVMError, TypeError, ValueError):
                return Evaluation(
                    outcome=Outcome.INFRA_ERROR,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "trace",
                        "reason": "malformed or unavailable local trace",
                        "steps": step_records,
                    },
                )

            record: dict[str, object] = {
                "index": index,
                "action_id": action.id,
                "sender": self.actors[step.sender_slot],
                "target": self.deployments[step.target_id],
                "transaction_hash": transaction_hash,
                "calldata_hash": _sha256(bytes.fromhex(calldata[2:])),
                "receipt_status": status,
                "gas_used": gas_used,
                "effective_gas_price": effective_gas_price,
                "trace_struct_log_count": struct_count,
                "call_trace_count": call_count,
                "trace_failed": trace_failed,
                "return_data": return_data,
                "revert_data": return_data if status != 1 else None,
                "observation_state_hash": None,
            }
            step_records.append(record)
            if status != 1:
                return Evaluation(
                    outcome=Outcome.REVERT,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "initial_observations": dict(self.initial_observations.values),
                        "baseline_observations": dict(self.initial_observations.values),
                        "steps": step_records,
                        "revert_step": index,
                        "violation_prefix_length": violation_prefix,
                    },
                )
            try:
                current = self._observe()
                self.current_observations = current
                final_invariants, any_false, any_inconclusive = self._invariants(
                    current
                )
                final_impact = self._impact(current)
            except EVMError:
                return Evaluation(
                    outcome=Outcome.INFRA_ERROR,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "observation-rpc",
                        "reason": "malformed or unavailable observation RPC",
                        "steps": step_records,
                    },
                )
            except EvaluatorError:
                return Evaluation(
                    outcome=Outcome.INCONCLUSIVE,
                    transaction_count=submitted,
                    trace_features=frozenset(features),
                    state_fingerprint=current.state_hash,
                    metadata={
                        "category": "observation",
                        "reason": "post-transaction observation failed",
                        "steps": step_records,
                    },
                )
            record["observation_state_hash"] = current.state_hash
            record["observations"] = dict(current.values)
            record["invariants"] = final_invariants
            if (
                violation_prefix is None
                and any_false
                and final_impact["admissible"] is True
            ):
                violation_prefix = index

        if violation_prefix is not None:
            outcome = Outcome.VIOLATION
        elif any_false or any_inconclusive:
            outcome = Outcome.INCONCLUSIVE
        else:
            outcome = Outcome.PASS
        return Evaluation(
            outcome=outcome,
            transaction_count=submitted,
            trace_features=frozenset(features),
            state_fingerprint=current.state_hash,
            metadata={
                "initial_observations": dict(self.initial_observations.values),
                "baseline_observations": dict(self.initial_observations.values),
                "current_observations": dict(current.values),
                "steps": step_records,
                "invariants": final_invariants,
                "impact": final_impact,
                "violation_prefix_length": violation_prefix,
                "confirmation": "not_confirmed",
            },
        )
