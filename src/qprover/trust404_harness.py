"""Execution boundary for TRUST404 Track 04 organizer proof semantics."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from qprover.trust404 import Track04Manifest


@dataclass(frozen=True, slots=True)
class VerificationResult:
    proven: bool
    violated_predicate: str
    category: str
    note: str = ""


_ATTEMPT_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {{Harness}} from "../src/Harness.sol";
import {{console2}} from "forge-std/console2.sol";
import {{{target_name}}} from "./_qprover_target.sol";
import {{Invariants}} from "./_qprover_invariants.sol";{setup_import}
import {{Exploit}} from "./_qprover_exploit.sol";

contract QProverAttemptTest is Harness {{
    function test_attempt() public {{
        {deploy_line}
        Invariants invariants = new Invariants();
        Exploit exploit = new Exploit();
        (bool proven, string memory violated) = _prove(
            target,
            address(invariants),
            address(exploit),
            {block_number},
            {block_timestamp},
            DEFAULT_EXPLOIT_FUNDING_WEI
        );
        console2.log("AGENT_RESULT", proven ? "PROVEN" : "NOT_PROVEN", violated);
    }}
}}
"""


def _tail(text: str, count: int = 20) -> str:
    return "\n".join(text.strip().splitlines()[-count:])


def _rewrite_setup_import(source: str, target_name: str) -> str:
    pattern = re.compile(r'(["\'])[^"\']*src/' + re.escape(target_name) + r"\.sol\1")
    return pattern.sub('"./_qprover_target.sol"', source)


def _local_solc(solc_version: str) -> str | None:
    """Return an exact local solc path when available for offline verification."""

    candidates = tuple(
        dict.fromkeys(
            item
            for item in (
                os.environ.get("QPROVER_SOLC"),
                "/usr/local/bin/solc",
                shutil.which("solc"),
            )
            if item
        )
    )
    for candidate in candidates:
        path = Path(candidate)
        if not path.is_file():
            continue
        try:
            result = subprocess.run(
                (str(path), "--version"),
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        version_text = f"{result.stdout}\n{result.stderr}"
        match = re.search(r"Version:\s*(\d+\.\d+\.\d+)", version_text)
        if result.returncode == 0 and match and match.group(1) == solc_version:
            return str(path)
    return None


def verify_exploit(
    harness_dir: Path | str,
    target_path: Path | str,
    invariants_path: Path | str,
    exploit_code: str,
    manifest: Track04Manifest,
    *,
    timeout_seconds: int,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> VerificationResult:
    """Compile and execute one candidate under the organizer Harness._prove oracle."""
    hdir = Path(harness_dir).resolve()
    target = Path(target_path).resolve()
    invariants = Path(invariants_path).resolve()
    scratch = hdir / "test"
    if not (hdir / "src" / "Harness.sol").is_file() or not scratch.is_dir():
        return VerificationResult(
            False, "", "infrastructure", "invalid harness directory"
        )
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        return VerificationResult(False, "", "infrastructure", "invalid timeout")
    if manifest.setup is None and manifest.constructor_args:
        return VerificationResult(
            False,
            "",
            "unsupported_deploy",
            (
                "constructor_args require deploy.setup under the organizer "
                "harness contract"
            ),
        )

    target_dst = scratch / "_qprover_target.sol"
    invariants_dst = scratch / "_qprover_invariants.sol"
    exploit_dst = scratch / "_qprover_exploit.sol"
    attempt_dst = scratch / "_qprover_attempt.t.sol"
    setup_dst = scratch / "_qprover_setup.sol"
    generated = (target_dst, invariants_dst, exploit_dst, attempt_dst, setup_dst)

    setup_import = ""
    if manifest.setup is not None:
        setup_path = manifest.path.parent / manifest.setup
        deploy_line = "address target = (new Setup()).run();"
        setup_import = '\nimport {Setup} from "./_qprover_setup.sol";'
    else:
        setup_path = None
        deploy_line = (
            f"{manifest.target_name} deployed = new {manifest.target_name}(); "
            "address target = address(deployed);"
        )

    try:
        shutil.copyfile(target, target_dst)
        shutil.copyfile(invariants, invariants_dst)
        exploit_dst.write_text(exploit_code, encoding="utf-8")
        if setup_path is not None:
            if not setup_path.is_file():
                return VerificationResult(
                    False,
                    "",
                    "infrastructure",
                    f"setup file not found: {setup_path}",
                )
            setup_source = setup_path.read_text(encoding="utf-8")
            setup_dst.write_text(
                _rewrite_setup_import(setup_source, manifest.target_name),
                encoding="utf-8",
            )

        attempt_dst.write_text(
            _ATTEMPT_TEMPLATE.format(
                target_name=manifest.target_name,
                setup_import=setup_import,
                deploy_line=deploy_line,
                block_number=manifest.block_number,
                block_timestamp=manifest.block_timestamp,
            ),
            encoding="utf-8",
        )
        compiler_args: list[str] = []
        local_solc = _local_solc(manifest.solc)
        if local_solc is not None:
            compiler_args = ["--use", local_solc, "--offline"]
        try:
            completed = runner(
                [
                    "forge",
                    "test",
                    "--match-path",
                    "test/_qprover_attempt.t.sol",
                    "-vv",
                    *compiler_args,
                ],
                cwd=hdir,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            output = "\n".join(
                part.decode() if isinstance(part, bytes) else (part or "")
                for part in (error.stdout, error.stderr)
            )
            return VerificationResult(False, "", "timeout", _tail(output))
        except OSError as error:
            return VerificationResult(False, "", "infrastructure", str(error))

        output = (completed.stdout or "") + (completed.stderr or "")
        results = re.findall(
            r"(?m)^\s*AGENT_RESULT\s+(PROVEN|NOT_PROVEN)(?:\s+(\S+))?\s*$",
            output,
        )
        if completed.returncode == 0 and results:
            verdict, predicate = results[-1]
            proven = verdict == "PROVEN"
            violated = predicate if proven else ""
            return VerificationResult(
                proven,
                violated,
                "proven" if proven else "not_proven",
            )
        revert_step = re.search(r"QProverFailure\((\d+)\)", output)
        note = (
            f"revert_step={revert_step.group(1)}"
            if revert_step is not None
            else (_tail(output) or f"forge exited {completed.returncode}")
        )
        return VerificationResult(False, "", "forge_error", note)
    finally:
        for path in generated:
            with suppress(OSError):
                path.unlink(missing_ok=True)
