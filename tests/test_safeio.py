from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

import qprover.safeio as safeio
from qprover.runtime import ExecutionRuntime
from qprover.safeio import PrivateDirectoryLease, SafeOutputError


def _created_lease(path: Path) -> PrivateDirectoryLease:
    lease = PrivateDirectoryLease(path)
    lease.create()
    return lease


def test_private_tree_rejects_hardlinked_file(tmp_path: Path) -> None:
    lease = _created_lease(tmp_path / "stage")
    victim = tmp_path / "victim"
    victim.write_text("evidence")
    (lease.path / "proof.json").hardlink_to(victim)

    with pytest.raises(SafeOutputError, match="hard-linked"):
        lease.validate({"proof.json"})
    lease.cleanup()


def test_private_tree_rejects_symlinked_parent(tmp_path: Path) -> None:
    lease = _created_lease(tmp_path / "stage")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "proof.json").write_text("evidence")
    (lease.path / "nested").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SafeOutputError, match="link or special"):
        lease.validate({"nested/proof.json"})
    lease.cleanup()


def test_private_tree_rejects_fifo(tmp_path: Path) -> None:
    lease = _created_lease(tmp_path / "stage")
    os.mkfifo(lease.path / "channel")

    with pytest.raises(SafeOutputError, match="link or special"):
        lease.validate({"channel"})
    lease.cleanup()


def test_private_tree_rejects_unlisted_stale_file(tmp_path: Path) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    (lease.path / "stale.txt").write_text("stale")

    with pytest.raises(SafeOutputError, match="exact expected file set"):
        lease.validate({"proof.json"})
    lease.cleanup()


def test_create_fsync_and_first_rollback_failure_remains_owned_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = PrivateDirectoryLease(tmp_path / "stage")
    original_rmdir = safeio.os.rmdir
    cleanup_calls = 0

    def transient_cleanup(path: str | bytes | os.PathLike[str], *, dir_fd=None) -> None:
        nonlocal cleanup_calls
        cleanup_calls += 1
        if cleanup_calls == 1:
            raise OSError("transient rmdir failure")
        original_rmdir(path, dir_fd=dir_fd)

    monkeypatch.setattr(
        safeio.os,
        "fsync",
        lambda descriptor: (_ for _ in ()).throw(OSError("fsync failed")),
    )
    monkeypatch.setattr(safeio.os, "rmdir", transient_cleanup)

    with (
        ExecutionRuntime.activate() as runtime,
        pytest.raises(OSError, match="fsync failed"),
    ):
        runtime.own_path(
            lease.path,
            lambda target: lease.create(),
            lambda target: lease.cleanup(),
        )

    assert cleanup_calls == 2
    assert not lease.path.exists()


def test_publication_rejects_replaced_staging_root(tmp_path: Path) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = lease.validate({"proof.json"})
    original = tmp_path / "original"
    lease.path.rename(original)
    lease.path.mkdir()
    (lease.path / "proof.json").write_text("replacement")

    with pytest.raises(SafeOutputError, match="root identity"):
        lease.publish(tmp_path / "published", expected)

    assert not (tmp_path / "published").exists()
    shutil.rmtree(lease.path)
    original.rename(lease.path)
    lease.cleanup()


def test_publication_rejects_replaced_staging_parent_path(tmp_path: Path) -> None:
    parent = tmp_path / "runs"
    lease = _created_lease(parent / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = lease.validate({"proof.json"})
    original_parent = tmp_path / "original-runs"
    parent.rename(original_parent)
    replacement_parent = tmp_path / "replacement-runs"
    replacement_parent.mkdir()
    parent.symlink_to(replacement_parent, target_is_directory=True)

    with pytest.raises(SafeOutputError, match="parent identity"):
        lease.publish(parent / "published", expected)

    assert not (replacement_parent / "published").exists()
    parent.unlink()
    original_parent.rename(parent)
    lease.cleanup()


def test_publication_rejects_file_inode_mutation_after_validation(
    tmp_path: Path,
) -> None:
    lease = _created_lease(tmp_path / "stage")
    proof = lease.path / "proof.json"
    proof.write_text("first")
    expected = lease.validate({"proof.json"})
    replacement = lease.path / "replacement"
    replacement.write_text("second")
    replacement.replace(proof)

    with pytest.raises(SafeOutputError, match="changed while publishing"):
        lease.publish(tmp_path / "published", expected)
    lease.cleanup()


def test_postcommit_fsync_failure_returns_warning_and_keeps_disk_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = lease.validate({"proof.json"})
    monkeypatch.setattr(
        os, "fsync", lambda descriptor: (_ for _ in ()).throw(OSError("disk"))
    )

    outcome = lease.publish(tmp_path / "published", expected)

    assert outcome.destination == tmp_path / "published"
    assert outcome.durability_warning == "post-rename fsync: disk"
    assert (outcome.destination / "proof.json").read_text() == "evidence"
    assert not lease.path.exists()
    lease.cleanup()
