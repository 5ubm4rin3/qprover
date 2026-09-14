from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

import qprover.safeio as safeio
from qprover.runtime import ExecutionRuntime
from qprover.safeio import (
    PrivateDirectoryLease,
    PublicationIntegrityError,
    SafeOutputError,
    StaleOwnershipError,
)


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
        runtime.own_resource(lease.create, lease.cleanup)

    assert cleanup_calls == 2
    assert not lease.path.exists()


def test_create_root_reuse_reports_stale_ownership_and_never_deletes_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = PrivateDirectoryLease(tmp_path / "stage")
    detached = tmp_path / "detached"
    marker = lease.path / "later-owner"

    def swap_then_fail(descriptor: int) -> None:
        del descriptor
        lease.path.rename(detached)
        lease.path.mkdir()
        marker.write_text("survives")
        raise OSError("fsync failed after root swap")

    monkeypatch.setattr(safeio.os, "fsync", swap_then_fail)
    with (
        ExecutionRuntime.activate() as runtime,
        pytest.raises(StaleOwnershipError, match="not proven cleaned"),
    ):
        runtime.own_resource(lease.create, lease.cleanup)

    assert runtime.has_pending_cleanup is False
    assert runtime.cleanup_warnings
    assert marker.read_text() == "survives"
    assert detached.is_dir()
    shutil.rmtree(lease.path)
    shutil.rmtree(detached)


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


def _publish_with_final_mutation(
    lease: PrivateDirectoryLease,
    destination: Path,
    expected: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    mutate,
) -> PublicationIntegrityError:
    original_rename = safeio.os.rename

    def rename_then_mutate(source, target, **kwargs):
        original_rename(source, target, **kwargs)
        if source == lease.path.name and target == destination.name:
            mutate(destination)

    monkeypatch.setattr(safeio.os, "rename", rename_then_mutate)
    with pytest.raises(PublicationIntegrityError) as captured:
        lease.publish(destination, expected)
    return captured.value


class HandoffInterrupted(BaseException):
    """Synchronous stand-in for cancellation at a publication boundary."""


def test_final_rename_then_baseexception_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"proof.json"}))
    original_rename = safeio.os.rename
    interrupted = False

    def rename_then_interrupt(source, target, **kwargs):
        nonlocal interrupted
        original_rename(source, target, **kwargs)
        if not interrupted:
            interrupted = True
            raise HandoffInterrupted("after rename syscall")

    monkeypatch.setattr(safeio.os, "rename", rename_then_interrupt)
    with pytest.raises(PublicationIntegrityError) as captured:
        lease.publish(tmp_path / "published", expected)

    assert captured.value.quarantined is True
    assert captured.value.destination is None
    assert not (tmp_path / "published").exists()
    lease.cleanup()


def test_baseexception_during_final_scan_is_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"proof.json"}))
    original_rename = safeio.os.rename
    original_listdir = safeio.os.listdir
    armed = False
    interrupted = False

    def arm_after_rename(source, target, **kwargs):
        nonlocal armed
        original_rename(source, target, **kwargs)
        armed = True

    def interrupt_final_scan(directory):
        nonlocal interrupted
        if armed and not interrupted:
            interrupted = True
            raise HandoffInterrupted("during final scan")
        return original_listdir(directory)

    monkeypatch.setattr(safeio.os, "rename", arm_after_rename)
    monkeypatch.setattr(safeio.os, "listdir", interrupt_final_scan)
    with pytest.raises(PublicationIntegrityError) as captured:
        lease.publish(tmp_path / "published", expected)

    assert captured.value.quarantined is True
    assert captured.value.destination is None
    assert not (tmp_path / "published").exists()
    lease.cleanup()


def test_final_file_poison_is_quarantined_and_never_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"proof.json"}))

    error = _publish_with_final_mutation(
        lease,
        tmp_path / "published",
        expected,
        monkeypatch,
        lambda destination: (destination / "proof.json").write_text("poisoned"),
    )

    assert error.quarantined is True
    assert error.ambiguous_visible_path is False
    assert error.destination is None
    assert not (tmp_path / "published").exists()
    assert error.quarantine_path is not None and error.quarantine_path.exists()
    lease.cleanup()
    assert not error.quarantine_path.exists()


def test_final_nested_directory_addition_after_listing_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    nested = lease.path / "nested"
    nested.mkdir()
    (nested / "proof.json").write_text("evidence")
    nested_inode = nested.stat().st_ino
    expected = dict(lease.validate({"nested/proof.json"}))
    original_rename = safeio.os.rename
    original_listdir = safeio.os.listdir
    armed = False
    added = False

    def arm_after_rename(source, target, **kwargs):
        nonlocal armed
        original_rename(source, target, **kwargs)
        if source == lease.path.name and target == "published":
            armed = True

    def listdir_then_add(directory):
        nonlocal added
        names = original_listdir(directory)
        if armed and not added and os.fstat(directory).st_ino == nested_inode:
            added = True
            (tmp_path / "published" / "nested" / "late.txt").write_text("late")
        return names

    monkeypatch.setattr(safeio.os, "rename", arm_after_rename)
    monkeypatch.setattr(safeio.os, "listdir", listdir_then_add)

    with pytest.raises(PublicationIntegrityError) as captured:
        lease.publish(tmp_path / "published", expected)

    assert added is True
    assert captured.value.quarantined is True
    assert not (tmp_path / "published").exists()
    lease.cleanup()


def test_final_nested_directory_swap_is_detected_even_with_identical_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    nested = lease.path / "nested"
    nested.mkdir()
    (nested / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"nested/proof.json"}))
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "proof.json").write_text("evidence")
    detached = tmp_path / "detached-nested"

    def swap(destination: Path) -> None:
        (destination / "nested").rename(detached)
        replacement.rename(destination / "nested")

    error = _publish_with_final_mutation(
        lease, tmp_path / "published", expected, monkeypatch, swap
    )

    assert error.quarantined is True
    assert not (tmp_path / "published").exists()
    lease.cleanup()
    shutil.rmtree(detached)


def test_final_root_swap_is_ambiguous_and_returns_no_usable_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _created_lease(tmp_path / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"proof.json"}))
    detached = tmp_path / "detached-root"

    def swap(destination: Path) -> None:
        destination.rename(detached)
        destination.mkdir()
        (destination / "proof.json").write_text("foreign")

    error = _publish_with_final_mutation(
        lease, tmp_path / "published", expected, monkeypatch, swap
    )

    assert error.quarantined is False
    assert error.ambiguous_visible_path is True
    assert error.destination is None
    assert (tmp_path / "published" / "proof.json").read_text() == "foreign"
    with pytest.raises(StaleOwnershipError, match="not proven cleaned"):
        lease.cleanup()
    shutil.rmtree(tmp_path / "published")
    shutil.rmtree(detached)


def test_final_lexical_parent_swap_quarantines_only_pinned_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "runs"
    lease = _created_lease(parent / "stage")
    (lease.path / "proof.json").write_text("evidence")
    expected = dict(lease.validate({"proof.json"}))
    moved_parent = tmp_path / "moved-runs"

    def swap_parent(destination: Path) -> None:
        destination.parent.rename(moved_parent)
        destination.parent.mkdir()
        (destination.parent / destination.name).mkdir()
        (destination.parent / destination.name / "foreign").write_text("foreign")

    error = _publish_with_final_mutation(
        lease, parent / "published", expected, monkeypatch, swap_parent
    )

    assert error.quarantined is True
    assert error.ambiguous_visible_path is True
    assert error.destination is None
    assert error.quarantine_path is None
    assert (parent / "published" / "foreign").read_text() == "foreign"
    assert not (moved_parent / "published").exists()
    lease.cleanup()
    shutil.rmtree(parent)
    shutil.rmtree(moved_parent)


def test_reused_owned_path_is_never_deleted_and_records_cleanup_warning(
    tmp_path: Path,
) -> None:
    lease = PrivateDirectoryLease(tmp_path / "owned")
    detached = tmp_path / "detached"

    with ExecutionRuntime.activate() as runtime:
        owned, token = runtime.own_resource(lease.create, lease.cleanup)
        owned.path.rename(detached)
        owned.path.mkdir()
        marker = owned.path / "later-owner"
        marker.write_text("survives")
        with pytest.raises(StaleOwnershipError, match="not proven cleaned"):
            runtime.release(token)
        assert runtime.has_pending_cleanup is False
        assert runtime.cleanup_warnings

    assert marker.read_text() == "survives"
    assert detached.is_dir()
    shutil.rmtree(owned.path)
    shutil.rmtree(detached)


def test_cleanup_restores_access_to_exact_owned_locked_nested_directory(
    tmp_path: Path,
) -> None:
    lease = _created_lease(tmp_path / "owned")
    nested = lease.path / "locked"
    nested.mkdir()
    (nested / "evidence").write_text("owned")
    nested.chmod(0)

    lease.cleanup()

    assert not lease.path.exists()
