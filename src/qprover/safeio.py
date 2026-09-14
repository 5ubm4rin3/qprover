"""Race-resistant local output primitives for proof artifacts."""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import shutil
import stat
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


class SafeOutputError(RuntimeError):
    """An output path violates the trusted local publication boundary."""


@dataclass(frozen=True, slots=True)
class PublicationOutcome:
    """The post-rename state; durability warnings cannot revoke a committed run."""

    destination: Path
    durability_warning: str | None = None


def _absolute_lexical(path: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    if ".." in candidate.parts:
        raise SafeOutputError("output path traversal is forbidden")
    return candidate


def _open_parent(path: Path, *, create: bool) -> tuple[int, str, Path]:
    absolute = _absolute_lexical(path)
    if absolute.name in {"", ".", ".."}:
        raise SafeOutputError("output requires a file or directory name")
    components = absolute.parent.parts[1:]
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for component in components:
            if component in {"", ".", ".."}:
                raise SafeOutputError("invalid output path component")
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise SafeOutputError("output parent does not exist") from None
                with suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                try:
                    child = os.open(component, flags, dir_fd=descriptor)
                except OSError as error:
                    raise SafeOutputError(
                        "output parent is not a trusted directory"
                    ) from error
            except OSError as error:
                raise SafeOutputError(
                    "output path contains a symlink or non-directory component"
                ) from error
            os.close(descriptor)
            descriptor = child
        return descriptor, absolute.name, absolute
    except BaseException:
        os.close(descriptor)
        raise


def _existing_regular_is_safe(parent_fd: int, name: str) -> bool:
    try:
        record = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(record.st_mode):
        raise SafeOutputError("output target must not be a symlink")
    if not stat.S_ISREG(record.st_mode):
        raise SafeOutputError("output target must be a regular file")
    if record.st_nlink != 1:
        raise SafeOutputError("output target must not be hard-linked")
    return True


def safe_atomic_write(
    output: Path,
    content: bytes | str,
    *,
    replace: bool = True,
) -> Path:
    """Write one file through a verified parent fd without following links."""

    payload = content.encode() if isinstance(content, str) else content
    if type(payload) is not bytes:
        raise TypeError("safe output content must be bytes or text")
    parent_fd, name, absolute = _open_parent(output, create=True)
    temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
    temporary_created = False
    try:
        exists = _existing_regular_is_safe(parent_fd, name)
        if exists and not replace:
            raise SafeOutputError("output target already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_fd)
        temporary_created = True
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise SafeOutputError("short write while publishing output")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        # Recheck the destination immediately before replacement to reject a
        # link swap that occurred after the first inspection.
        now_exists = _existing_regular_is_safe(parent_fd, name)
        if now_exists and not replace:
            raise SafeOutputError("output target already exists")
        os.replace(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_created = False
        os.fsync(parent_fd)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise SafeOutputError("output path follows an unsafe link") from error
        raise
    finally:
        if temporary_created:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_fd)
        os.close(parent_fd)
    return absolute


def create_private_directory(path: Path) -> Path:
    """Create one collision-free 0700 directory below verified parents."""

    parent_fd, name, absolute = _open_parent(path, create=True)
    created = False
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError as error:
            raise SafeOutputError("output directory already exists") from error
        os.fsync(parent_fd)
    except BaseException:
        if created:
            with suppress(OSError):
                os.rmdir(name, dir_fd=parent_fd)
        raise
    finally:
        os.close(parent_fd)
    return absolute


def validated_private_tree(root: Path) -> Mapping[str, str]:
    """Return fd-hashed regular files after rejecting every unsafe tree entry."""

    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(_absolute_lexical(root), flags)
    except OSError as error:
        raise SafeOutputError("staging root is not a trusted directory") from error
    records: dict[str, str] = {}

    def visit(directory_fd: int, prefix: str) -> None:
        for name in os.listdir(directory_fd):
            if name in {".", ".."}:
                raise SafeOutputError("invalid staging entry")
            entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            relative = f"{prefix}/{name}" if prefix else name
            if stat.S_ISLNK(entry.st_mode) or (
                not stat.S_ISREG(entry.st_mode) and not stat.S_ISDIR(entry.st_mode)
            ):
                raise SafeOutputError("staging contains a link or special entry")
            if stat.S_ISDIR(entry.st_mode):
                child = os.open(name, flags, dir_fd=directory_fd)
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
                continue
            if entry.st_nlink != 1:
                raise SafeOutputError("staging contains a hard-linked file")
            file_fd = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                opened = os.fstat(file_fd)
                opened_identity = (opened.st_dev, opened.st_ino, opened.st_size)
                entry_identity = (entry.st_dev, entry.st_ino, entry.st_size)
                if opened_identity != entry_identity:
                    raise SafeOutputError("staging entry changed while publishing")
                with os.fdopen(os.dup(file_fd), "rb") as handle:
                    digest = hashlib.file_digest(handle, "sha256").hexdigest()
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino, after.st_size) != entry_identity:
                    raise SafeOutputError("staging entry changed while publishing")
                records[relative] = digest
            finally:
                os.close(file_fd)

    try:
        visit(root_fd, "")
    finally:
        os.close(root_fd)
    return records


def publish_private_directory(staging: Path, destination: Path) -> PublicationOutcome:
    """Atomically rename a private sibling directory to an immutable run path."""

    staging_abs = _absolute_lexical(staging)
    destination_abs = _absolute_lexical(destination)
    if staging_abs.parent != destination_abs.parent:
        raise SafeOutputError("staging and publication directories must be siblings")
    parent_fd, destination_name, _ = _open_parent(destination_abs, create=False)
    try:
        source_name = staging_abs.name
        source = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(source.st_mode):
            raise SafeOutputError("staging output is not a directory")
        try:
            os.stat(destination_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SafeOutputError("published run already exists")
        os.rename(
            source_name,
            destination_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        try:
            os.fsync(parent_fd)
        except OSError as error:
            # The atomic namespace update already committed.  Report the
            # durability boundary to the caller without permitting a second,
            # contradictory publication for the same run id.
            return PublicationOutcome(destination_abs, f"post-rename fsync: {error}")
    finally:
        os.close(parent_fd)
    return PublicationOutcome(destination_abs)


def remove_private_directory(path: Path) -> None:
    """Best-effort cleanup limited to one explicitly owned staging directory."""

    absolute = _absolute_lexical(path)
    try:
        record = os.lstat(absolute)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(record.st_mode) or stat.S_ISLNK(record.st_mode):
        raise SafeOutputError("owned cleanup target is not a real directory")
    shutil.rmtree(absolute)


__all__ = [
    "SafeOutputError",
    "PublicationOutcome",
    "create_private_directory",
    "validated_private_tree",
    "publish_private_directory",
    "remove_private_directory",
    "safe_atomic_write",
]
