"""Race-resistant local output primitives for proof artifacts."""

from __future__ import annotations

import errno
import os
import secrets
import shutil
import stat
from contextlib import suppress
from pathlib import Path


class SafeOutputError(RuntimeError):
    """An output path violates the trusted local publication boundary."""


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
    try:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError as error:
            raise SafeOutputError("output directory already exists") from error
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return absolute


def publish_private_directory(staging: Path, destination: Path) -> Path:
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
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return destination_abs


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
    "create_private_directory",
    "publish_private_directory",
    "remove_private_directory",
    "safe_atomic_write",
]
