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
from pathlib import Path, PurePosixPath
from types import MappingProxyType


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


def _record_identity(record: os.stat_result) -> tuple[int, ...]:
    return (
        record.st_dev,
        record.st_ino,
        record.st_mode,
        record.st_nlink,
        record.st_size,
        record.st_mtime_ns,
        record.st_ctime_ns,
    )


def _expected_paths(
    expected: Mapping[str, str] | set[str],
) -> tuple[set[str], set[str]]:
    files = set(expected)
    directories: set[str] = set()
    for raw in files:
        path = PurePosixPath(raw)
        scheme, separator, _ = raw.partition(":")
        has_uri_scheme = bool(
            separator
            and scheme
            and scheme[0].isalpha()
            and all(character.isalnum() or character in "+-." for character in scheme)
        )
        if (
            not raw
            or raw.startswith("/")
            or raw in {".", ".."}
            or raw.endswith("/")
            or has_uri_scheme
            or "\\" in raw
            or "://" in raw
            or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != raw
        ):
            raise SafeOutputError("invalid expected staging path")
        parent = path.parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return files, directories


class PrivateDirectoryLease:
    """Pinned identity for one private staging directory until commit/cleanup.

    Descriptor pinning closes accidental pathname replacement races.  As with
    every local process artifact, a malicious process running as the same UID
    remains inside QProver's explicitly trusted-host boundary.
    """

    def __init__(self, path: Path) -> None:
        self.path = _absolute_lexical(path)
        self._parent_fd: int | None = None
        self._root_fd: int | None = None
        self._parent_identity: tuple[int, int] | None = None
        self._root_identity: tuple[int, int] | None = None
        self._published_name: str | None = None

    def create(self) -> PrivateDirectoryLease:
        if self._parent_fd is not None or self._root_fd is not None:
            raise SafeOutputError("private directory lease is already created")
        parent_fd, name, absolute = _open_parent(self.path, create=True)
        created = False
        root_fd: int | None = None
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                created = True
            except FileExistsError as error:
                raise SafeOutputError("output directory already exists") from error
            root_fd = os.open(name, flags, dir_fd=parent_fd)
            record = os.fstat(root_fd)
            if not stat.S_ISDIR(record.st_mode):
                raise SafeOutputError("staging root is not a trusted directory")
            self.path = absolute
            self._parent_fd = parent_fd
            self._root_fd = root_fd
            parent_record = os.fstat(parent_fd)
            self._parent_identity = (parent_record.st_dev, parent_record.st_ino)
            self._root_identity = (record.st_dev, record.st_ino)
            os.fsync(parent_fd)
            return self
        except BaseException:
            if self._parent_fd is not None:
                with suppress(BaseException):
                    self.cleanup()
                raise
            if root_fd is not None:
                os.close(root_fd)
            if created:
                with suppress(OSError):
                    os.rmdir(name, dir_fd=parent_fd)
            os.close(parent_fd)
            raise

    def _descriptors(
        self,
    ) -> tuple[int, int, tuple[int, int], tuple[int, int]]:
        if (
            self._parent_fd is None
            or self._root_fd is None
            or self._parent_identity is None
            or self._root_identity is None
        ):
            raise SafeOutputError("private directory lease is not live")
        return (
            self._parent_fd,
            self._root_fd,
            self._parent_identity,
            self._root_identity,
        )

    def _verify_path_identity(self, name: str | None = None) -> None:
        parent_fd, root_fd, parent_identity, identity = self._descriptors()
        try:
            fresh_parent_fd, fresh_name, _ = _open_parent(self.path, create=False)
        except SafeOutputError as error:
            raise SafeOutputError(
                "staging parent identity changed while publishing"
            ) from error
        try:
            fresh_parent = os.fstat(fresh_parent_fd)
            if (fresh_parent.st_dev, fresh_parent.st_ino) != parent_identity:
                raise SafeOutputError(
                    "staging parent identity changed while publishing"
                )
            fresh_root = os.stat(
                fresh_name, dir_fd=fresh_parent_fd, follow_symlinks=False
            )
            if (fresh_root.st_dev, fresh_root.st_ino) != identity:
                raise SafeOutputError("staging root identity changed while publishing")
        except FileNotFoundError as error:
            raise SafeOutputError(
                "staging root identity is no longer reachable"
            ) from error
        finally:
            os.close(fresh_parent_fd)
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != identity:
            raise SafeOutputError("staging root identity changed while publishing")
        try:
            pathname = os.stat(
                name or self.path.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise SafeOutputError(
                "staging root identity is no longer reachable"
            ) from error
        if (pathname.st_dev, pathname.st_ino) != identity:
            raise SafeOutputError("staging root identity changed while publishing")

    def validate(self, expected: Mapping[str, str] | set[str]) -> Mapping[str, str]:
        """Hash the pinned tree and require exactly the declared file set."""

        _, root_fd, _, _ = self._descriptors()
        self._verify_path_identity()
        expected_files, expected_directories = _expected_paths(expected)
        records: dict[str, str] = {}
        directories: set[str] = set()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

        def visit(directory_fd: int, prefix: str) -> None:
            for name in sorted(os.listdir(directory_fd)):
                if name in {".", ".."}:
                    raise SafeOutputError("invalid staging entry")
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                relative = f"{prefix}/{name}" if prefix else name
                if stat.S_ISLNK(entry.st_mode) or (
                    not stat.S_ISREG(entry.st_mode) and not stat.S_ISDIR(entry.st_mode)
                ):
                    raise SafeOutputError("staging contains a link or special entry")
                if stat.S_ISDIR(entry.st_mode):
                    child = os.open(name, directory_flags, dir_fd=directory_fd)
                    try:
                        if _record_identity(os.fstat(child)) != _record_identity(entry):
                            raise SafeOutputError(
                                "staging entry changed while publishing"
                            )
                        directories.add(relative)
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
                    identity = _record_identity(entry)
                    if _record_identity(os.fstat(file_fd)) != identity:
                        raise SafeOutputError("staging entry changed while publishing")
                    with os.fdopen(os.dup(file_fd), "rb") as handle:
                        digest = hashlib.file_digest(handle, "sha256").hexdigest()
                    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if (
                        _record_identity(os.fstat(file_fd)) != identity
                        or _record_identity(after) != identity
                    ):
                        raise SafeOutputError("staging entry changed while publishing")
                    records[relative] = digest
                finally:
                    os.close(file_fd)

        visit(root_fd, "")
        self._verify_path_identity()
        if set(records) != expected_files or directories != expected_directories:
            raise SafeOutputError("staging does not match exact expected file set")
        if isinstance(expected, Mapping) and any(
            records[path] != digest for path, digest in expected.items()
        ):
            raise SafeOutputError("staging entry changed while publishing")
        return MappingProxyType(records)

    def write_root_file(
        self, name: str, content: bytes | str, *, replace: bool = False
    ) -> Path:
        """Write a root-level file through the pinned staging descriptor."""

        if PurePosixPath(name).name != name or name in {"", ".", ".."}:
            raise SafeOutputError("staged output name must be root-local")
        _, root_fd, _, _ = self._descriptors()
        payload = content.encode() if isinstance(content, str) else content
        if type(payload) is not bytes:
            raise TypeError("safe output content must be bytes or text")
        temporary_name = f".{name}.{secrets.token_hex(16)}.tmp"
        temporary_created = False
        try:
            exists = _existing_regular_is_safe(root_fd, name)
            if exists and not replace:
                raise SafeOutputError("output target already exists")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=root_fd)
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
            now_exists = _existing_regular_is_safe(root_fd, name)
            if now_exists and not replace:
                raise SafeOutputError("output target already exists")
            os.replace(temporary_name, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            temporary_created = False
            os.fsync(root_fd)
        finally:
            if temporary_created:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_name, dir_fd=root_fd)
        return self.path / name

    def publish(
        self, destination: Path, expected: Mapping[str, str]
    ) -> PublicationOutcome:
        """Validate and atomically rename the originally created root."""

        destination_abs = _absolute_lexical(destination)
        if self.path.parent != destination_abs.parent:
            raise SafeOutputError(
                "staging and publication directories must be siblings"
            )
        parent_fd, _, _, identity = self._descriptors()
        self.validate(expected)
        self._verify_path_identity()
        try:
            os.stat(destination_abs.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SafeOutputError("published run already exists")
        os.rename(
            self.path.name,
            destination_abs.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        self._published_name = destination_abs.name
        warning: str | None = None
        try:
            published = os.stat(
                destination_abs.name, dir_fd=parent_fd, follow_symlinks=False
            )
            if (published.st_dev, published.st_ino) != identity:
                warning = "post-rename destination identity could not be verified"
            os.fsync(parent_fd)
        except OSError as error:
            warning = f"post-rename fsync: {error}"
        return PublicationOutcome(destination_abs, warning)

    def cleanup(self) -> None:
        """Remove only the original uncommitted root and prove its absence."""

        if self._parent_fd is None:
            return
        if self._published_name is not None:
            try:
                os.stat(
                    self.path.name,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                self._close_descriptors()
                return
            raise SafeOutputError("published staging source unexpectedly remains")
        try:
            self._verify_path_identity()
        except SafeOutputError:
            try:
                os.stat(
                    self.path.name,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                self._close_descriptors()
                return
            raise
        shutil.rmtree(self.path)
        try:
            os.stat(
                self.path.name,
                dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            self._close_descriptors()
            return
        raise SafeOutputError("owned staging directory remains after cleanup")

    def _close_descriptors(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None
        if self._parent_fd is not None:
            os.close(self._parent_fd)
            self._parent_fd = None


def create_private_directory(path: Path) -> PrivateDirectoryLease:
    return PrivateDirectoryLease(path).create()


def validated_private_tree(
    root: PrivateDirectoryLease, expected: Mapping[str, str] | set[str]
) -> Mapping[str, str]:
    return root.validate(expected)


def publish_private_directory(
    staging: PrivateDirectoryLease,
    destination: Path,
    expected: Mapping[str, str],
) -> PublicationOutcome:
    return staging.publish(destination, expected)


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
    "PrivateDirectoryLease",
    "PublicationOutcome",
    "create_private_directory",
    "validated_private_tree",
    "publish_private_directory",
    "remove_private_directory",
    "safe_atomic_write",
]
