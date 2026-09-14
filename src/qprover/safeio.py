"""Race-resistant local output primitives for proof artifacts."""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import shutil
import signal
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType


class SafeOutputError(RuntimeError):
    """An output path violates the trusted local publication boundary."""


class StaleOwnershipError(SafeOutputError):
    """An owned pathname now names another object and must be left untouched."""

    drop_cleanup_ownership = True


class PublicationIntegrityError(SafeOutputError):
    """A post-rename integrity check failed; no destination is usable."""

    def __init__(
        self,
        message: str,
        *,
        quarantined: bool,
        ambiguous_visible_path: bool,
        quarantine_path: Path | None,
    ) -> None:
        self.destination = None
        self.quarantined = quarantined
        self.ambiguous_visible_path = ambiguous_visible_path
        self.quarantine_path = quarantine_path
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PublicationOutcome:
    """The post-rename state; durability warnings cannot revoke a committed run."""

    destination: Path
    durability_warning: str | None = None


@dataclass(frozen=True, slots=True)
class _TreeSnapshot:
    hashes: Mapping[str, str]
    identities: Mapping[str, tuple[int, ...]]


@contextmanager
def _blocked_termination_signals() -> Iterator[None]:
    """Defer cooperative termination across the final namespace handoff."""

    if not hasattr(signal, "pthread_sigmask"):
        yield
        return
    blocked = {signal.SIGINT, signal.SIGTERM}
    prior = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, prior)


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
            or any(ord(character) < 32 or ord(character) == 127 for character in raw)
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
        self._entry_name = self.path.name
        self._committed = False
        self._published_integrity_complete = False
        self._quarantined = False

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
            self._entry_name = name
            os.fsync(parent_fd)
            return self
        except BaseException as creation_error:
            if self._parent_fd is not None:
                try:
                    self.cleanup()
                except StaleOwnershipError as ownership_error:
                    raise ownership_error from creation_error
                except BaseException:
                    pass
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

    def _verify_reachable_identity(self, lexical_path: Path, entry_name: str) -> None:
        parent_fd, root_fd, parent_identity, identity = self._descriptors()
        try:
            fresh_parent_fd, fresh_name, _ = _open_parent(lexical_path, create=False)
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
            if fresh_name != entry_name:
                raise SafeOutputError("staging root identity changed while publishing")
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
                entry_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError as error:
            raise SafeOutputError(
                "staging root identity is no longer reachable"
            ) from error
        if (pathname.st_dev, pathname.st_ino) != identity:
            raise SafeOutputError("staging root identity changed while publishing")

    def _snapshot(self, expected: Mapping[str, str] | set[str]) -> _TreeSnapshot:
        _, root_fd, _, _ = self._descriptors()
        expected_files, expected_directories = _expected_paths(expected)
        records: dict[str, str] = {}
        identities: dict[str, tuple[int, ...]] = {}
        directories: set[str] = set()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

        def visit(directory_fd: int, prefix: str) -> None:
            directory_before = _record_identity(os.fstat(directory_fd))
            names_before = tuple(sorted(os.listdir(directory_fd)))
            for name in names_before:
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
                        identities[relative] = _record_identity(entry)
                        visit(child, relative)
                        child_after = os.fstat(child)
                    finally:
                        os.close(child)
                    entry_after = os.stat(
                        name, dir_fd=directory_fd, follow_symlinks=False
                    )
                    if _record_identity(child_after) != _record_identity(
                        entry
                    ) or _record_identity(entry_after) != _record_identity(entry):
                        raise SafeOutputError("staging entry changed while publishing")
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
                    identities[relative] = identity
                finally:
                    os.close(file_fd)
            if tuple(sorted(os.listdir(directory_fd))) != names_before:
                raise SafeOutputError("staging entries changed while publishing")
            if _record_identity(os.fstat(directory_fd)) != directory_before:
                raise SafeOutputError("staging directory changed while publishing")

        visit(root_fd, "")
        if set(records) != expected_files or directories != expected_directories:
            raise SafeOutputError("staging does not match exact expected file set")
        if isinstance(expected, Mapping) and any(
            records[path] != digest for path, digest in expected.items()
        ):
            raise SafeOutputError("staging entry changed while publishing")
        return _TreeSnapshot(MappingProxyType(records), MappingProxyType(identities))

    def validate(self, expected: Mapping[str, str] | set[str]) -> Mapping[str, str]:
        """Hash the pinned tree and require exactly the declared file set."""

        self._verify_reachable_identity(self.path, self._entry_name)
        snapshot = self._snapshot(expected)
        self._verify_reachable_identity(self.path, self._entry_name)
        return snapshot.hashes

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
        self._verify_reachable_identity(self.path, self._entry_name)
        before = self._snapshot(expected)
        self._verify_reachable_identity(self.path, self._entry_name)
        try:
            os.stat(destination_abs.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SafeOutputError("published run already exists")
        with _blocked_termination_signals():
            try:
                os.rename(
                    self._entry_name,
                    destination_abs.name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
            except BaseException as error:
                try:
                    renamed = os.stat(
                        destination_abs.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    raise error from None
                if (renamed.st_dev, renamed.st_ino) != identity:
                    raise error from None
                self._entry_name = destination_abs.name
                self._committed = True
                integrity = self._quarantine_after_integrity_failure(
                    destination_abs, error
                )
                raise integrity from error
            self._entry_name = destination_abs.name
            self._committed = True
            try:
                self._verify_reachable_identity(destination_abs, self._entry_name)
                after = self._snapshot(expected)
                self._verify_reachable_identity(destination_abs, self._entry_name)
                if (
                    after.hashes != before.hashes
                    or after.identities != before.identities
                ):
                    raise SafeOutputError(
                        "staging identity tree changed during final publication handoff"
                    )
                self._published_integrity_complete = True
            except BaseException as error:
                integrity = self._quarantine_after_integrity_failure(
                    destination_abs, error
                )
                raise integrity from error
        try:
            os.fsync(parent_fd)
        except OSError as error:
            return PublicationOutcome(destination_abs, f"post-rename fsync: {error}")
        return PublicationOutcome(destination_abs)

    def _quarantine_after_integrity_failure(
        self, destination: Path, cause: BaseException
    ) -> PublicationIntegrityError:
        parent_fd, _, parent_identity, identity = self._descriptors()
        quarantine_name = (
            f".{destination.name}.{secrets.token_hex(16)}.integrity-failed"
        )
        quarantine_path: Path | None = None
        lexical_parent_matches = False
        try:
            published = os.stat(
                self._entry_name, dir_fd=parent_fd, follow_symlinks=False
            )
            if (published.st_dev, published.st_ino) != identity:
                raise SafeOutputError("visible destination no longer names pinned root")
            os.rename(
                self._entry_name,
                quarantine_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            quarantined = os.stat(
                quarantine_name, dir_fd=parent_fd, follow_symlinks=False
            )
            if (quarantined.st_dev, quarantined.st_ino) != identity:
                raise SafeOutputError("quarantine identity verification failed")
            try:
                os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise SafeOutputError("visible destination remains after quarantine")
            self._entry_name = quarantine_name
            self._committed = False
            self._quarantined = True
            try:
                fresh_parent_fd, _, _ = _open_parent(destination, create=False)
            except SafeOutputError:
                fresh_parent_fd = None
            if fresh_parent_fd is not None:
                try:
                    fresh_parent = os.fstat(fresh_parent_fd)
                    if (fresh_parent.st_dev, fresh_parent.st_ino) == parent_identity:
                        lexical_parent_matches = True
                        quarantine_path = destination.parent / quarantine_name
                finally:
                    os.close(fresh_parent_fd)
            return PublicationIntegrityError(
                f"post-rename publication integrity failure: {cause}",
                quarantined=True,
                ambiguous_visible_path=not lexical_parent_matches,
                quarantine_path=quarantine_path,
            )
        except BaseException as quarantine_error:
            return PublicationIntegrityError(
                "post-rename publication integrity failure; visible path is "
                f"ambiguous and unusable: {cause}; quarantine: {quarantine_error}",
                quarantined=False,
                ambiguous_visible_path=True,
                quarantine_path=None,
            )

    def cleanup(self) -> None:
        """Remove only the original uncommitted root and prove its absence."""

        if self._parent_fd is None:
            return
        parent_fd, _, _, identity = self._descriptors()
        if self._committed and self._published_integrity_complete:
            self._close_descriptors()
            return
        if self._committed:
            try:
                current = os.stat(
                    self._entry_name, dir_fd=parent_fd, follow_symlinks=False
                )
            except FileNotFoundError as error:
                self._close_descriptors()
                raise StaleOwnershipError(
                    "published root is missing; detached original is not proven cleaned"
                ) from error
            if (current.st_dev, current.st_ino) != identity:
                self._close_descriptors()
                raise StaleOwnershipError(
                    "published root identity changed; detached original is not proven "
                    "cleaned and the later-owner path was left untouched"
                )
            self._committed = False
        try:
            current = os.stat(self._entry_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError as error:
            self._close_descriptors()
            raise StaleOwnershipError(
                "owned root is missing; detached original is not proven cleaned"
            ) from error
        if (current.st_dev, current.st_ino) != identity:
            self._close_descriptors()
            raise StaleOwnershipError(
                "owned root identity changed; detached original is not proven cleaned "
                "and the later-owner path was left untouched"
            )
        try:
            self._make_owned_directories_writable()
        except StaleOwnershipError:
            self._close_descriptors()
            raise
        final = os.stat(self._entry_name, dir_fd=parent_fd, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != identity:
            self._close_descriptors()
            raise StaleOwnershipError(
                "owned root identity changed immediately before cleanup; the "
                "later-owner path was left untouched"
            )
        shutil.rmtree(self._entry_name, dir_fd=parent_fd)
        try:
            os.stat(
                self._entry_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            self._close_descriptors()
            return
        raise SafeOutputError("owned staging directory remains after cleanup")

    def _make_owned_directories_writable(self) -> None:
        """Restore owner access through pinned fds without following links."""

        _, root_fd, _, _ = self._descriptors()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)

        def visit(directory_fd: int) -> None:
            os.fchmod(directory_fd, stat.S_IRWXU)
            for name in os.listdir(directory_fd):
                entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode):
                    continue
                os.chmod(
                    name,
                    stat.S_IRWXU,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                writable = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (writable.st_dev, writable.st_ino) != (entry.st_dev, entry.st_ino):
                    raise StaleOwnershipError(
                        "owned child identity changed during cleanup; cleanup "
                        "ownership was dropped"
                    )
                child = os.open(name, directory_flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                        raise StaleOwnershipError(
                            "owned child identity changed during cleanup; cleanup "
                            "ownership was dropped"
                        )
                    visit(child)
                finally:
                    os.close(child)

        visit(root_fd)

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
    "PublicationIntegrityError",
    "PrivateDirectoryLease",
    "PublicationOutcome",
    "StaleOwnershipError",
    "create_private_directory",
    "validated_private_tree",
    "publish_private_directory",
    "remove_private_directory",
    "safe_atomic_write",
]
