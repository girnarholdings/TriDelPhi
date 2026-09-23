"""Small, shared filesystem primitives for user-visible output files."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

__all__ = ["atomic_copy_file", "atomic_write_text"]

_COPY_CHUNK = 1024 * 1024
_DEFAULT_MAX_COPY_BYTES = 256 * 1024 * 1024


def _first_symlink_component(path: Path) -> Path | None:
    """Find a symlink in ``path`` without resolving through it.

    ``Path.resolve`` is deliberately not used: resolving first would erase the
    evidence that an attacker-controlled ancestor redirected the destination.
    Parent traversal components are handled only after every preceding
    component has been checked.
    """

    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        if part in ("", "."):
            continue
        if part == "..":
            current = current.parent
            continue
        current = current / part
        if current.is_symlink():
            return current
    return None


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    create_parent: bool = False,
    mode: int | None = None,
) -> None:
    """Write UTF-8 text without following an existing destination symlink.

    The temporary file is created beside the destination, flushed, fsynced and
    atomically replaced. A caller must opt in to parent creation so a misspelled
    output path does not silently create a new directory tree.
    """

    target = Path(path)
    parent = target.parent
    if (linked := _first_symlink_component(parent)) is not None:
        raise OSError(f"refusing to write through symlinked directory: {linked}")
    if create_parent:
        parent.mkdir(parents=True, exist_ok=True)
    # Re-check after mkdir so a path that was only partly present above is held
    # to the same rule once all of its components exist.
    if (linked := _first_symlink_component(parent)) is not None:
        raise OSError(f"refusing to write through symlinked directory: {linked}")
    if not parent.is_dir():
        raise OSError(f"parent directory does not exist: {parent}")
    if target.is_symlink():
        raise OSError(f"refusing to replace symlink: {target}")
    final_mode = mode
    if final_mode is None:
        try:
            final_mode = stat.S_IMODE(target.stat(follow_symlinks=False).st_mode)
        except FileNotFoundError:
            final_mode = 0o644
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            # A report can quote a file name that is not valid UTF-8 (a lone
            # surrogate in Python). Write it as a visible escape rather than
            # abandon the report — and the temp file — halfway.
            errors="backslashreplace",
            newline="\n",
            dir=parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(final_mode)
        os.replace(temporary, target)
    except OSError:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def atomic_copy_file(
    source: str | Path,
    destination: str | Path,
    *,
    max_bytes: int = _DEFAULT_MAX_COPY_BYTES,
    create_parent: bool = False,
) -> None:
    """Copy a regular file without following source or destination symlinks.

    GitHub Actions integrations commonly need an internal, trusted artifact for
    upload *and* a user-selected copy in the workspace.  A normal ``cp`` follows
    a pre-planted symlink and can overwrite a different file.  This helper opens
    the source with ``O_NOFOLLOW`` where available, streams into a sibling temp
    file, and atomically replaces the requested destination only after the copy
    is complete.  A size ceiling keeps this convenience path from becoming an
    unbounded disk copy.
    """

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")

    src = Path(source)
    target = Path(destination)
    if (linked := _first_symlink_component(src)) is not None:
        raise OSError(f"refusing to read through symlink: {linked}")

    parent = target.parent
    if (linked := _first_symlink_component(parent)) is not None:
        raise OSError(f"refusing to write through symlinked directory: {linked}")
    if create_parent:
        parent.mkdir(parents=True, exist_ok=True)
    if (linked := _first_symlink_component(parent)) is not None:
        raise OSError(f"refusing to write through symlinked directory: {linked}")
    if not parent.is_dir():
        raise OSError(f"parent directory does not exist: {parent}")
    if target.is_symlink():
        raise OSError(f"refusing to replace symlink: {target}")

    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW
    source_fd = os.open(src, open_flags)
    temporary: Path | None = None
    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise OSError(f"source is not a regular file: {src}")
        if source_stat.st_size > max_bytes:
            raise OSError(
                f"source exceeds the {max_bytes}-byte artifact copy limit: {src}"
            )

        with (
            os.fdopen(source_fd, "rb", closefd=False) as source_handle,
            tempfile.NamedTemporaryFile(
                mode="wb",
                dir=parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as destination_handle,
        ):
            temporary = Path(destination_handle.name)
            copied = 0
            while chunk := source_handle.read(_COPY_CHUNK):
                copied += len(chunk)
                if copied > max_bytes:
                    raise OSError(
                        f"source exceeds the {max_bytes}-byte artifact copy limit: {src}"
                    )
                destination_handle.write(chunk)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, target)
    except OSError:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(source_fd)
