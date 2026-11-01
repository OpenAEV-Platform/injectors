"""Output-workspace security and lifecycle tests for CHK.004."""

# ruff: noqa: D101, D102, D103

import os
import shutil
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


def _api() -> Any:
    from prowler._core import prowler_client

    return prowler_client


def test_posix_prefers_writable_dev_shm_equivalent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    memory_root = tmp_path / "dev-shm"
    memory_root.mkdir()
    monkeypatch.setattr(os, "access", lambda path, mode: path == memory_root)
    api = _api()
    required_capacity = (
        api.DEFAULT_MAXIMUM_ARTIFACT_BYTES
        + api.DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES
    )
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=required_capacity),
    )

    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(
            platform_name="posix",
            memory_root=memory_root,
            temporary_root=tmp_path / "disk",
        )
        .create()
    )
    try:
        assert workspace.backend == "memory_tmpfs"
        assert workspace.directory.parent == memory_root
        assert workspace.directory.stat().st_mode & 0o777 == 0o700
        assert workspace.artifact_path.name == "findings.ocsf.json"
    finally:
        workspace.cleanup()


def test_posix_rejects_tmpfs_without_artifact_capacity_plus_safety_margin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = _api()
    memory_root = tmp_path / "dev-shm"
    memory_root.mkdir()
    disk_root = tmp_path / "disk"
    disk_root.mkdir()
    monkeypatch.setattr(os, "access", lambda path, mode: path == memory_root)
    required_capacity = (
        api.DEFAULT_MAXIMUM_ARTIFACT_BYTES
        + api.DEFAULT_MEMORY_TMPFS_SAFETY_MARGIN_BYTES
    )
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=required_capacity - 1),
    )

    workspace = api.TemporaryOutputWorkspaceFactory(
        platform_name="posix",
        memory_root=memory_root,
        temporary_root=disk_root,
    ).create()
    try:
        assert workspace.backend == "filesystem_temp"
        assert workspace.directory.parent == disk_root
    finally:
        workspace.cleanup()


def test_tmpfs_capacity_probe_failure_falls_back_to_system_temp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    memory_root = tmp_path / "dev-shm"
    memory_root.mkdir()
    disk_root = tmp_path / "disk"
    disk_root.mkdir()
    monkeypatch.setattr(os, "access", lambda path, mode: path == memory_root)
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: (_ for _ in ()).throw(OSError("probe failed")),
    )

    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(
            platform_name="posix",
            memory_root=memory_root,
            temporary_root=disk_root,
        )
        .create()
    )
    try:
        assert workspace.backend == "filesystem_temp"
        assert workspace.directory.parent == disk_root
    finally:
        workspace.cleanup()


def test_tmpfs_creation_failure_falls_back_once_to_system_temp(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = _api()
    memory_root = tmp_path / "dev-shm"
    memory_root.mkdir()
    disk_root = tmp_path / "disk"
    disk_root.mkdir()
    monkeypatch.setattr(os, "access", lambda path, mode: path == memory_root)
    monkeypatch.setattr(
        shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=1024 * 1024 * 1024),
    )
    original_temporary_directory = __import__("tempfile").TemporaryDirectory
    creation_roots: list[Path | None] = []

    def create_with_tmpfs_failure(*, prefix: str, dir: Path | None) -> Any:
        creation_roots.append(dir)
        if dir == memory_root:
            raise OSError("tmpfs creation failed")
        return original_temporary_directory(prefix=prefix, dir=dir)

    monkeypatch.setattr("tempfile.TemporaryDirectory", create_with_tmpfs_failure)

    workspace = api.TemporaryOutputWorkspaceFactory(
        platform_name="posix",
        memory_root=memory_root,
        temporary_root=disk_root,
    ).create()
    try:
        assert workspace.backend == "filesystem_temp"
        assert workspace.directory.parent == disk_root
        assert creation_roots == [memory_root, disk_root]
    finally:
        workspace.cleanup()


@pytest.mark.parametrize("memory_state", ["missing", "file", "unwritable"])
def test_posix_falls_back_to_system_temp_when_memory_root_is_unsuitable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, memory_state: str
) -> None:
    memory_root = tmp_path / "dev-shm"
    if memory_state == "file":
        memory_root.write_text("not a directory", encoding="utf-8")
    elif memory_state == "unwritable":
        memory_root.mkdir()
    monkeypatch.setattr(os, "access", lambda _path, _mode: False)
    disk_root = tmp_path / "disk"
    disk_root.mkdir()

    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(
            platform_name="posix", memory_root=memory_root, temporary_root=disk_root
        )
        .create()
    )
    try:
        assert workspace.backend == "filesystem_temp"
        assert workspace.directory.parent == disk_root
    finally:
        workspace.cleanup()


def test_windows_uses_system_temp_without_posix_permission_claim(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    chmod_calls: list[tuple[object, object]] = []
    monkeypatch.setattr(
        os, "chmod", lambda path, mode: chmod_calls.append((path, mode))
    )

    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(
            platform_name="nt",
            memory_root=tmp_path / "dev-shm",
            temporary_root=tmp_path,
        )
        .create()
    )
    try:
        assert workspace.backend == "filesystem_temp"
        assert chmod_calls == []
    finally:
        workspace.cleanup()


def test_concurrent_workspaces_are_unique_and_cleanup_only_their_owned_tree(
    tmp_path: Path,
) -> None:
    factory = _api().TemporaryOutputWorkspaceFactory(
        platform_name="nt", temporary_root=tmp_path
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        workspaces = list(pool.map(lambda _index: factory.create(), range(16)))

    sentinel = tmp_path / "unrelated"
    sentinel.write_text("preserve", encoding="utf-8")
    try:
        assert len({workspace.directory for workspace in workspaces}) == 16
        for workspace in workspaces:
            nested = workspace.directory / "compliance" / "nested"
            nested.mkdir(parents=True)
            (nested / "result.json").write_text("fixture", encoding="utf-8")
            workspace.cleanup()
            workspace.cleanup()
            assert not workspace.directory.exists()
        assert sentinel.read_text(encoding="utf-8") == "preserve"
    finally:
        for workspace in workspaces:
            workspace.cleanup()


@pytest.mark.parametrize(
    ("artifact_kind", "expected_kind"),
    [
        ("missing", "missing"),
        ("directory", "nonregular"),
        ("symlink", "nonregular"),
        ("oversized", "oversized"),
    ],
)
def test_artifact_reader_fails_closed_without_path_or_exception_text(
    tmp_path: Path, artifact_kind: str, expected_kind: str
) -> None:
    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(platform_name="nt", temporary_root=tmp_path)
        .create()
    )
    canary = "path-canary-secret"
    try:
        if artifact_kind == "directory":
            workspace.artifact_path.mkdir()
        elif artifact_kind == "symlink":
            target = workspace.directory / canary
            target.write_bytes(b"{}")
            workspace.artifact_path.symlink_to(target)
        elif artifact_kind == "oversized":
            workspace.artifact_path.write_bytes(b"12345")

        with pytest.raises(_api().OutputArtifactError) as caught:
            workspace.read_artifact(maximum_bytes=4)

        assert caught.value.kind == expected_kind
        assert canary not in repr(caught.value)
        assert str(workspace.directory) not in repr(caught.value)
    finally:
        workspace.cleanup()


def test_artifact_reader_accepts_exact_limit_and_reads_incrementally(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(platform_name="nt", temporary_root=tmp_path)
        .create()
    )
    workspace.artifact_path.write_bytes(b"1234")
    real_read = os.read
    read_sizes: list[int] = []

    def recording_read(descriptor: int, size: int) -> bytes:
        read_sizes.append(size)
        return real_read(descriptor, min(size, 2))

    monkeypatch.setattr(os, "read", recording_read)
    try:
        assert workspace.read_artifact(maximum_bytes=4) == b"1234"
        assert len(read_sizes) >= 3
    finally:
        workspace.cleanup()


def test_artifact_read_failure_is_typed_and_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(platform_name="nt", temporary_root=tmp_path)
        .create()
    )
    workspace.artifact_path.write_bytes(b"{}")
    monkeypatch.setattr(
        os,
        "read",
        lambda _descriptor, _size: (_ for _ in ()).throw(OSError("unsafe-canary")),
    )
    try:
        with pytest.raises(_api().OutputArtifactError) as caught:
            workspace.read_artifact(maximum_bytes=4)
        assert caught.value.kind == "unreadable"
        assert "unsafe-canary" not in repr(caught.value)
    finally:
        workspace.cleanup()


def test_artifact_reader_preserves_preopen_and_opened_file_identity_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = (
        _api()
        .TemporaryOutputWorkspaceFactory(platform_name="nt", temporary_root=tmp_path)
        .create()
    )
    workspace.artifact_path.write_bytes(b"{}")
    path_status = workspace.artifact_path.lstat()
    try:
        with monkeypatch.context() as identity_patch:
            identity_patch.setattr(
                os,
                "fstat",
                lambda _descriptor: SimpleNamespace(
                    st_mode=stat.S_IFREG,
                    st_dev=path_status.st_dev,
                    st_ino=path_status.st_ino + 1,
                ),
            )
            with pytest.raises(_api().OutputArtifactError) as caught:
                workspace.read_artifact(maximum_bytes=4)
        assert caught.value.kind == "nonregular"
    finally:
        workspace.cleanup()


def test_windows_reparse_safety_is_documented_without_false_atomic_claim() -> None:
    repository_root = Path(__file__).parents[3]
    output_storage = (
        (repository_root / "README.md")
        .read_text(encoding="utf-8")
        .split("## Assessment output storage", maxsplit=1)[1]
    )
    windows_safety = output_storage.lower()

    assert "best-effort" in windows_safety
    assert "controlled directory" in windows_safety
    assert "identity checks" in windows_safety
    assert "does not claim atomic reparse-point exclusion" in windows_safety
