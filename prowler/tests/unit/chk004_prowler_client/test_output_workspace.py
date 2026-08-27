"""Output-workspace security and lifecycle tests for CHK.004."""

# ruff: noqa: D101, D102, D103

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
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
