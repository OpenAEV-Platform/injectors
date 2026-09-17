"""Deterministic, config-driven Rich traces for Prowler findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

_MISSING = object()
_DEFAULT_COLUMNS: tuple[dict[str, str], ...] = (
    {"title": "Check", "path": "value"},
    {"title": "Status", "path": "expectation_result"},
    {"title": "Severity", "path": "severity"},
    {"title": "Asset", "path": "asset_name"},
    {"title": "Region", "path": "region"},
    {"title": "Account", "path": "cloud_account"},
)


def _display_mapping(value: object) -> Mapping[str, Any]:
    """Convert supported models to display data without mutating source values."""
    if isinstance(value, Mapping):
        return value
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        dumped = model_dump(mode="json")
        if isinstance(dumped, Mapping):
            return dumped
    return {}


def _walk(values: list[object], parts: Sequence[str]) -> list[object]:
    """Walk one dot path, expanding list wildcards and numeric indexes."""
    if not parts:
        return values
    part, *remaining = parts
    next_values: list[object] = []
    for value in values:
        if part == "*":
            if isinstance(value, Mapping):
                next_values.extend(value.values())
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                next_values.extend(value)
            continue
        if isinstance(value, Mapping) and part in value:
            next_values.append(value[part])
            continue
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            try:
                next_values.append(value[int(part)])
            except (ValueError, IndexError):
                continue
    return _walk(next_values, remaining)


def extract(data: object, path: str) -> object:
    """Extract a dot path with ``|`` alternatives, returning a missing sentinel."""
    for alternative in (item.strip() for item in path.split("|")):
        if not alternative:
            continue
        values = _walk([data], alternative.split("."))
        usable = [value for value in values if value not in (None, "", [])]
        if usable:
            return usable[0] if len(usable) == 1 else usable
    return _MISSING


def _positive_int(value: object, default: int, maximum: int) -> int:
    """Constrain config limits even when a subclass supplies malformed values."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        return default
    return min(value, maximum)


def _format_cell(value: object, limit: int) -> str:
    """Render one bounded cell with stable placeholders and collection syntax."""
    if value is _MISSING or value is None or value == "":
        return "-"
    if isinstance(value, Mapping):
        text = "; ".join(
            f"{key}: {_format_cell(item, 40)}" for key, item in value.items()
        )
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        text = ", ".join(_format_cell(item, 40) for item in value)
    else:
        text = str(value)
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def _trace_columns(config: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], str]:
    """Read simple or Censys-shaped columns and a table title."""
    columns = config.get("columns")
    title = "Prowler Findings"
    tables = config.get("tables")
    if not isinstance(columns, list) and isinstance(tables, list) and tables:
        first = tables[0]
        if isinstance(first, Mapping):
            header = first.get("header")
            if isinstance(header, Mapping) and isinstance(header.get("title"), str):
                title = header["title"]
            table_config = first.get("config")
            if isinstance(table_config, Mapping):
                columns = table_config.get("columns")
    valid: list[Mapping[str, Any]] = []
    if isinstance(columns, list):
        valid = [
            item
            for item in columns[:8]
            if isinstance(item, Mapping)
            and isinstance(item.get("title"), str)
            and isinstance(item.get("path"), str)
        ]
    return (valid or list(_DEFAULT_COLUMNS), title)


def _summary(findings: Sequence[Mapping[str, Any]], field: str) -> str:
    """Count one flattened finding field in stable lexical order."""
    counts = Counter(
        str(value)
        for finding in findings
        if (value := extract(finding, field)) is not _MISSING
    )
    return " ".join(f"{key}={counts[key]}" for key in sorted(counts)) or "none"


def _joined_preview_cell(
    preview: Mapping[str, Any], first: str, second: str, limit: int
) -> str:
    """Combine two statically allowlisted preview fields into one compact cell."""
    first_value = _format_cell(preview.get(first, _MISSING), limit)
    second_value = _format_cell(preview.get(second, _MISSING), limit)
    if second_value == "-":
        return first_value
    if first_value == "-":
        return second_value
    return _format_cell(f"{first_value} [{second_value}]", limit)


def _raw_preview_renderables(
    raw_record_count: int,
    raw_output_bytes: int,
    raw_preview: Sequence[object],
    max_cell_length: int,
) -> list[RenderableType]:
    """Render only the closed, already-projected raw OCSF evidence boundary."""
    previews = [_display_mapping(item) for item in raw_preview[:10]]
    table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=True)
    table.add_column("#", width=4)
    for title in ("Finding", "Status", "Severity", "Resource", "Cloud / Provider UID"):
        table.add_column(title, overflow="fold")
    for index, preview in enumerate(previews, 1):
        provider_uid = _format_cell(
            preview.get("provider_uid", _MISSING), max_cell_length
        )
        cloud_parts = [
            _format_cell(preview.get(key, _MISSING), max_cell_length)
            for key in ("cloud_provider", "cloud_region", "cloud_account")
        ]
        usable_cloud = [part for part in cloud_parts if part != "-"]
        cloud = " / ".join(usable_cloud) if usable_cloud else provider_uid
        table.add_row(
            str(index),
            _joined_preview_cell(
                preview, "finding_title", "finding_uid", max_cell_length
            ),
            _joined_preview_cell(preview, "status", "status_code", max_cell_length),
            _format_cell(preview.get("severity", _MISSING), max_cell_length),
            _joined_preview_cell(
                preview, "resource_name", "resource_uid", max_cell_length
            ),
            _format_cell(cloud, max_cell_length),
        )
    omitted = max(0, raw_record_count - len(previews))
    return [
        Text(""),
        Rule("[PROWLER] Raw OCSF evidence (bounded preview)", characters="─"),
        Text(f"Total raw records: {raw_record_count}"),
        Text(f"Artifact bytes: {raw_output_bytes}"),
        table,
        Text(f"Records omitted: {omitted}"),
    ]


def _trace_options(config: Mapping[str, Any]) -> tuple[int, int, str]:
    """Normalize display limits and the configured-or-derived report title."""
    options = config.get("options")
    options = options if isinstance(options, Mapping) else {}
    max_rows = _positive_int(options.get("max_rows"), 50, 100)
    max_cell_length = _positive_int(options.get("max_cell_length"), 120, 500)
    header = config.get("header")
    header = header if isinstance(header, Mapping) else {}
    title = header.get("title")
    if not isinstance(title, str) or not title.strip():
        return max_rows, max_cell_length, ""
    return max_rows, max_cell_length, title


def _report_opening(title: str) -> list[RenderableType]:
    """Render the fixed report framing around a resolved title."""
    return [
        Text(""),
        Rule(characters="─"),
        Panel(Align.center(Text(title)), padding=(1, 1)),
        Text(""),
        Rule(characters="─"),
    ]


def _request_renderables(
    provider_name: str, request_info: Mapping[str, object], max_cell_length: int
) -> list[RenderableType]:
    """Render the supplied, already-safe request metadata."""
    request_tree = Tree(Text("[CONFIG] Safe request summary"), guide_style="bold")
    request_tree.add(Text(f"provider: {_format_cell(provider_name, max_cell_length)}"))
    for key, value in request_info.items():
        if value not in (None, "", []):
            request_tree.add(Text(f"{key}: {_format_cell(value, max_cell_length)}"))
    return [request_tree, Text(""), Rule(characters="─")]


def _execution_renderable(
    display_findings: Sequence[Mapping[str, Any]],
    duration: int,
    is_error: bool,
    error_message: str,
    raw_record_count: int,
    raw_output_bytes: int,
) -> Tree:
    """Render mutually exclusive success or failure execution details."""
    heading = (
        "[PROWLER] Assessment failed" if is_error else "[PROWLER] Assessment completed"
    )
    execution = Tree(Text(heading), guide_style="bold")
    if is_error:
        failure = execution.add(Text("Call Failed"))
        diagnostics = failure.add(Text("Error diagnostics"))
        for line in error_message.splitlines()[:32]:
            diagnostics.add(Text(_format_cell(line, 600)))
        return execution

    success = execution.add(Text("Call Success"))
    success.add(Text(f"Findings: {len(display_findings)}"))
    success.add(Text(f"Duration: {duration}s"))
    success.add(Text(f"Artifact capture: complete ({raw_output_bytes} bytes)"))
    success.add(Text(f"OCSF mapping: complete ({raw_record_count} raw records)"))
    success.add(
        Text("Status Summary: " f"{_summary(display_findings, 'expectation_result')}")
    )
    success.add(Text(f"Severity Summary: {_summary(display_findings, 'severity')}"))
    return execution


def _findings_renderables(
    display_findings: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    max_rows: int,
    max_cell_length: int,
    raw_record_count: int,
    raw_output_bytes: int,
    raw_preview: Sequence[object],
) -> list[RenderableType]:
    """Render the findings table and bounded raw-evidence preview."""
    renderables: list[RenderableType] = [Text(""), Rule(characters="─")]
    if not display_findings:
        renderables.append(
            Panel(Text("No findings to display"), title="Prowler Findings")
        )
    else:
        columns, table_title = _trace_columns(config)
        table = Table(
            title=table_title,
            title_justify="left",
            show_lines=True,
            box=box.HEAVY_HEAD,
            expand=True,
        )
        table.add_column("#", width=4)
        for column in columns:
            table.add_column(str(column["title"]), overflow="fold")
        for index, finding in enumerate(display_findings[:max_rows], 1):
            cells = [Text(str(index))]
            cells.extend(
                Text(
                    _format_cell(extract(finding, str(column["path"])), max_cell_length)
                )
                for column in columns
            )
            table.add_row(*cells)
        hidden = len(display_findings) - max_rows
        if hidden > 0:
            suffix = "finding" if hidden == 1 else "findings"
            table.add_row(
                Text("..."),
                Text(f"+{hidden} more {suffix}"),
                *[Text("") for _ in columns[1:]],
            )
        renderables.append(table)
    renderables.extend(
        _raw_preview_renderables(
            raw_record_count,
            raw_output_bytes,
            raw_preview,
            max_cell_length,
        )
    )
    return renderables


def _capture(renderables: Sequence[RenderableType]) -> str:
    """Capture Rich renderables with the stable non-terminal console settings."""
    console = Console(color_system=None, force_terminal=False, width=150)
    with console.capture() as capture:
        console.print(Group(*renderables))
    return capture.get()


def generate(
    route_name: str,
    provider_name: str,
    request_info: Mapping[str, object],
    findings: Sequence[object],
    duration: int,
    trace_config: Mapping[str, Any] | None = None,
    is_error: bool = False,
    error_message: str = "",
    raw_record_count: int = 0,
    raw_output_bytes: int = 0,
    raw_preview: Sequence[object] = (),
) -> str:
    """Capture one bounded Rich report from explicitly safe display inputs."""
    config = trace_config or {}
    max_rows, max_cell_length, title = _trace_options(config)
    if not title:
        title = f"PROWLER - {route_name.upper()}"

    display_findings = [_display_mapping(finding) for finding in findings]
    renderables = _report_opening(title)
    renderables.extend(
        _request_renderables(provider_name, request_info, max_cell_length)
    )
    renderables.append(
        _execution_renderable(
            display_findings,
            duration,
            is_error,
            error_message,
            raw_record_count,
            raw_output_bytes,
        )
    )

    if not is_error:
        renderables.extend(
            _findings_renderables(
                display_findings,
                config,
                max_rows,
                max_cell_length,
                raw_record_count,
                raw_output_bytes,
                raw_preview,
            )
        )
    return _capture(renderables)
