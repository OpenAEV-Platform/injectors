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


def generate(
    route_name: str,
    provider_name: str,
    request_info: Mapping[str, object],
    findings: Sequence[object],
    duration: int,
    trace_config: Mapping[str, Any] | None = None,
    is_error: bool = False,
    error_message: str = "",
) -> str:
    """Capture one bounded Rich report from explicitly safe display inputs."""
    config = trace_config or {}
    options = config.get("options")
    options = options if isinstance(options, Mapping) else {}
    max_rows = _positive_int(options.get("max_rows"), 50, 100)
    max_cell_length = _positive_int(options.get("max_cell_length"), 120, 500)
    header = config.get("header")
    header = header if isinstance(header, Mapping) else {}
    title = header.get("title")
    if not isinstance(title, str) or not title.strip():
        title = f"PROWLER - {route_name.upper()}"

    display_findings = [_display_mapping(finding) for finding in findings]
    renderables: list[RenderableType] = [
        Text(""),
        Rule(characters="─"),
        Panel(Align.center(Text(title)), padding=(1, 1)),
        Text(""),
        Rule(characters="─"),
    ]

    request_tree = Tree(Text("[CONFIG] Safe request summary"), guide_style="bold")
    request_tree.add(Text(f"provider: {_format_cell(provider_name, max_cell_length)}"))
    for key, value in request_info.items():
        if value not in (None, "", []):
            request_tree.add(Text(f"{key}: {_format_cell(value, max_cell_length)}"))
    renderables.append(request_tree)
    renderables.extend((Text(""), Rule(characters="─")))

    heading = (
        "[PROWLER] Assessment failed" if is_error else "[PROWLER] Assessment completed"
    )
    execution = Tree(Text(heading), guide_style="bold")
    if is_error:
        failure = execution.add(Text("Call Failed"))
        diagnostics = failure.add(Text("Error diagnostics"))
        for line in error_message.splitlines()[:32]:
            diagnostics.add(Text(_format_cell(line, 600)))
    else:
        success = execution.add(Text("Call Success"))
        success.add(Text(f"Findings: {len(display_findings)}"))
        success.add(Text(f"Duration: {duration}s"))
        success.add(
            Text(
                "Status Summary: " f"{_summary(display_findings, 'expectation_result')}"
            )
        )
        success.add(Text(f"Severity Summary: {_summary(display_findings, 'severity')}"))
    renderables.append(execution)

    if not is_error:
        renderables.extend((Text(""), Rule(characters="─")))
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
                        _format_cell(
                            extract(finding, str(column["path"])), max_cell_length
                        )
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

    console = Console(color_system=None, force_terminal=False, width=150)
    with console.capture() as capture:
        console.print(Group(*renderables))
    return capture.get()
