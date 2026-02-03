import json
from datetime import datetime
from enum import Enum
from typing import Any

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.json import JSON
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree


class OutputIcons(Enum):
    SUCCESS = "✅"
    FAILED = "❌"
    SEARCH = "🔍"
    CONFIG = "⚙️"
    INFO = "ℹ️"
    API = "🌐"


class Utils:

    @staticmethod
    def _get_trace_config(output_trace_config: dict, path: str, default=None):
        keys = path.split(".")
        try:
            for key in keys:
                output_trace_config = output_trace_config[key]
            return output_trace_config
        except (KeyError, TypeError):
            return default

    def _add_value_to_tree(self, tree: Tree, key: str, value: Any) -> None:
        if isinstance(value, list):
            node = tree.add(f"{key}:")
            for item in value:
                if isinstance(item, dict):
                    for sub_key, sub_value in item.items():
                        if sub_value is None or sub_value == "":
                            continue
                        self._add_value_to_tree(node, sub_key, sub_value)
                else:
                    node.add(str(item))
        elif isinstance(value, dict):
            node = tree.add(f"{key}:")
            for sub_key, sub_value in value.items():
                if sub_value is None or sub_value == "":
                    continue
                self._add_value_to_tree(node, sub_key, sub_value)
        else:
            tree.add(f"{key}: {value}")

    def _build_tree(
        self,
        tree: Tree,
        data: list[dict[str, Any]],
        keys_to_exclude: list[str],
        keys_list_to_string: list[str],
    ):
        keys_to_exclude = keys_to_exclude or []
        for section in data:
            if not isinstance(section, dict):
                continue

            for key, value in section.items():
                if key in keys_to_exclude or value is None or not value:
                    continue

                if key in keys_list_to_string and isinstance(value, list):
                    parts = []

                    for item in value:
                        if isinstance(item, dict):
                            parts.extend(f"{k}:{v}" for k, v in item.items())
                        else:
                            parts.append(str(item))
                    value = ",".join(parts)

                self._add_value_to_tree(tree, key, value)

    @staticmethod
    def _get_output_icon(icon_name: str = "") -> str:
        if not icon_name:
            return ""

        icon = icon_name.upper()
        if icon in OutputIcons.__members__:
            return OutputIcons[icon].value
        return ""

    # MAKE JSON
    def _make_json(self, data, output_trace_config: dict):
        options_show_json_is_active = self._get_trace_config(
            output_trace_config, "options.show_json.is_active", False
        )
        if not options_show_json_is_active:
            return None

        options_show_json_indent = self._get_trace_config(
            output_trace_config, "options.show_json.indent", 2
        )
        options_show_json_sort_keys = self._get_trace_config(
            output_trace_config, "options.show_json.sort_keys", False
        )

        if isinstance(data, (dict, list)):
            return JSON.from_data(
                data,
                indent=options_show_json_indent,
                sort_keys=options_show_json_sort_keys,
            )

        if isinstance(data, str):
            return JSON.from_data(data)

        return JSON.from_data({"data": str(data)})

    @staticmethod
    def _make_header(output_trace_config: dict):
        options = output_trace_config.get("options", {})
        show_header = options.get("show_header", {})

        if not show_header.get("is_active", True):
            return None

        header = output_trace_config.get("header", {})
        title = header.get("title", "")
        show_subtitle = show_header.get("show_subtitle", True)
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        subtitle = header.get("subtitle", now) or now

        return Panel(
            renderable=Align.center(title),
            padding=(1, 1),
            subtitle=subtitle if show_subtitle else None,
            subtitle_align="center",
        )

    # MAKE SEPARATOR
    def _make_separator(self, output_trace_config: dict) -> Rule | None:
        options_show_separator = self._get_trace_config(
            output_trace_config, "options.show_separator.is_active", default=False
        )
        if not options_show_separator:
            return None
        return Rule(characters="─")

    # MAKE SECTION CONFIG
    def _make_section_config(
        self, output_trace_config: dict, data_sections_config: list[dict]
    ):
        options_show_sections = self._get_trace_config(
            output_trace_config, "options.show_sections.is_active", default=True
        )
        options_show_sec_config = self._get_trace_config(
            output_trace_config, "options.show_sections.sec_config", default=True
        )

        if not (options_show_sections and options_show_sec_config):
            return None

        sec_config_icon = self._get_output_icon(
            self._get_trace_config(
                output_trace_config, "sections_config.header.icon", default="CONFIG"
            )
        )
        sec_config_title = self._get_trace_config(
            output_trace_config,
            "sections_config.header.title",
            default="[CONFIG] Summary of all configurations used for the contract.",
        )
        keys_list_to_string = self._get_trace_config(
            output_trace_config, "sections_config.keys_list_to_string", default=[]
        )
        keys_to_exclude = self._get_trace_config(
            output_trace_config, "sections_config.keys_to_exclude", default=[]
        )

        section_tree = Tree(
            f"{sec_config_icon} {sec_config_title}".strip(), guide_style="bold"
        )
        self._build_tree(
            tree=section_tree,
            data=data_sections_config,
            keys_to_exclude=keys_to_exclude,
            keys_list_to_string=keys_list_to_string,
        )
        return section_tree

    # MAKE SECTION INFO
    def _make_section_info(
        self, output_trace_config: dict, data_sections_info: list[dict]
    ):
        options_show_sections = self._get_trace_config(
            output_trace_config, "options.show_sections.is_active", default=True
        )
        options_show_sec_info = self._get_trace_config(
            output_trace_config, "options.show_sections.sec_info", default=True
        )

        if not (options_show_sections and options_show_sec_info):
            return None

        sec_info_icon = self._get_output_icon(
            self._get_trace_config(
                output_trace_config, "sections_info.header.icon", default="INFO"
            )
        )
        sec_info_title = self._get_trace_config(
            output_trace_config,
            "sections_info.header.title",
            default="[INFO] The Injector information",
        )
        keys_list_to_string = self._get_trace_config(
            output_trace_config, "sections_info.keys_list_to_string", default=[]
        )
        keys_to_exclude = self._get_trace_config(
            output_trace_config, "sections_info.keys_to_exclude", default=[]
        )

        section_tree = Tree(
            f"{sec_info_icon} {sec_info_title}".strip(), guide_style="bold"
        )
        self._build_tree(
            tree=section_tree,
            data=data_sections_info,
            keys_to_exclude=keys_to_exclude,
            keys_list_to_string=keys_list_to_string,
        )
        return section_tree

    @staticmethod
    def _count_at_path(result: dict, path: str) -> int:
        current = result
        for key in path.split("."):
            if not isinstance(current, dict):
                return 0
            current = current.get(key, None)
            if current is None:
                return 0
        if isinstance(current, list):
            return len(current)
        else:
            return 1

    def _prepare_call_details(
        self, output_trace_config: dict, data_sections_external_api: list[dict]
    ):
        results_success = []
        total_success_details_count = 0

        results_failed = []
        total_call_failed_count = 0
        for result in data_sections_external_api:

            if result.get("is_error"):
                request = result.get("request")
                response = result.get("response")

                raw_error = response.get("error")
                if isinstance(raw_error, str) and raw_error.startswith("{"):
                    error_message = json.loads(raw_error).get("error")
                else:
                    error_message = raw_error

                call_failed_details = {
                    "data_target": result.get("target"),
                    "request": request.get("url"),
                    "error": f"{error_message} ({response.get('status_code')} - {response.get('reason')})",
                }
                total_call_failed_count += 1
                results_failed.append(call_failed_details)
            else:
                call_success_details = {
                    "data_target": result.get("target"),
                    "request": result.get("url"),
                    "result": result.get("result"),
                }
                results_success.append(call_success_details)
                count_at_path = self._get_trace_config(
                    output_trace_config,
                    "sections_external_api.call_success.count_at_path",
                    default="",
                )
                if count_at_path:
                    total_success_details_count += self._count_at_path(
                        call_success_details.get("result"), count_at_path
                    )

        return (results_success, total_success_details_count), (
            results_failed,
            total_call_failed_count,
        )

    # MAKE SECTION EXTERNAL API
    def _make_section_external_api(
        self, output_trace_config: dict, data_sections_external_api: list[dict]
    ):
        options_show_sections = self._get_trace_config(
            output_trace_config, "options.show_sections.is_active", default=True
        )
        options_show_sec_external_api = self._get_trace_config(
            output_trace_config, "options.show_sections.sec_external_api", default=True
        )

        if not (options_show_sections and options_show_sec_external_api):
            return None, None

        sec_external_api_icon = self._get_output_icon(
            self._get_trace_config(
                output_trace_config, "sections_external_api.header.icon", default="API"
            )
        )
        sec_external_api_title = self._get_trace_config(
            output_trace_config,
            "sections_external_api.header.title",
            default="[INJECTOR] Call API completed",
        )
        section_tree = Tree(
            f"{sec_external_api_icon} {sec_external_api_title}".strip(),
            guide_style="bold",
        )

        # Add node call success
        call_success_icon = self._get_output_icon(
            self._get_trace_config(
                output_trace_config,
                "sections_external_api.call_success.icon",
                default="SUCCESS",
            )
        )
        call_success_title = self._get_trace_config(
            output_trace_config,
            "sections_external_api.call_success.title",
            default="Call Success",
        )
        success_node = section_tree.add(
            f"{call_success_icon} {call_success_title}".strip()
        )

        # Add node call failed
        call_failed_icon = self._get_output_icon(
            self._get_trace_config(
                output_trace_config,
                "sections_external_api.call_failed.icon",
                default="FAILED",
            )
        )
        call_failed_title = self._get_trace_config(
            output_trace_config,
            "sections_external_api.call_failed.title",
            default="Call Failed",
        )
        failed_node = section_tree.add(
            f"{call_failed_icon} {call_failed_title}".strip()
        )

        (results_success_details, total_success_details_count), (
            results_failed_details,
            total_call_failed_count,
        ) = self._prepare_call_details(output_trace_config, data_sections_external_api)

        # Add Total results (success and failed)
        success_node.add(f"Total results: {total_success_details_count}")
        failed_node.add(f"Total results: {total_call_failed_count}")

        # Add Details for call Success
        success_details_node = success_node.add("Details:")
        for result_detail in results_success_details:
            target = result_detail.get("data_target")
            result_details_count = 0
            request = result_detail.get("request")

            count_at_path = self._get_trace_config(
                output_trace_config,
                "sections_external_api.call_success.count_at_path",
                default="",
            )
            if count_at_path:
                result_details_count += self._count_at_path(
                    result_detail.get("result"), count_at_path
                )
            target_node = success_details_node.add(
                f"• {target} → {result_details_count} results"
            )
            target_node.add(f"Request: {request}")

        # Add Details for call Failed
        failed_details_node = failed_node.add("Details:")
        for result_detail in results_failed_details:
            target = result_detail.get("data_target")
            error = result_detail.get("error")
            request = result_detail.get("request")

            target_node = failed_details_node.add(f"• {target}")
            target_node.add(f"Error: {error}")
            target_node.add(f"Request: {request}")

        return section_tree, results_success_details

    def _extract_level(
        self, items: list[Any], parts_remaining: list[str], use_key: bool = False
    ) -> list[Any]:
        if not parts_remaining:
            return items

        part = parts_remaining[0]
        next_parts = parts_remaining[1:]
        result = []

        for item in items:
            if isinstance(item, dict):
                if part == "*":
                    # If there is a "next_parts", we retrieve the values
                    if next_parts:
                        sub_result = list(item.values())
                    else:
                        # if we have a “*” and use_key is true, then we retrieve the keys rather than the values
                        sub_result = [k if use_key else v for k, v in item.items()]

                    if next_parts:
                        sub_result = self._extract_level(
                            sub_result, next_parts, use_key
                        )

                    result.append(sub_result)
                else:
                    value = item.get(part, [])
                    result.append(self._extract_level(value, next_parts, use_key))
            elif isinstance(item, list):
                result.append(self._extract_level(item, parts_remaining, use_key))
            else:
                if part == "*" and next_parts:
                    result.extend(
                        self._extract_level([items[item]], next_parts, use_key)
                    )
                else:
                    if part in items and not next_parts and isinstance(item, str):
                        if item == part:
                            result.append(items[part])
                        else:
                            continue
                    else:
                        result.append(item)
        return result

    def _extractor(
        self, data: list[dict], path: str, use_key: bool = False
    ) -> list[list[Any]]:
        if not path:
            return []

        parts = path.split(".")
        data_list = data if isinstance(data, list) else [data]
        final_result = self._extract_level(data_list, parts, use_key)
        return final_result

    @staticmethod
    def _organizer_row(
        tables_config_columns,
        show_index_is_active,
        index_start,
        column_values,
        column_extras,
    ):

        single_columns = [
            values
            for config, values in zip(tables_config_columns, column_values)
            if config.get("mode") == "single"
        ]
        row_count = len(single_columns[0])

        final_rows = []
        index = index_start

        for row_idx in range(row_count):
            row_cells = []

            if show_index_is_active:
                row_cells.append(str(index))

            for table_config_index, table_config in enumerate(tables_config_columns):
                mode = table_config.get("mode", "inline")

                values = (
                    column_values[table_config_index]
                    if table_config_index < len(column_values)
                    else []
                )
                extras = (
                    column_extras[table_config_index]
                    if column_extras and table_config_index < len(column_extras)
                    else None
                )

                cell = "-"
                if mode == "single":
                    if isinstance(values, list) and len(values) > 0:
                        for value in values:
                            if isinstance(value, list):
                                filtered = [
                                    str(v) for v in value if v not in (None, "")
                                ]
                                cell = ", ".join(filtered) if filtered else "-"
                            else:
                                val = values[row_idx] if row_idx < len(values) else None
                                cell = str(val) if val not in (None, "") else "-"

                    elif values not in (None, ""):
                        cell = str(values)
                    else:
                        cell = "-"

                elif mode == "inline":
                    if row_idx == 0:
                        all_vals = []
                        for val in values:
                            if isinstance(val, list):
                                all_vals.extend(
                                    str(v) for v in val if v not in (None, "")
                                )
                            elif val not in (None, ""):
                                all_vals.append(str(val))
                        cell = ", ".join(all_vals) if all_vals else "-"

                    else:
                        cell = ""

                elif mode == "align_to_single":
                    if row_idx < len(values):
                        val = values[row_idx]
                        extra = (
                            extras[row_idx]
                            if extras and row_idx < len(extras)
                            else None
                        )
                        if isinstance(val, list):
                            if val:
                                if extra:
                                    cell = ", ".join(
                                        f"{v} ({e if e is not None else '-'})"
                                        for v, e in zip(val, extra or ["-"] * len(val))
                                    )
                                else:
                                    cell = ", ".join(str(v) for v in val)
                            else:
                                cell = "-"
                        elif val not in (None, ""):
                            if extra:
                                cell = f"{val} ({extra})"
                            else:
                                cell = str(val)
                        else:
                            cell = "-"
                    else:
                        cell = "-"

                elif mode == "repeat":
                    if values:
                        val = values
                        extra = extras if extras else None

                        if isinstance(val, list):
                            if val:
                                val_join = ", ".join(str(v) for v in val)
                                cell = val_join
                                if extra and isinstance(extra, list):
                                    extra_join = ", ".join(str(v) for v in extra)
                                    cell = f"{val_join} ({extra_join})"
                            else:
                                cell = "-"
                        elif val not in (None, ""):
                            if extra:
                                cell = f"{val} ({extra})"
                            else:
                                cell = str(val)
                        else:
                            cell = "-"
                    else:
                        cell = "-"

                row_cells.append(cell)
            final_rows.append(row_cells)
            index += 1

        return final_rows

    @staticmethod
    def _rows_with_limit_cells(rows: list[list[str]], max_display_by_cell: int | None):
        rows_with_limit = []

        for row in rows:
            main_row = []
            hidden_row = []
            has_hidden = False

            for cell in row:
                if (
                    isinstance(cell, str)
                    and "," in cell
                    and max_display_by_cell is not None
                ):
                    items = [c.strip() for c in cell.split(",") if c.strip()]
                    if len(items) > max_display_by_cell:
                        shown = items[:max_display_by_cell]
                        hidden = len(items) - max_display_by_cell

                        main_row.append(", ".join(shown))
                        hidden_row.append(f"...(+{hidden} hidden)")
                        has_hidden = True
                    else:
                        main_row.append(", ".join(items))
                        hidden_row.append("")
                else:
                    main_row.append(cell)
                    hidden_row.append("")

            rows_with_limit.append(main_row)
            if has_hidden:
                rows_with_limit.append(hidden_row)
        return rows_with_limit

    # MAKE TABLES
    def _make_tables(
        self,
        output_trace_config: dict,
        data_tables: list[dict],
        auto_create_assets: bool | None,
    ):

        options_show_tables_is_active = self._get_trace_config(
            output_trace_config, "options.show_tables.is_active", default=True
        )
        if not options_show_tables_is_active:
            return []

        show_index_is_active = self._get_trace_config(
            output_trace_config,
            "options.show_tables.show_index.is_active",
            default=False,
        )
        index_start = self._get_trace_config(
            output_trace_config, "options.show_tables.show_index.index_start", default=0
        )
        show_lines = self._get_trace_config(
            output_trace_config, "options.show_tables.show_lines", default=True
        )
        max_display_by_cell = self._get_trace_config(
            output_trace_config, "options.show_tables.max_display_by_cell", default=10
        )

        tables = self._get_trace_config(output_trace_config, "tables", default=[])

        tables_rendering = []
        for table_config in tables:
            header_icon = self._get_output_icon(
                self._get_trace_config(table_config, "header.icon", default="SEARCH")
            )
            header_title = self._get_trace_config(
                table_config, "header.title", default=""
            )
            search_entity = self._get_trace_config(
                table_config, "config.search_entity", default=None
            )

            table_rendering = []
            for data_table in data_tables:
                result = data_table.get("result")
                if header_title:
                    table_title = header_title.format(**result)
                else:
                    table_title = (
                        f"Asset(s) "
                        f"{'Created' if auto_create_assets else 'Not Created'} "
                        f"for {result.get(search_entity) or data_table.get("data_target")}"
                    )

                table = Table(
                    title=f"{header_icon} {table_title}".strip(),
                    title_justify="left",
                    show_lines=show_lines,
                    box=box.HEAVY_HEAD if show_lines else None,
                    expand=True,
                )

                tables_config_columns = self._get_trace_config(
                    table_config, "config.columns"
                )

                if show_index_is_active:
                    table.add_column("#")

                column_values = []
                column_extras = []
                for config in tables_config_columns:
                    title = config.get("title", "-")
                    table.add_column(title, overflow="fold")

                    path = config.get("path")
                    use_key = config.get("use_key", False)
                    values = self._extractor(result, path, use_key)
                    column_values.append(values[0])

                    extra_path = config.get("extra")
                    if extra_path:
                        extras = self._extractor(result, extra_path)
                        column_extras.append(extras[0])
                    else:
                        column_extras.append(None)

                final_rows = self._organizer_row(
                    tables_config_columns,
                    show_index_is_active,
                    index_start,
                    column_values,
                    column_extras,
                )

                rows_with_limit_cell = self._rows_with_limit_cells(
                    final_rows, max_display_by_cell
                )

                for row_with_limit in rows_with_limit_cell:
                    table.add_row(*row_with_limit)

                table_rendering.append(table)

            tables_rendering.extend(table_rendering)
        return tables_rendering

    def generate_output_message(
        self,
        output_trace_config: dict,
        data_sections_config: list[dict],
        data_sections_info: list[dict],
        data_sections_external_api: list[dict],
        auto_create_assets: bool | None,
    ):
        # Todo: Make split mode

        renderables = []

        # Output Header
        output_header = self._make_header(output_trace_config=output_trace_config)
        if output_header:
            renderables.append(Text(""))
            separator = self._make_separator(output_trace_config=output_trace_config)
            if separator:
                renderables.append(separator)
            renderables.append(output_header)

        # Output Sections Config
        output_sections_config = self._make_section_config(
            output_trace_config=output_trace_config,
            data_sections_config=data_sections_config,
        )
        if output_sections_config:
            renderables.append(Text(""))
            separator = self._make_separator(output_trace_config=output_trace_config)
            if separator:
                renderables.append(separator)
            renderables.append(output_sections_config)

        # Output Sections Info
        output_sections_info = self._make_section_info(
            output_trace_config=output_trace_config,
            data_sections_info=data_sections_info,
        )
        if output_sections_info:
            renderables.append(Text(""))
            separator = self._make_separator(output_trace_config=output_trace_config)
            if separator:
                renderables.append(separator)
            renderables.append(output_sections_info)

        # Output Sections Client API
        output_sections_client_api, results_success_details = (
            self._make_section_external_api(
                output_trace_config=output_trace_config,
                data_sections_external_api=data_sections_external_api,
            )
        )
        if output_sections_client_api:
            renderables.append(Text(""))
            separator = self._make_separator(output_trace_config=output_trace_config)
            if separator:
                renderables.append(separator)
            renderables.append(output_sections_client_api)

        if results_success_details:
            # Output Tables
            output_tables = self._make_tables(
                output_trace_config=output_trace_config,
                auto_create_assets=auto_create_assets,
                data_tables=results_success_details,
            )
            for output_table in output_tables:
                if output_table:
                    renderables.append(Text(""))
                    separator = self._make_separator(
                        output_trace_config=output_trace_config
                    )
                    if separator:
                        renderables.append(separator)
                    renderables.append(output_table)

        # Output JSON
        output_json = self._make_json(
            data=data_sections_external_api,
            output_trace_config=output_trace_config,
        )

        if output_json:
            renderables.append(Text(""))
            separator = self._make_separator(output_trace_config=output_trace_config)
            if separator:
                renderables.append(separator)
            renderables.append(output_json)

        group = Group(*renderables)
        console = Console(
            color_system=None,
            force_terminal=False,
            width=150,
        )
        with console.capture() as capture:
            console.print(group)
        output_str = capture.get()
        return output_str
