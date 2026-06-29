"""Pure command-line argument renderer (no execution, no I/O)."""

from injectors_sdk._core.engine.contracts.specs import (
    ArgumentSpec,
    CommandSpec,
    OptionKind,
    OptionSpec,
)
from injectors_sdk._core.errors import CliContractError


class DefaultCommandRenderer:
    """Render validated argv tokens for one command invocation.

    Produces an argv list in the order:
    [binary] + static_argv + rendered_options + positional_args + raw_args
    """

    def render(
        self,
        binary: str,
        command: CommandSpec,
        *,
        options: dict[str, object] | None = None,
        args: dict[str, object] | None = None,
        raw_args: list[str] | None = None,
    ) -> list[str]:
        """Render a complete argv list for subprocess execution.

        Args:
            binary: The executable name or path.
            command: The command specification to render.
            options: Named option values to render.
            args: Named positional argument values.
            raw_args: Undeclared arguments passed through verbatim.

        Returns:
            A list of string tokens ready for subprocess execution.

        Raises:
            CliContractError: On unknown options/args, missing required fields,
                or type violations.
        """
        option_values = self._validate_mapping("options", options)
        arg_values = self._validate_mapping("args", args)
        raw_tokens = self._validate_raw_args(raw_args)

        tokens: list[str] = [binary, *command.argv]
        tokens.extend(self._render_options(command, option_values))
        tokens.extend(self._render_arguments(command.arguments, arg_values))

        if raw_tokens:
            if not command.allow_raw_args:
                raise CliContractError(
                    f"Command '{command.name}' does not accept undeclared "
                    f"arguments. Set allow_raw_args=True in the CommandSpec "
                    f"to enable raw argument passthrough."
                )
            tokens.extend(raw_tokens)

        return tokens

    def _render_options(self, command: CommandSpec, options: dict[str, object]) -> list[str]:
        option_specs = command.options or {}

        for option_name in options:
            if option_name not in option_specs:
                raise CliContractError(f"Unknown option: {option_name}")

        rendered: list[str] = []
        for option_name, spec in option_specs.items():
            value = options.get(option_name)
            if spec.required and value is None:
                raise CliContractError(f"Missing required option: {option_name}")
            if value is None:
                continue
            rendered.extend(self._render_one_option(spec, value))

        return rendered

    def _render_one_option(self, spec: OptionSpec, value: object) -> list[str]:
        if spec.kind == OptionKind.BOOL:
            if not isinstance(value, bool):
                raise CliContractError(f"Option {spec.name} must be a boolean")
            return [spec.flag] if value else []

        if spec.kind == OptionKind.LIST:
            if not isinstance(value, list):
                raise CliContractError(f"Option {spec.name} must be a list")
            if any(not isinstance(item, str) for item in value):
                raise CliContractError(f"Option {spec.name} list items must be strings")
            return self._render_list_option(spec, value)

        if isinstance(value, (list, dict, tuple, set)):
            raise CliContractError(f"Option {spec.name} has invalid type")
        self._validate_choices(spec, str(value))
        return self._render_value_option(spec, str(value))

    def _render_list_option(self, spec: OptionSpec, values: list[str]) -> list[str]:
        rendered: list[str] = []
        for item in values:
            self._validate_choices(spec, item)
            if spec.equals:
                rendered.append(f"{spec.flag}={item}")
            else:
                rendered.extend([spec.flag, item])
        return rendered

    def _render_value_option(self, spec: OptionSpec, value: str) -> list[str]:
        if spec.equals:
            return [f"{spec.flag}={value}"]
        return [spec.flag, value]

    def _validate_choices(self, spec: OptionSpec, value: str) -> None:
        if spec.choices and value not in spec.choices:
            raise CliContractError(
                f"Option {spec.name} value {value!r} must be one of {', '.join(spec.choices)}"
            )

    def _render_arguments(
        self,
        argument_specs: list[ArgumentSpec],
        args: dict[str, object],
    ) -> list[str]:
        declared_names = {spec.name for spec in argument_specs}
        unknown_keys = set(args.keys()) - declared_names
        if unknown_keys:
            unknown_names = ", ".join(sorted(unknown_keys))
            raise CliContractError(f"Unknown argument(s): {unknown_names}")

        rendered: list[str] = []
        for spec in argument_specs:
            value = args.get(spec.name)
            if value is None:
                if spec.required:
                    raise CliContractError(f"Missing argument: {spec.name}")
                continue
            if isinstance(value, (list, dict, tuple, set)):
                raise CliContractError(f"Argument {spec.name} has invalid type")
            rendered.append(str(value))
        return rendered

    def _validate_mapping(
        self, field_name: str, value: dict[str, object] | None
    ) -> dict[str, object]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise CliContractError(f"{field_name} must be a dict")
        return value

    def _validate_raw_args(self, raw_args: list[str] | None) -> list[str]:
        if raw_args is None:
            return []
        if not isinstance(raw_args, list):
            raise CliContractError("raw_args must be a list")
        if any(not isinstance(token, str) for token in raw_args):
            raise CliContractError("raw_args must contain strings")
        return raw_args
