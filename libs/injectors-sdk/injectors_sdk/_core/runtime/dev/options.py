"""Injector dev options: the common dev options plus the injector's own."""

from injectors_sdk.seam.runtime import InjectorDevOptions
from xtm_oaev_sdk import dev_argument_parser, dev_options

__all__ = ["DEFAULT_TIMEOUT", "injector_help", "injector_options"]

DEFAULT_TIMEOUT = 600.0

_DESCRIPTION = (
    "Injector dev mode: run the injector without the OpenAEV platform. It reads the"
    " inject message as the platform publishes it, and writes every call the platform"
    ' would have received as one JSON list of {"method", "path", "body"}.'
)
_EPILOG = (
    "Exit codes: 0 completed, 1 failed or never completed, 2 refused before running."
    " Guide: xtm-oaev-sdk docs/how_to_dev_mode.md."
)


def _parser():
    parser = dev_argument_parser(_DESCRIPTION, _EPILOG)
    injector = parser.add_argument_group("injector options")
    injector.add_argument(
        "--inject",
        metavar="PATH",
        help="the inject message to run, as the platform publishes it; only the"
        " contract id, the content and the targets are needed (- for stdin)",
    )
    injector.add_argument(
        "--timeout",
        metavar="SECONDS",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="how long to wait for the inject to complete (default: %(default)g); an"
        " inject that does not complete in time exits with code 1",
    )
    injector.add_argument(
        "--emit",
        action="append",
        default=[],
        metavar="expectations",
        help="also write on stdout the pending expectations collectors would then"
        " get (the calls go to stderr unless --out is given)",
    )
    injector.add_argument(
        "--dump-contracts",
        action="store_true",
        help="write the registration, contracts included, and exit",
    )
    injector.add_argument(
        "--list-contracts",
        action="store_true",
        help="list the contracts it serves, and exit",
    )
    injector.add_argument(
        "--new-inject",
        metavar="CONTRACT",
        help="write an inject message to edit for CONTRACT (an id, or a piece of a"
        " label), with a guide to its fields on stderr, and exit",
    )
    return parser


def injector_options(argv: list[str] | None = None) -> InjectorDevOptions:
    """The injector's dev options, read from ``argv`` (the process arguments when
    ``None``); collector options and the injector's own flags are left alone."""
    args, _ = _parser().parse_known_args(argv)
    common = dev_options(argv)
    return InjectorDevOptions(
        enabled=common.enabled,
        out=common.out,
        record=common.record,
        replay=common.replay,
        help=common.help,
        inject=args.inject,
        timeout=args.timeout,
        emit=tuple(args.emit),
        dump_contracts=args.dump_contracts,
        list_contracts=args.list_contracts,
        new_inject=args.new_inject,
    )


def injector_help() -> str:
    """The help of the injector's dev options."""
    return _parser().format_help()
