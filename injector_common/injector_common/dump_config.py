import argparse
import sys

from pyoaev.configuration import Configuration


def intercept_dump_argument(config: Configuration):
    parser = argparse.ArgumentParser(description="parse daemon options")
    parser.add_argument("--dump-config-schema", action="store_true")
    # Only the flag this parser owns reaches it, so dev and tool flags can share the
    # command line. parse_args stays the parsing call for code that patches it.
    own = [arg for arg in sys.argv[1:] if arg == "--dump-config-schema"]
    args = parser.parse_args(own)
    if args.dump_config_schema:
        print(config.schema())
        exit(0)
