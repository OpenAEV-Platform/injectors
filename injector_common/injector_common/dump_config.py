import argparse

from pyoaev.configuration import Configuration


def intercept_dump_argument(config: Configuration):
    parser = argparse.ArgumentParser(description="parse daemon options")
    parser.add_argument("--dump-config-schema", action="store_true")
    args = parser.parse_args()
    if args.dump_config_schema:
        print(config.schema())
        exit(0)
