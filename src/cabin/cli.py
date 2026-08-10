"""Console entry point (`cabin`)."""

import sys

from cabin import server
from cabin.config import Config, ConfigError, ensure_data_dir_writable


def main() -> None:
    try:
        config = Config.load(argv=sys.argv[1:])
        # Before starting the server, so an unusable DATA_DIR ends as one
        # sentence and a non-zero exit rather than as a traceback out of the
        # first query.
        ensure_data_dir_writable(config.data_dir)
    except ConfigError as exc:
        raise SystemExit(f"cabin: {exc}") from exc
    server.run(config)
