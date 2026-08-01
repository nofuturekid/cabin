"""Console entry point (`cabin`)."""

import sys

import uvicorn

from cabin.app import create_app
from cabin.config import Config, ConfigError


def main() -> None:
    try:
        config = Config.load(argv=sys.argv[1:])
    except ConfigError as exc:
        raise SystemExit(f"cabin: {exc}") from exc
    uvicorn.run(create_app(config), host="0.0.0.0", port=config.port)
