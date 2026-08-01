"""Server-rendered UI: Jinja2 + htmx, vendored assets, no CDN, no SPA."""

from pathlib import Path

STATIC_DIR = Path(__file__).resolve().parent / "static"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
