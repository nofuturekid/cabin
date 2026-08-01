"""Server-rendered UI: Jinja2 + htmx, vendored assets, no CDN, no SPA."""

from pathlib import Path

from fastapi.templating import Jinja2Templates
from jinja2 import StrictUndefined

from cabin import __version__

STATIC_DIR = Path(__file__).resolve().parent / "static"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# One Jinja environment shared by every UI router (ui.py, ca_ui.py, ...):
# building a separate Jinja2Templates per module would silently duplicate
# (and risk diverging) the globals/undefined setup below.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["version"] = __version__
# StrictUndefined turns a missing template variable into a hard error at
# render time instead of a silently-empty string -- e.g. this is exactly
# what would have caught the dashboard's missing csrf_token earlier.
templates.env.undefined = StrictUndefined
