"""cabin's own TLS material, and the live `uvicorn.Config` it is loaded into
(spec 0022).

**This is a Phase-0 skeleton, not an implementation.** It exists so that
`cabin.app` and `cabin.server` have a stable, typed seam to build against --
`app.state.tls` needs a real type (spec 0022's Interface Contract, R1), and
`server.run` needs something to hand its `uvicorn.Config` to (FR-1/FR-6).
Everything below is a placeholder: `TlsManager.mode` never leaves `None`,
`ensure_current` never touches the filesystem or the database, and there is
no certificate issuance, no renewal and no swap here. That behaviour (FR-3
through FR-9) belongs to a later phase; building it here would be scope
creep in the module that is supposed to just be the seam.

`cert_path`/`sealed_key_path` are the one exception: they are pure path
arithmetic with no rule in them, so `tests/live_server.py`'s
`plant_tls_material` (spec 0022 work split §2.4a) can plant material at
exactly the paths the real implementation will use, without duplicating the
two file names in two places.
"""

from enum import StrEnum
from pathlib import Path

import uvicorn
from sqlalchemy.orm import Session

from cabin.secrets import SecretStore


class TlsMode(StrEnum):
    """Which kind of certificate `TlsManager` currently has loaded."""

    self_signed = "self_signed"
    ca_issued = "ca_issued"


def cert_path(data_dir: Path) -> Path:
    """FR-3: the certificate, in the clear -- a public document."""
    return data_dir / "tls" / "cabin.crt"


def sealed_key_path(data_dir: Path) -> Path:
    """FR-3: the private key, sealed. There is no ``key_path``: no
    plaintext key file exists to have one."""
    return data_dir / "tls" / "cabin.key.sealed"


class TlsManager:
    """Owns cabin's own TLS material and the `uvicorn.Config` it is loaded
    into.

    Phase-0 placeholder (see module docstring): `mode` stays `None`,
    `attach` only records the live `uvicorn.Config` so a later phase can
    mutate its `.ssl`, and `ensure_current` does nothing and reports no
    change. The full surface is spec 0022's Interface Contract.
    """

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        #: What is currently loaded; `None` before the first
        #: `ensure_current`. Read by FR-14's templates via `app.state.tls`.
        self.mode: TlsMode | None = None
        self._uvicorn_config: uvicorn.Config | None = None

    def attach(self, uvicorn_config: uvicorn.Config) -> None:
        """Hand over the `Config` whose `.ssl` a later phase will mutate."""
        self._uvicorn_config = uvicorn_config

    def ensure_current(self, db: Session, secrets: SecretStore) -> bool:
        """FR-6, stubbed: does nothing, changes nothing, returns `False`."""
        return False
