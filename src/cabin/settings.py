"""Settings an operator configures in the UI and cabin stores in the
database -- as opposed to :mod:`cabin.config`, which is the handful of
process-level knobs that come from flags and environment variables.

The ``settings`` table (migration 0001) is a plain key/value store; every
setting is text, and validation lives next to the key that needs it.
"""

from urllib.parse import urlparse, urlunparse

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.store import Base

#: Public origin of this cabin instance, e.g. ``https://ca.example.org``.
#: Empty/absent means "not configured" -- see spec 0007 FR-6.
BASE_URL = "base_url"

#: Whether cabin is behind a reverse proxy it may believe about the client's
#: address (spec 0009 FR-5). Default false: ``X-Forwarded-For`` is a header
#: any client can set, so trusting it without a proxy in front lets anyone
#: choose which IP the audit log blames.
TRUST_PROXY = "trust_proxy"

#: Whether cabin's ACME server answers at all (spec 0010 FR-5). Default
#: false, and "off" means 404 rather than 403: an internal CA has no reason
#: to tell the internet which protocols it declines to speak.
ACME_ENABLED = "acme_enabled"

#: What a checkbox-style setting stores when it is on / off.
TRUE = "true"
FALSE = "false"
#: What counts as on when reading one back -- generous on input, exact on
#: output, so a value typed straight into the database still works.
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


class SettingError(Exception):
    """A submitted setting failed validation; the message names the reason
    and is safe to show in the UI."""


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    value: Mapped[str] = mapped_column(sa.Text, nullable=False)


def get_setting(db: Session, key: str) -> str | None:
    row = db.get(Setting, key)
    return row.value if row is not None else None


def set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
    db.commit()


def get_flag(db: Session, key: str) -> bool:
    """A checkbox-style setting, absent meaning off."""
    return (get_setting(db, key) or "").strip().lower() in _TRUE_VALUES


def validate_base_url(raw: str) -> str:
    """FR-6: an absolute http(s) URL without a trailing slash, or the empty
    string to clear it. Returns the canonical form to store.

    Strict on purpose: this value is baked into the CRL distribution point of
    every certificate issued from here on, and a certificate lives far longer
    than the typo that produced it. A path is allowed (cabin behind a reverse
    proxy at ``/cabin``); a query or fragment is dropped, because a CDP is a
    location, not a request.

    Rejected outright:

    * userinfo (``user:pass@host``) -- it would end up in every certificate
      and in every relying party's fetch of the CRL;
    * a backslash anywhere in the host -- browsers read it as a separator and
      :func:`urlparse` does not, so ``https://host\\@evil.example`` would name
      one host here and another one where it matters.
    """
    value = raw.strip()
    if not value:
        return ""
    if any(char.isspace() for char in value):
        raise SettingError("the base URL must not contain whitespace")
    parsed = urlparse(value)
    if parsed.scheme.lower() not in ("http", "https"):
        raise SettingError("the base URL must be absolute and start with http:// or https://")
    if not parsed.netloc:
        raise SettingError("the base URL must include a host")
    if "@" in parsed.netloc:
        raise SettingError("the base URL must not contain a username or password")
    if "\\" in parsed.netloc:
        raise SettingError("the base URL's host must not contain a backslash")
    # Scheme and host are case-insensitive, the path is not; the query and
    # fragment are dropped rather than carried into a certificate.
    canonical = urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, "", "", ""))
    if canonical.endswith("/"):
        raise SettingError("the base URL must not end with a slash")
    return canonical
