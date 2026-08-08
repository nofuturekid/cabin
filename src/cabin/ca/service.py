"""CA hierarchies: DB storage of certificates and sealed private keys,
orchestrated on top of the pure crypto in :mod:`cabin.ca.x509` and the
secrets layer's AES-GCM sealing (spec 0004 FR-3/FR-4; spec 0017 FR-2..FR-6
for multiple, independently rotatable hierarchies).
"""

from dataclasses import dataclass
from datetime import UTC, datetime

import sqlalchemy as sa
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from sqlalchemy import select
from sqlalchemy.orm import Mapped, Session, mapped_column

from cabin.ca import leaf
from cabin.ca import x509 as ca_x509
from cabin.secrets import SecretStore
from cabin.store import Base


class CANotConfiguredError(Exception):
    """No usable signing key: either no active issuer exists at all
    (:func:`resolve_issuer`), or a specific row's ``key_sealed`` is NULL --
    which is what every imported hierarchy's root looks like, since its
    private key was never handed to cabin (:func:`signing_credentials`,
    :func:`create_intermediate_under`, :func:`renew_in_place`)."""


class UnknownIssuerError(Exception):
    """No ``ca_certificates`` row has the given id (spec 0017 FR-2)."""


class IssuerRetiredError(Exception):
    """The named issuer exists and is an intermediate, but its status is
    retired -- it may still sign a CRL, just not a new certificate
    (spec 0017 FR-6)."""


class IssuerRequiredError(Exception):
    """``issuer_id`` was omitted and more than one active issuer exists, so
    there is no single default to fall back to (spec 0017 FR-6)."""


class RetireError(Exception):
    """Retiring this row would leave the instance with no active issuer and
    therefore no way to issue anything (spec 0017 FR-4) -- the same
    invariant as "the last superadmin cannot be deleted" in
    ``users.py:75-79``."""


class CrossSignError(Exception):
    """A cross certificate cannot be produced for these two roots: the
    signing root's path_length cannot carry the subtree (spec 0021 FR-3),
    or an active cross certificate for this pair already exists (FR-4)."""


class CACertificate(Base):
    __tablename__ = "ca_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    #: Always the subject CN of this row's own cert_pem (spec 0017's naming
    #: rule) -- never a separate cabin-local label, so /ca can never show a
    #: name that disagrees with the certificate a relying party is handed.
    #: Not unique: a rotation deliberately produces a second row with the
    #: same name.
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    #: Self-referential; NULL for a self-signed root (spec 0017 FR-1). For a
    #: cross row this names the root that SIGNED it, never a cross row
    #: itself -- chain_for's parent_id walk never crosses two cross rows.
    parent_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), nullable=True
    )
    #: The self-signed row this row duplicates; set only for kind="cross"
    #: (spec 0021 FR-1). NULL for every other row -- nullable even though a
    #: cross row must always have one, because that pairing isn't
    #: expressible as a single-row CHECK constraint.
    cross_of_id: Mapped[int | None] = mapped_column(
        sa.ForeignKey("ca_certificates.id"), nullable=True
    )
    #: "active" or "retired" (spec 0017 FR-1/FR-4).
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="active", server_default="active"
    )
    cert_pem: Mapped[str] = mapped_column(sa.Text, nullable=False)
    key_sealed: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC).replace(tzinfo=None),
    )


@dataclass(frozen=True)
class CAHierarchy:
    root: CACertificate
    intermediate: CACertificate


@dataclass(frozen=True)
class Chain:
    """One complete path from an issuer to its trust anchor (spec 0021
    FR-6): ``rows`` is nearest-issuer-first with the anchor last, the order
    every existing chain consumer already assumes. ``via_cross_id`` names
    the cross row this path goes through, or ``None`` for the self-signed
    path -- which is how :attr:`ChainSet.self_signed` finds it without
    re-deriving anything from ``rows``."""

    rows: tuple[CACertificate, ...]
    via_cross_id: int | None

    @property
    def anchor_id(self) -> int:
        """The id a client names this path by (FR-8, FR-9): the topmost
        row's id, deliberately not an ordinal -- an ordinal shifts when a
        cross certificate expires, and a client that remembered "alternate
        1" would quietly start fetching a different chain."""
        return self.rows[-1].id


@dataclass(frozen=True)
class ChainSet:
    """The default path cabin serves for a CA and the alternates offered
    alongside it (spec 0021 FR-6). The base (self-signed) path is always
    present, whatever its own dates -- if the self-signed root has expired
    there is nothing better to serve, and returning no chain at all would
    turn a bad state into a 500 on every download."""

    default: Chain
    alternates: tuple[Chain, ...]

    @property
    def self_signed(self) -> Chain:
        """The path whose ``via_cross_id`` is ``None``. Always present
        (see class docstring), so this property is total and
        ``web/ui.py``'s dashboard link can rely on it without a fallback."""
        for chain in (self.default, *self.alternates):
            if chain.via_cross_id is None:
                return chain
        raise AssertionError("ChainSet built with no self-signed path")

    def by_anchor(self, anchor_id: int) -> Chain | None:
        """The path whose topmost row has this id, or ``None`` when no path
        in this set does (FR-8's and FR-9's 404s are built on this -- it
        never falls back to the default)."""
        for chain in (self.default, *self.alternates):
            if chain.anchor_id == anchor_id:
                return chain
        return None


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _key_pem(key: CertificateIssuerPrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _subject_name(cert: x509.Certificate) -> str:
    """The value :func:`import_hierarchy` stores in ``name``: the imported
    certificate's own subject CN, read off the parsed certificate rather
    than accepted as a caller-supplied label (the naming rule -- a second,
    cabin-local name would let ``/ca`` disagree with what the certificate
    itself says). Falls back to the full subject for the rare certificate
    with no CN attribute at all, so the column is never empty.
    """
    common_names = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not common_names:
        return cert.subject.rfc4514_string()
    value = common_names[0].value
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


def _unseal_signing_key(secrets: SecretStore, key_sealed: str) -> CertificateIssuerPrivateKeyTypes:
    key_pem = secrets.unseal(key_sealed)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(key, ca_x509.SIGNING_KEY_TYPES):
        raise CANotConfiguredError("stored key is not a supported signing key type")
    return key


def get_ca(db: Session, issuer_id: int) -> CACertificate:
    """The row with this id, whatever its status (spec 0017 FR-2).

    Unlike the pre-0017 no-argument version, a retired row is a perfectly
    normal answer here: it still needs to be looked up to serve its chain
    and its CRL (FR-4). Raises UnknownIssuerError for an id nothing has.
    """
    row = db.get(CACertificate, issuer_id)
    if row is None:
        raise UnknownIssuerError(f"no CA certificate with id {issuer_id}")
    return row


def list_cas(
    db: Session, *, status: str | None = None, kind: str | None = None
) -> list[CACertificate]:
    """Every hierarchy row, ordered by id, optionally narrowed by status
    and/or kind (spec 0017 FR-2) -- what the ``/ca`` inventory and
    ``GET /api/v1/ca`` both list from."""
    conditions: list[sa.ColumnElement[bool]] = []
    if status is not None:
        conditions.append(CACertificate.status == status)
    if kind is not None:
        conditions.append(CACertificate.kind == kind)
    return list(db.scalars(select(CACertificate).where(*conditions).order_by(CACertificate.id)))


def _parent_walk(db: Session, ca_id: int) -> list[CACertificate]:
    """``ca_id``'s row and its ancestors, nearest first, root last
    (spec 0017 FR-2/FR-8) -- walking ``parent_id`` rather than assuming the
    one hierarchy this replaces did. No cross row can ever appear here:
    nothing's ``parent_id`` names a cross row (spec 0021 FR-1's second
    invariant), which is what keeps this walk from ever needing to know
    about cross rows at all. Raises UnknownIssuerError for an unknown id.
    """
    chain = [get_ca(db, ca_id)]
    while chain[-1].parent_id is not None:
        chain.append(get_ca(db, chain[-1].parent_id))
    return chain


def chain_for(db: Session, ca_id: int) -> list[CACertificate]:
    """``ca_id``'s row and its ancestors, nearest first, root last
    (spec 0017 FR-2/FR-8) -- the DEFAULT chain (spec 0021 FR-6). Keeps its
    exact pre-0021 signature and now delegates to :func:`chains_for`: every
    existing chain-assembling call site serves the default without being
    told to, and there is no argument a new one can forget to pass. Raises
    UnknownIssuerError for an unknown id.
    """
    return list(chains_for(db, ca_id).default.rows)


def _cert_valid_at(row: CACertificate, now: datetime) -> bool:
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def chains_for(db: Session, ca_id: int, now: datetime | None = None) -> ChainSet:
    """Every path from ``ca_id`` to a trust anchor cabin currently serves,
    and which one is the default (spec 0021 FR-6).

    The base path is the plain ``parent_id`` walk (:func:`_parent_walk`,
    unchanged since spec 0017). Each active cross row whose ``cross_of_id``
    is the base path's topmost row -- taken in id order -- yields one
    alternate: the base path with that top replaced by the cross row,
    followed by the ``parent_id`` walk upward from the cross row's own
    signing root. Only one hop: a cross row's signing root is never itself
    searched for a further cross row, so the set of paths does not grow
    with every generation of cross-signing.

    An alternate is dropped when any row on it -- the cross certificate OR
    the signing root above it -- isn't valid at ``now`` (FR-7, the DST Root
    CA X3 requirement): evaluated fresh on every call, against ``now``
    (defaulting to the current instant), with no cache and no column. The
    surviving alternate whose cross row has the lowest id becomes the
    default -- the oldest cross certificate, the one in the most trust
    stores -- and the base path is always in ``alternates`` when it isn't
    the default, because even an expired self-signed root is still the
    only thing left to serve.

    ``now`` lets a test name the instant directly rather than monkeypatching
    a clock, so FR-7's boundary is measurable from both sides; production
    callers omit it.
    """
    if now is None:
        now = datetime.now(UTC)

    base_rows = tuple(_parent_walk(db, ca_id))
    base = Chain(rows=base_rows, via_cross_id=None)
    top_id = base_rows[-1].id

    cross_rows = db.scalars(
        select(CACertificate)
        .where(CACertificate.cross_of_id == top_id, CACertificate.status == "active")
        .order_by(CACertificate.id)
    )

    surviving: list[Chain] = []
    for cross_row in cross_rows:
        assert cross_row.parent_id is not None  # FR-1: a cross row always has a signing root
        signing_walk = tuple(_parent_walk(db, cross_row.parent_id))
        if all(_cert_valid_at(row, now) for row in (cross_row, *signing_walk)):
            rows = (*base_rows[:-1], cross_row, *signing_walk)
            surviving.append(Chain(rows=rows, via_cross_id=cross_row.id))

    if surviving:
        return ChainSet(default=surviving[0], alternates=(base, *surviving[1:]))
    return ChainSet(default=base, alternates=())


def active_issuers(db: Session) -> list[CACertificate]:
    """The active intermediates -- i.e. what may sign a leaf right now
    (spec 0017 FR-2)."""
    return list(
        db.scalars(
            select(CACertificate)
            .where(CACertificate.kind == "intermediate", CACertificate.status == "active")
            .order_by(CACertificate.id)
        )
    )


def resolve_issuer(db: Session, issuer_id: int | None) -> CACertificate:
    """FR-6's issuer-selection rule, in the one place both
    :func:`cabin.ca.certs.issue_and_store` and
    :func:`cabin.ca.certs.sign_csr_and_store` call it from.

    An explicit id must name an existing, active intermediate. Omitted, it
    resolves to the sole active issuer, or raises IssuerRequiredError when
    several exist -- ambiguity is not silently broken by picking one.
    CANotConfiguredError covers the case with no active issuer at all.
    """
    if issuer_id is not None:
        row = get_ca(db, issuer_id)
        if row.kind != "intermediate":
            raise UnknownIssuerError(f"CA certificate {issuer_id} is not an intermediate")
        if row.status != "active":
            raise IssuerRetiredError(f"issuer {issuer_id} is retired")
        return row
    issuers = active_issuers(db)
    if len(issuers) == 1:
        return issuers[0]
    if len(issuers) > 1:
        raise IssuerRequiredError("more than one active issuer exists; an issuer_id is required")
    # Deliberately worded about a hierarchy, not an issuer: retire() refuses
    # to leave zero active issuers (FR-4), so the only way to land here with
    # no explicit issuer_id is that no CA was ever created or imported. An
    # "issuer" framing would describe a state that cannot exist on its own,
    # and would tell a first-time operator nothing about what to do next.
    raise CANotConfiguredError("no CA hierarchy has been created or imported yet")


def signing_credentials(
    db: Session, secrets: SecretStore, issuer_id: int
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """The named row's certificate and unsealed private key.

    Raises UnknownIssuerError for an unknown id, CANotConfiguredError when
    that row's ``key_sealed`` is NULL (an imported hierarchy's root, or --
    before this spec -- any CA at all).
    """
    row = get_ca(db, issuer_id)
    if row.key_sealed is None:
        raise CANotConfiguredError(f"CA certificate {issuer_id}'s private key is not available")
    key = _unseal_signing_key(secrets, row.key_sealed)
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))
    return cert, key


def create_hierarchy(
    db: Session,
    secrets: SecretStore,
    name: str,
    key_type: str = "ecdsa-p256",
    root_years: int = 20,
    intermediate_years: int = 10,
    path_length: int = 1,
    constraints: leaf.NameConstraintSpec | None = None,
) -> CAHierarchy:
    """Generate a fresh root+intermediate hierarchy and store both rows,
    sealing both private keys before insert (never plaintext in the DB).

    Adds a *further* hierarchy alongside whatever already exists
    (spec 0017 FR-2): the pre-0017 "only one CA ever" guard, and the
    IntegrityError backstop that assumed any constraint violation here
    meant that guard raced, are both gone. That backstop was already wrong
    the moment a second NOT NULL constraint (``name``) existed on the same
    table -- it would have reported "a CA already exists" for what was
    actually a missing column, which is exactly the bug this spec fixes
    first.

    ``path_length`` (spec 0017 FR-13) is forwarded to
    :func:`cabin.ca.x509.create_root` as-is -- this layer does not bound it,
    the create form does (AC-11). It is not in the spec's own
    interface-contract table for this function, which otherwise pins the
    signature unchanged from before 0017; added because this is the only
    function that ever builds a root during hierarchy creation, so FR-13's
    form field has no other way to reach ``create_root``, and
    ``web/ca_ui.py`` already calls this with the keyword.

    ``constraints`` (spec 0020 FR-1) applies to the **intermediate only**:
    the root, built here too, never takes one -- a root does not sign
    leaves in cabin, so a constraint on it would only ever be evaluated by
    somebody else's validator. ``None`` and an empty spec both mean "no
    constraints" (``leaf.name_constraints_extension`` is where that
    collapsing happens); either way the intermediate carries no
    ``NameConstraints`` extension at all, exactly as it did before this
    spec.
    """
    root_cert, root_key = ca_x509.create_root(
        f"{name} Root CA", key_type, years=root_years, path_length=path_length
    )
    intermediate_cert, intermediate_key = ca_x509.create_intermediate(
        root_cert,
        root_key,
        f"{name} Intermediate CA",
        key_type,
        years=intermediate_years,
        name_constraints=leaf.name_constraints_extension(
            constraints if constraints is not None else leaf.NameConstraintSpec()
        ),
    )

    root_row = CACertificate(
        kind="root",
        name=f"{name} Root CA",
        status="active",
        cert_pem=_cert_pem(root_cert),
        key_sealed=secrets.seal(_key_pem(root_key)),
    )
    db.add(root_row)
    db.flush()  # assigns root_row.id, needed for the intermediate's parent_id
    intermediate_row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_row.id,
        status="active",
        cert_pem=_cert_pem(intermediate_cert),
        key_sealed=secrets.seal(_key_pem(intermediate_key)),
    )
    db.add(intermediate_row)
    db.commit()
    return CAHierarchy(root=root_row, intermediate=intermediate_row)


def import_hierarchy(
    db: Session,
    secrets: SecretStore,
    cert_pem: str,
    key_pem: str,
    key_passphrase: str | None,
    chain_pem: str,
) -> CAHierarchy:
    """Validate (see :func:`cabin.ca.x509.load_import`) and store an
    imported signing CA plus its parent/root certificate as a further
    hierarchy (spec 0017 FR-2).

    Takes no ``name``: the naming rule says ``ca_certificates.name`` is
    always the subject CN of that row's own certificate, and for an
    imported hierarchy that subject was chosen by whoever ran that CA, not
    by the operator running this import.

    The root's private key is never supplied for an import, so its
    key_sealed stays NULL -- which is what later makes
    ``create_intermediate_under``/``renew_in_place`` refuse to use it as a
    signer (FR-3/FR-5). Raises CAImportError if validation fails (FR-2).
    """
    cert, key, parent = ca_x509.load_import(
        cert_pem.encode("utf-8"),
        key_pem.encode("utf-8"),
        key_passphrase,
        chain_pem.encode("utf-8"),
    )
    # chain_pem is required here (unlike the pure load_import, where it's
    # optional), so load_import always parses and returns a parent.
    assert parent is not None
    # Store the PARSED parent certificate, not the raw submitted chain_pem:
    # an operator may paste a multi-cert bundle or an openssl "subject=/
    # issuer=" text preamble, and /ca/{id}.pem must serve exactly the one
    # clean certificate that the chain check above validated against (the
    # first certificate found in chain_pem -- a single-level parent check
    # is enough for v1, see FR-2).
    root_row = CACertificate(
        kind="root",
        name=_subject_name(parent),
        status="active",
        cert_pem=_cert_pem(parent),
        key_sealed=None,
    )
    db.add(root_row)
    db.flush()  # assigns root_row.id, needed for the intermediate's parent_id
    intermediate_row = CACertificate(
        kind="intermediate",
        name=_subject_name(cert),
        parent_id=root_row.id,
        status="active",
        cert_pem=_cert_pem(cert),
        key_sealed=secrets.seal(_key_pem(key)),
    )
    db.add(intermediate_row)
    db.commit()
    return CAHierarchy(root=root_row, intermediate=intermediate_row)


def create_intermediate_under(
    db: Session,
    secrets: SecretStore,
    root_id: int,
    name: str,
    key_type: str = "ecdsa-p256",
    years: int = 10,
    constraints: leaf.NameConstraintSpec | None = None,
) -> CACertificate:
    """The rotation path (spec 0017 FR-3): a further intermediate under an
    existing root, active immediately, alongside whatever intermediates
    that root already has.

    ``root_id`` must name a ``kind == "root"`` row -- a plain ValueError,
    not one of the new exception types, because the UI only ever offers
    this action on a root; reaching this with anything else is a
    programming error at the call site, not a state an operator can steer
    into. Signs with the root's own key, so a root with no stored key (every
    imported hierarchy) raises CANotConfiguredError naming the reason
    (AC-13) rather than failing deeper inside with an AttributeError.
    ``ca/x509.py:create_intermediate`` already clamps ``years`` to the
    root's remaining validity.

    ``constraints`` (spec 0020 FR-1): the only other way to add a further
    intermediate, so it gets the same parameter ``create_hierarchy`` does,
    forwarded the same way.
    """
    root = get_ca(db, root_id)
    if root.kind != "root":
        raise ValueError(f"CA certificate {root_id} is not a root")
    if root.key_sealed is None:
        raise CANotConfiguredError(f"root {root_id}'s private key is not available")
    root_cert = x509.load_pem_x509_certificate(root.cert_pem.encode("utf-8"))
    root_key = _unseal_signing_key(secrets, root.key_sealed)

    intermediate_cert, intermediate_key = ca_x509.create_intermediate(
        root_cert,
        root_key,
        f"{name} Intermediate CA",
        key_type,
        years=years,
        name_constraints=leaf.name_constraints_extension(
            constraints if constraints is not None else leaf.NameConstraintSpec()
        ),
    )
    row = CACertificate(
        kind="intermediate",
        name=f"{name} Intermediate CA",
        parent_id=root_id,
        status="active",
        cert_pem=_cert_pem(intermediate_cert),
        key_sealed=secrets.seal(_key_pem(intermediate_key)),
    )
    db.add(row)
    db.commit()
    return row


def _same_ca(a: x509.Certificate, b: x509.Certificate) -> bool:
    """Same subject -- compared as DER, never as an RFC 4514 string -- and
    the same SubjectPublicKeyInfo (spec 0021 FR-5): the "these two
    certificates are for the same logical CA" identity that resolving an
    imported cross certificate's subject and signing root against existing
    ``ca_certificates`` rows stands on. Without the public-key half, a CA
    certificate whose subject CN happens to read the same as an existing
    row's -- a string that isn't unique and that cabin itself generates
    from an operator's label -- could be stapled into that row's identity.
    """
    a_key = a.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    b_key = b.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return a.subject.public_bytes() == b.subject.public_bytes() and a_key == b_key


def cross_sign_root(
    db: Session,
    secrets: SecretStore,
    ca_id: int,
    signing_root_id: int,
    years: int = 10,
) -> CACertificate:
    """Sign another root's certificate with this root's key, so a device
    that only trusts ``signing_root_id`` can build a path to whatever
    ``ca_id``'s hierarchy issues (spec 0021 FR-4). Writes one ``kind=
    "cross"`` row: ``parent_id`` the signing root, ``cross_of_id`` the
    subject root, ``key_sealed`` NULL -- the private key is the subject
    root's own and is already sealed on that row.

    ``ca_id``'s own private key is never needed and never touched: signing
    a certificate for another CA's public key needs only that public key,
    which is what lets cabin cross-sign an imported root. ``signing_root_id``
    is the one whose key actually signs, so it must name a root with a
    stored key -- CANotConfiguredError, naming the missing key, is raised
    for the same reason :func:`create_intermediate_under` raises it for a
    root with none.

    Raises ``ValueError`` (naming "root") when ``ca_id`` or
    ``signing_root_id`` doesn't name a ``kind == "root"`` row, or when they
    name the same row -- cross-signing a root with itself would just be a
    re-issued self-signed root, which is what :func:`renew_in_place` is
    for. Raises :class:`CrossSignError` when
    :func:`cabin.ca.x509.cross_path_length_error` finds a problem (FR-3),
    or when an active cross certificate already exists for this exact pair
    -- a second identical path serves nobody and makes FR-6's default rule
    depend on a coin toss; renewing the existing one (FR-11) is what
    extending it means.
    """
    ca = get_ca(db, ca_id)
    if ca.kind != "root":
        raise ValueError(f"CA certificate {ca_id} is not a root")
    signing_root = get_ca(db, signing_root_id)
    if signing_root.kind != "root":
        raise ValueError(f"CA certificate {signing_root_id} is not a root")
    if signing_root_id == ca_id:
        raise ValueError(f"CA certificate {ca_id} cannot cross-sign itself")
    if signing_root.key_sealed is None:
        raise CANotConfiguredError(f"root {signing_root_id}'s private key is not available")

    subject_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode("utf-8"))
    issuer_cert = x509.load_pem_x509_certificate(signing_root.cert_pem.encode("utf-8"))

    path_length_error = ca_x509.cross_path_length_error(subject_cert, issuer_cert)
    if path_length_error is not None:
        raise CrossSignError(path_length_error)

    existing = db.scalars(
        select(CACertificate).where(
            CACertificate.cross_of_id == ca_id,
            CACertificate.parent_id == signing_root_id,
            CACertificate.status == "active",
        )
    ).first()
    if existing is not None:
        raise CrossSignError(
            f"an active cross certificate for CA {ca_id} signed by {signing_root_id} "
            "already exists; renew it instead of cross-signing again"
        )

    issuer_key = _unseal_signing_key(secrets, signing_root.key_sealed)
    cross_cert = ca_x509.cross_sign(subject_cert, issuer_cert, issuer_key, years)

    row = CACertificate(
        kind="cross",
        name=_subject_name(cross_cert),
        parent_id=signing_root_id,
        cross_of_id=ca_id,
        status="active",
        cert_pem=_cert_pem(cross_cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row


def import_cross(db: Session, cross_pem: str, issuer_pem: str) -> CACertificate:
    """Store a cross certificate produced elsewhere (spec 0021 FR-5): the
    old root belongs to somebody else, so there is no private key to submit
    and nothing here ever touches one.

    Resolves the SUBJECT root by comparing subject and public key
    (:func:`_same_ca`) against every ``kind == "root"`` row cabin has:
    exactly one must match, or the import is refused -- none matching means
    this isn't a certificate for any CA on this instance, and more than one
    matching is a duplicate-root state cabin cannot resolve. Reuses an
    existing row for the SIGNING root by the same comparison, and otherwise
    inserts it as a ``kind="root"`` row with ``key_sealed=None`` -- the same
    shape :func:`import_hierarchy` already stores an imported parent in --
    so two cross certificates from one old root don't produce two rows for
    it and two entries on ``/ca``.

    Raises :class:`cabin.ca.x509.CAImportError` for everything
    :func:`cabin.ca.x509.load_cross` refuses, and for the "no matching root"
    / "more than one matches" cases above.
    """
    try:
        cross_preview = x509.load_pem_x509_certificate(cross_pem.encode("utf-8"))
    except ValueError as exc:
        raise ca_x509.CAImportError(f"not a valid certificate PEM: {exc}") from exc
    try:
        issuer_cert = x509.load_pem_x509_certificate(issuer_pem.encode("utf-8"))
    except ValueError as exc:
        raise ca_x509.CAImportError(f"not a valid issuer certificate PEM: {exc}") from exc

    roots = list_cas(db, kind="root")
    subject_rows = [
        row
        for row in roots
        if _same_ca(x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8")), cross_preview)
    ]
    if not subject_rows:
        raise ca_x509.CAImportError(
            "this certificate's subject and public key do not match any CA on this instance"
        )
    if len(subject_rows) > 1:
        raise ca_x509.CAImportError(
            "more than one CA on this instance matches this certificate's subject and public key"
        )
    subject_row = subject_rows[0]
    subject_cert = x509.load_pem_x509_certificate(subject_row.cert_pem.encode("utf-8"))

    cross_cert = ca_x509.load_cross(cross_pem.encode("utf-8"), subject_cert, issuer_cert)

    signing_rows = [
        row
        for row in roots
        if row.id != subject_row.id
        and _same_ca(x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8")), issuer_cert)
    ]
    if signing_rows:
        signing_row = signing_rows[0]
    else:
        signing_row = CACertificate(
            kind="root",
            name=_subject_name(issuer_cert),
            status="active",
            cert_pem=_cert_pem(issuer_cert),
            key_sealed=None,
        )
        db.add(signing_row)
        db.flush()  # assigns signing_row.id, needed for the cross row's parent_id

    row = CACertificate(
        kind="cross",
        name=_subject_name(cross_cert),
        parent_id=signing_row.id,
        cross_of_id=subject_row.id,
        status="active",
        cert_pem=_cert_pem(cross_cert),
        key_sealed=None,
    )
    db.add(row)
    db.commit()
    return row


def retire_targets(db: Session, ca_id: int) -> set[int]:
    """The ids :func:`retire` would stand down for ``ca_id``: the row
    itself, plus its intermediates when it is a root (spec 0017 FR-4's
    cascade).

    Extracted so spec 0022 FR-17's route check -- "would retiring this leave
    cabin's own TLS binding without an issuer" -- and :func:`retire` itself
    share one definition of what a retire touches, instead of the check
    re-deriving the cascade and silently drifting from it.
    """
    row = get_ca(db, ca_id)
    if row.kind != "root":
        return {row.id}
    children = db.scalars(select(CACertificate).where(CACertificate.parent_id == row.id))
    return {row.id, *(child.id for child in children)}


def retire(db: Session, ca_id: int) -> None:
    """Stand a row down: it stops being offered as an issuer, but keeps
    serving its chain, its CRL and its inventory entry (spec 0017 FR-4).

    Retiring an already-retired row is a no-op, not an error -- a caller
    retrying after a timeout should get success, not a 409. Retiring a root
    cascades to every one of its intermediates, because a root that must
    not be used is not one whose intermediates may keep issuing under it --
    :func:`retire_targets` is what computes that set. Either way, the
    operation is refused with RetireError when it would leave the whole
    instance with no active issuer anywhere -- the same invariant as "the
    last superadmin cannot be deleted" (``users.py:75-79``) -- and refusing
    leaves every row untouched.
    """
    row = get_ca(db, ca_id)
    if row.status == "retired":
        return

    targets = retire_targets(db, ca_id)
    remaining = [issuer for issuer in active_issuers(db) if issuer.id not in targets]
    if not remaining:
        if row.kind == "root":
            raise RetireError(f"retiring root {ca_id} would leave no active issuer")
        raise RetireError(f"cannot retire the last active issuer ({ca_id})")
    for target_id in targets:
        get_ca(db, target_id).status = "retired"
    db.commit()


def renew_in_place(db: Session, secrets: SecretStore, ca_id: int, years: int) -> CACertificate:
    """Re-sign the same row's certificate for the same key, subject and row
    id, with a later ``not_after`` (spec 0017 FR-5) -- so every certificate
    already issued under it, whose AuthorityKeyIdentifier matches its
    unchanged SubjectKeyIdentifier, keeps validating without reissue.

    Delegates the actual rebuilding to
    ``ca/x509.py:renew_certificate(cert, parent_cert, parent_key, years)``
    rather than assembling a ``CertificateBuilder`` here. ``parent_key`` is
    the only key that ever signs: for a root that is its own unsealed key
    (self-renewal); for an intermediate or a cross row it is the row
    ``parent_id`` names -- never the row's own key, which only ever
    supplies its already-signed public key via ``cert``. Requires the
    signing key: raises CANotConfiguredError, naming the reason, for a root
    with no stored key (an imported root) or a non-root row whose parent
    has none (an intermediate under an imported root, or a cross
    certificate whose signing root has no key).

    The ``key_sealed is None`` check lives in the ``kind == "root"`` branch
    rather than up front (spec 0021 FR-11): a cross row's own ``key_sealed``
    is always NULL -- its key belongs to the subject root's row, not to
    this one (spec 0021 FR-1) -- so a top-of-function check on this row
    would refuse a cross row's renewal outright. The non-root branch below
    already checks the PARENT's key, which is what really guards the
    signature, so nothing changes for any intermediate that exists today.
    """
    row = get_ca(db, ca_id)
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode("utf-8"))

    if row.kind == "root":
        if row.key_sealed is None:
            raise CANotConfiguredError(f"CA certificate {ca_id}'s private key is not available")
        parent_cert = cert
        parent_key = _unseal_signing_key(secrets, row.key_sealed)
        effective_years = years
    else:
        parent = get_ca(db, row.parent_id) if row.parent_id is not None else None
        if parent is None or parent.key_sealed is None:
            raise CANotConfiguredError(
                f"CA certificate {ca_id}'s parent has no private key available"
            )
        parent_cert = x509.load_pem_x509_certificate(parent.cert_pem.encode("utf-8"))
        parent_key = _unseal_signing_key(secrets, parent.key_sealed)
        effective_years = _years_until(parent_cert.not_valid_after_utc, years)

    renewed = ca_x509.renew_certificate(cert, parent_cert, parent_key, effective_years)
    row.cert_pem = _cert_pem(renewed)
    db.commit()
    return row


def _years_until(deadline: datetime, years: int) -> int:
    """The largest whole-year count, at most ``years``, that still keeps a
    renewal at or before ``deadline`` (spec 0017 FR-5: an intermediate's
    renewal is clamped to its parent's remaining validity).

    ``ca/x509.py:renew_certificate`` takes a year count rather than a raw
    instant and, deliberately, clamps nothing itself -- unlike
    ``create_intermediate``, which clamps a computed ``not_after`` directly
    against the root's. This is the years-count equivalent of that same
    clamp, needed here because that is the only knob this call has.
    Negative or zero is possible (the parent is already past due); it is
    passed through rather than floored to some minimum, so a renewal
    attempted after the parent's own expiry stays visibly wrong rather than
    quietly granting a year it does not have.
    """
    remaining_days = (deadline - datetime.now(UTC)).days
    return min(years, remaining_days // 365)
