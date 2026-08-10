"""Pure X.509 crypto for the CA hierarchy: key generation, root/intermediate
creation, and import validation (spec 0004 FR-1/FR-2).

No FastAPI or database imports here -- this module only deals with
pyca/cryptography objects and PEM bytes. Storage and sealing of the
resulting keys live in :mod:`cabin.ca.service`.
"""

from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.x509.oid import NameOID

#: NotBefore is backdated by this much so a CA created "now" isn't rejected
#: by a relying party whose clock is slightly behind ours (FR-1).
_BACKDATE = timedelta(minutes=5)
_DAYS_PER_YEAR = 365

#: Private key types cabin can use to sign certificates. Anything else
#: (e.g. an imported X25519/DH key) isn't a valid CA signing key.
SIGNING_KEY_TYPES = (
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
)

#: generate_key() identifiers, in the order offered by the wizard.
KEY_TYPES = ("ecdsa-p256", "ecdsa-p384", "rsa-4096", "ed25519")

_KEY_USAGE_ERROR = "CA certificates must carry a KeyUsage extension with keyCertSign"


class CAImportError(Exception):
    """An imported CA certificate/key/chain failed validation (FR-2); the
    message names the specific reason."""


def generate_key(key_type: str) -> CertificateIssuerPrivateKeyTypes:
    """Generate a new private key.

    Supported ``key_type`` values: ``ecdsa-p256`` (default), ``ecdsa-p384``,
    ``rsa-4096``, ``ed25519``.
    """
    if key_type == "ecdsa-p256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ecdsa-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if key_type == "rsa-4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError(f"unsupported key type: {key_type!r}")


def signing_algorithm(
    key: CertificateIssuerPrivateKeyTypes,
) -> hashes.SHA256 | hashes.SHA384 | None:
    """The hash must match the signing key: Ed25519 signs with
    algorithm=None (pure EdDSA); ECDSA uses a hash sized to the curve's
    security level (SHA-384 for P-384, SHA-256 otherwise); RSA uses
    SHA-256."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP384R1):
        return hashes.SHA384()
    return hashes.SHA256()


def authority_key_identifier(
    issuer_cert: x509.Certificate, issuer_key: CertificateIssuerPrivateKeyTypes
) -> x509.AuthorityKeyIdentifier:
    """The AKI for anything ``issuer_cert`` signs -- a leaf (spec 0005 FR-1)
    or a CRL (spec 0007 FR-3).

    It is COPIED from the issuer's SubjectKeyIdentifier, not recomputed from
    its public key. An imported CA may use an SKI that isn't RFC 5280
    "method 1" (a SHA-1 of the public key), and OpenSSL will refuse to build
    the chain unless our AKI matches that SKI byte for byte. Only an issuer
    that carries no SKI at all leaves us the public key to derive from.
    """
    try:
        issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key())
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski)


def _ca_key_usage() -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _public_key_der(public_key: CertificatePublicKeyTypes) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _name_constraints_or_none(
    cert: x509.Certificate,
) -> x509.Extension[x509.NameConstraints] | None:
    try:
        return cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        return None


def create_root(
    subject_cn: str, key_type: str, years: int = 20, path_length: int = 1
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """Self-signed root CA.

    Extensions: ``BasicConstraints(ca=True, path_length=path_length)`` and
    ``KeyUsage(key_cert_sign, crl_sign)``, both critical, plus a
    ``SubjectKeyIdentifier``. ``path_length`` (spec 0017 FR-13) is the one
    decision about a root that cannot be corrected afterwards; this layer
    does not bound it -- the 1..4 policy range is the form's job (AC-11).
    """
    key = generate_key(key_type)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.now(UTC)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=_DAYS_PER_YEAR * years))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    cert = builder.sign(key, algorithm=signing_algorithm(key))
    return cert, key


def create_intermediate(
    root_cert: x509.Certificate,
    root_key: CertificateIssuerPrivateKeyTypes,
    subject_cn: str,
    key_type: str,
    years: int = 10,
    name_constraints: x509.NameConstraints | None = None,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    """Signing CA issued by ``root_cert``/``root_key``.

    Extensions: ``BasicConstraints(ca=True, path_length=0)`` and
    ``KeyUsage(key_cert_sign, crl_sign)``, both critical, a
    ``SubjectKeyIdentifier``, and an ``AuthorityKeyIdentifier`` derived from
    the root's ``SubjectKeyIdentifier``. ``name_constraints`` (spec 0020
    FR-1/FR-2), when given, is added as a **critical** ``NameConstraints``
    extension -- RFC 5280 requires it -- and left out entirely when
    ``None``, never written as an empty one. The caller
    (``cabin.ca.leaf.name_constraints_extension``) is what turns "no
    constraints" into ``None`` rather than an empty extension; this
    function only adds what it is given.
    """
    key = generate_key(key_type)
    root_ski = root_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    now = datetime.now(UTC)
    # An intermediate must never outlive its root: the wizard/service layer
    # already rejects intermediate_years > root_years, but clamp here too
    # as a primitive-level safety net against any other caller.
    not_after = min(now + timedelta(days=_DAYS_PER_YEAR * years), root_cert.not_valid_after_utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski),
            critical=False,
        )
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    cert = builder.sign(root_key, algorithm=signing_algorithm(root_key))
    return cert, key


def renew_certificate(
    cert: x509.Certificate,
    parent_cert: x509.Certificate,
    parent_key: CertificateIssuerPrivateKeyTypes,
    years: int,
) -> x509.Certificate:
    """Re-sign ``cert`` for the same key, subject and row (spec 0017 FR-5) --
    rotation without a rekey.

    ``parent_key`` is the ONLY key that signs, and there is no separate
    ``key`` parameter for ``cert``'s own key: the renewed certificate's
    public key is read straight off ``cert.public_key()``, so there is
    nothing for a second key argument to do except be silently ignored (that
    was this function's bug once). For a root, call with ``cert``/its own
    key as ``parent_cert``/``parent_key`` (self-signed); for an intermediate,
    pass its parent's cert/key. The public key, subject, SubjectKeyIdentifier,
    BasicConstraints (including ``path_length``) and KeyUsage are carried
    over from ``cert`` unchanged -- only the serial number and ``not_after``
    actually move. That is what keeps every certificate issued under the old
    ``cert`` valid against the renewed one: its AuthorityKeyIdentifier still
    matches the unchanged SubjectKeyIdentifier.

    The AuthorityKeyIdentifier is not "carried over" but re-derived from
    ``parent_cert``/``parent_key`` the normal way, and only added at all if
    ``cert`` already carried one -- mirroring :func:`create_root` (no AKI, a
    self-signed cert doesn't need one) and :func:`create_intermediate` (AKI
    from the parent's SKI). Since a renewal never changes any key, this
    lands on the same bytes an unrenewed AKI would already have carried.

    The ``NameConstraints`` extension, when ``cert`` carries one, is copied
    across unchanged -- value and criticality both (spec 0020 FR-6) -- and
    left out when ``cert`` carries none. A renewal that dropped it would
    turn an intermediate restricted to one subtree into one that may sign
    anything, on an operator action whose only visible effect is meant to
    be a later expiry date.

    This is a pure primitive: it clamps nothing. Cutting ``years`` back to
    the parent's remaining validity is ``ca.service.renew_in_place``'s job,
    the same way choosing which issuer to call this with is.
    """
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    try:
        cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        needs_aki = True
    except x509.ExtensionNotFound:
        needs_aki = False
    try:
        name_constraints = cert.extensions.get_extension_for_class(x509.NameConstraints)
    except x509.ExtensionNotFound:
        name_constraints = None

    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(parent_cert.subject)
        .public_key(cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=_DAYS_PER_YEAR * years))
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(ski, critical=False)
    )
    if needs_aki:
        builder = builder.add_extension(
            authority_key_identifier(parent_cert, parent_key), critical=False
        )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints.value, critical=name_constraints.critical)
    return builder.sign(parent_key, algorithm=signing_algorithm(parent_key))


def cross_path_length_error(
    subject_cert: x509.Certificate, issuer_cert: x509.Certificate
) -> str | None:
    """Whether ``issuer_cert`` can cross-sign ``subject_cert`` without
    producing a path no validator will build (spec 0021 FR-3).

    The cross path is one certificate longer than any path cabin builds
    today -- ``A -> cross(B) -> intermediate(B) -> leaf`` -- so the signing
    root ``issuer_cert`` needs ``path_length`` absent or >= 2 (the cross
    certificate and B's intermediate both count; the leaf does not), and
    the cross certificate -- which copies ``subject_cert``'s
    BasicConstraints unchanged (:func:`cross_sign`) -- needs
    ``path_length`` absent or >= 1. Checked before anything is signed or
    written: a root's ``path_length`` cannot be changed afterwards by any
    operation cabin has (:func:`renew_certificate` carries BasicConstraints
    over unchanged), so the only remedy for a root that fails this is a
    different root.

    Returns a message naming ``path_length`` and the value the failing root
    actually carries, or ``None`` when both hold. Shared by
    :func:`cross_sign`'s caller, :func:`load_cross` and the UI's select of
    roots that could sign a given one, so the arithmetic lives in one place.
    """
    issuer_length = issuer_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value.path_length
    if issuer_length is not None and issuer_length < 2:
        return f"signing root's path_length is {issuer_length}, but cross-signing needs at least 2"
    subject_length = subject_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value.path_length
    if subject_length is not None and subject_length < 1:
        return f"root's path_length is {subject_length}, but a cross certificate needs at least 1"
    return None


def cross_sign(
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
    issuer_key: CertificateIssuerPrivateKeyTypes,
    years: int = 10,
) -> x509.Certificate:
    """A second certificate for ``subject_cert``'s CA: same subject, same
    public key, a new serial, signed by ``issuer_cert``/``issuer_key``
    instead of ``subject_cert``'s own key (spec 0021 FR-2). Creates no new
    CA and no new key -- there is no key to return, which is the difference
    between this and :func:`create_intermediate`.

    Deliberately not built on :func:`renew_certificate`, which is otherwise
    the same shape: that function adds an AuthorityKeyIdentifier only when
    the input already carried one, and a self-signed root (:func:`create_root`)
    carries none -- so reusing it here would produce a cross certificate
    with NO AuthorityKeyIdentifier, exactly the hint a path builder uses to
    tell a root's two certificates apart (the DST Root CA X3 pathology in
    miniature). This function always adds one, derived from the SIGNING
    root through :func:`authority_key_identifier`.

    Every other extension is copied from ``subject_cert`` byte for byte,
    never rebuilt: a ``Name`` or a ``SubjectKeyIdentifier`` that renders
    identically can encode differently, and to a path builder a differently
    encoded one is a different CA. ``not_after`` is clamped to
    ``issuer_cert``'s own, the same way :func:`create_intermediate` clamps
    against its root, because a cross certificate outliving the root that
    signed it would look like a path and never be one.

    No CRL distribution point and no AuthorityInformationAccess: cabin
    publishes neither for a root, so either would point at a document that
    does not exist.

    Raises ``ValueError`` if ``subject_cert`` carries no
    SubjectKeyIdentifier -- a CA certificate without one cannot be
    cross-signed usefully, and cabin writes one on every CA it creates.
    """
    try:
        ski = subject_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("subject certificate carries no SubjectKeyIdentifier") from exc
    basic_constraints = subject_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    key_usage = subject_cert.extensions.get_extension_for_class(x509.KeyUsage).value
    name_constraints = _name_constraints_or_none(subject_cert)

    now = datetime.now(UTC)
    not_after = min(now + timedelta(days=_DAYS_PER_YEAR * years), issuer_cert.not_valid_after_utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_cert.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(subject_cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(not_after)
        .add_extension(basic_constraints, critical=True)
        .add_extension(key_usage, critical=True)
        .add_extension(ski, critical=False)
        .add_extension(authority_key_identifier(issuer_cert, issuer_key), critical=False)
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints.value, critical=name_constraints.critical)
    return builder.sign(issuer_key, algorithm=signing_algorithm(issuer_key))


def load_import(
    cert_pem: bytes,
    key_pem: bytes,
    key_passphrase: str | None,
    chain_pem: bytes | None,
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes, x509.Certificate | None]:
    """Parse and validate an imported signing CA certificate and private key.

    Returns ``(cert, key, parent)`` -- ``parent`` is the parsed certificate
    from ``chain_pem`` (or ``None`` if ``chain_pem`` wasn't given), so a
    caller that already validated the chain here doesn't need to re-parse
    it.

    Raises :class:`CAImportError`, with a message naming the reason, when:
    the key can't be decrypted with ``key_passphrase``; the key doesn't
    match the certificate; the certificate has no ``BasicConstraints
    (ca=True)``; its ``KeyUsage`` lacks ``keyCertSign``; it's expired or not
    yet valid; or (when ``chain_pem`` is given) the parent is the imported
    certificate itself, or it doesn't verify against that parent -- a
    single-level parent check is enough for v1 (FR-2).
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise CAImportError(f"not a valid certificate PEM: {exc}") from exc

    password = key_passphrase.encode("utf-8") if key_passphrase else None
    try:
        key = serialization.load_pem_private_key(key_pem, password=password)
    except (ValueError, TypeError) as exc:
        raise CAImportError(f"could not decrypt private key: {exc}") from exc
    if not isinstance(key, SIGNING_KEY_TYPES):
        raise CAImportError(f"unsupported private key type: {type(key).__name__}")

    if _public_key_der(key.public_key()) != _public_key_der(cert.public_key()):
        raise CAImportError("private key does not match the certificate's public key")

    try:
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError("certificate has no BasicConstraints extension") from exc
    if not basic_constraints.ca:
        raise CAImportError("certificate is not a CA certificate (BasicConstraints ca=False)")

    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError(_KEY_USAGE_ERROR) from exc
    if not key_usage.key_cert_sign:
        raise CAImportError(_KEY_USAGE_ERROR)

    now = datetime.now(UTC)
    if now < cert.not_valid_before_utc:
        raise CAImportError("certificate is not yet valid")
    if now > cert.not_valid_after_utc:
        raise CAImportError("certificate has expired")

    parent: x509.Certificate | None = None
    if chain_pem is not None:
        try:
            parent = x509.load_pem_x509_certificate(chain_pem)
        except ValueError as exc:
            raise CAImportError(f"not a valid parent certificate PEM: {exc}") from exc
        if parent.subject == cert.subject and _public_key_der(
            parent.public_key()
        ) == _public_key_der(cert.public_key()):
            raise CAImportError("the parent certificate is the imported certificate itself")
        try:
            cert.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise CAImportError(f"certificate does not chain to the given parent: {exc}") from exc

    return cert, key, parent


def load_cross(
    cross_pem: bytes,
    subject_cert: x509.Certificate,
    issuer_cert: x509.Certificate,
) -> x509.Certificate:
    """Parse and validate a cross certificate produced elsewhere, against
    the two roots it claims to connect (spec 0021 FR-5).

    Unlike :func:`load_import`, no private key is involved and none is
    checked: nobody holds the private key of a cross certificate somebody
    else produced, and cross-signing needs only a public key. What this
    function exists to check instead is that ``cross_pem`` really is
    another certificate for ``subject_cert``'s CA -- the same subject and
    the same public key, compared as DER rather than as an RFC 4514 string
    or a fingerprint of the subject alone -- and not an unrelated CA
    certificate an operator could staple into the chain cabin serves to
    every client because its subject CN happens to read the same.

    Raises :class:`CAImportError`, with a message naming the reason -- the
    existing type, not a new one, because the operator is doing the same
    thing they do at ``/ca/import`` -- when: ``cross_pem`` doesn't parse;
    its subject or its SubjectPublicKeyInfo don't match ``subject_cert``'s;
    it wasn't signed by ``issuer_cert``
    (:meth:`x509.Certificate.verify_directly_issued_by`); its
    SubjectKeyIdentifier doesn't match ``subject_cert``'s -- equal public
    keys don't force equal SKIs, and every intermediate under that root
    carries an AuthorityKeyIdentifier naming the subject root's SKI, not its
    public key; it has no ``BasicConstraints(ca=True)`` or its ``KeyUsage``
    lacks ``keyCertSign``; it's expired or not yet valid;
    :func:`cross_path_length_error` finds a problem with either root; or its
    ``NameConstraints`` extension -- value and criticality both -- isn't
    identical to ``subject_cert``'s, with both absent counting as identical
    (spec 0020's deferred question, FR-12).
    """
    try:
        cross = x509.load_pem_x509_certificate(cross_pem)
    except ValueError as exc:
        raise CAImportError(f"not a valid certificate PEM: {exc}") from exc

    if cross.subject.public_bytes() != subject_cert.subject.public_bytes():
        raise CAImportError("subject does not match the existing root's subject")
    if _public_key_der(cross.public_key()) != _public_key_der(subject_cert.public_key()):
        raise CAImportError("public key does not match the existing root's public key")

    try:
        cross.verify_directly_issued_by(issuer_cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise CAImportError(f"certificate was not signed by the given issuer: {exc}") from exc

    try:
        cross_ski = cross.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError("certificate has no SubjectKeyIdentifier extension") from exc
    try:
        subject_ski = subject_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError(
            "the existing root has no SubjectKeyIdentifier extension to compare against"
        ) from exc
    if cross_ski.public_bytes() != subject_ski.public_bytes():
        raise CAImportError(
            "SubjectKeyIdentifier does not match the existing root's -- "
            "no intermediate under it would chain through this certificate"
        )

    try:
        basic_constraints = cross.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError("certificate has no BasicConstraints extension") from exc
    if not basic_constraints.ca:
        raise CAImportError("certificate is not a CA certificate (BasicConstraints ca=False)")

    try:
        key_usage = cross.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise CAImportError(_KEY_USAGE_ERROR) from exc
    if not key_usage.key_cert_sign:
        raise CAImportError(_KEY_USAGE_ERROR)

    now = datetime.now(UTC)
    if now < cross.not_valid_before_utc:
        raise CAImportError("certificate is not yet valid")
    if now > cross.not_valid_after_utc:
        raise CAImportError("certificate has expired")

    path_length_error = cross_path_length_error(subject_cert, issuer_cert)
    if path_length_error is not None:
        raise CAImportError(path_length_error)

    cross_nc = _name_constraints_or_none(cross)
    subject_nc = _name_constraints_or_none(subject_cert)
    mismatched = (cross_nc is None) != (subject_nc is None) or (
        cross_nc is not None
        and subject_nc is not None
        and (
            cross_nc.critical != subject_nc.critical
            or cross_nc.value.public_bytes() != subject_nc.value.public_bytes()
        )
    )
    if mismatched:
        raise CAImportError("NameConstraints does not match the existing root's")

    return cross


def _key_type_label(public_key: CertificatePublicKeyTypes) -> str:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"ECDSA {public_key.curve.name}"
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(public_key).__name__


def describe_certificate(cert: x509.Certificate) -> dict[str, object]:
    """Human-readable summary of a certificate for the ``/ca`` info page:
    subject, issuer, serial (hex), validity window, SHA-256 fingerprint
    (colon-hex), and key type label."""
    fingerprint = cert.fingerprint(hashes.SHA256())
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_valid_before": cert.not_valid_before_utc,
        "not_valid_after": cert.not_valid_after_utc,
        "fingerprint": ":".join(f"{b:02x}" for b in fingerprint),
        "key_type": _key_type_label(cert.public_key()),
    }
