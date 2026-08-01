"""Tests for cabin.ca.leaf: leaf profiles, SAN policy, direct issuance and
CSR signing (spec 0005 FR-1..FR-4, AC-1..AC-4)."""

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from cabin.ca.leaf import (
    MAX_DAYS,
    MAX_SANS,
    MIN_DAYS,
    IssueError,
    Profile,
    issue_certificate,
    parse_profile,
    parse_san_lines,
    sign_csr,
)
from cabin.ca.x509 import create_intermediate, create_root

Issuer = tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]


@pytest.fixture(scope="module")
def issuer() -> Issuer:
    root_cert, root_key = create_root("Leaf Root CA", "ecdsa-p256")
    return create_intermediate(root_cert, root_key, "Leaf Intermediate CA", "ecdsa-p256")


def _csr(
    cn: str | None,
    *,
    sans: list[x509.GeneralName] | None = None,
    extra: list[tuple[x509.ExtensionType, bool]] | None = None,
    key: CertificateIssuerPrivateKeyTypes | None = None,
) -> bytes:
    signing_key = key or ec.generate_private_key(ec.SECP256R1())
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn is not None else []
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attributes))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    for extension, critical in extra or []:
        builder = builder.add_extension(extension, critical=critical)
    csr = builder.sign(signing_key, algorithm=hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _extension[T: x509.ExtensionType](cert: x509.Certificate, cls: type[T]) -> x509.Extension[T]:
    return cert.extensions.get_extension_for_class(cls)


# --- FR-1/AC-1: profile extensions ------------------------------------------


def test_issue_server_profile_extensions(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    cert, key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.server,
        "nas.lan",
        ["DNS:nas.lan", "IP:10.0.0.5"],
        days=90,
        key_type="ecdsa-p256",
    )

    assert cert.subject.rfc4514_string() == "CN=nas.lan"
    assert cert.issuer == issuer_cert.subject

    basic_constraints = _extension(cert, x509.BasicConstraints)
    assert basic_constraints.critical is True
    assert basic_constraints.value.ca is False

    key_usage = _extension(cert, x509.KeyUsage)
    assert key_usage.critical is True
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_encipherment is False  # ECDSA leaf key
    assert key_usage.value.key_cert_sign is False
    assert key_usage.value.crl_sign is False

    eku = _extension(cert, x509.ExtendedKeyUsage)
    assert eku.critical is False
    assert list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH]

    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["nas.lan"]
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("10.0.0.5")]

    # SKI over the leaf's own key, AKI pointing at the issuer's SKI (AC-1).
    ski = _extension(cert, x509.SubjectKeyIdentifier).value
    assert ski.digest == x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
    issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert _extension(cert, x509.AuthorityKeyIdentifier).value.key_identifier == issuer_ski.digest

    # the returned key is the certificate's key, and NotBefore is backdated
    assert key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    ) == cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert cert.not_valid_before_utc < datetime.now(UTC) - timedelta(minutes=4)
    assert cert.serial_number > 0


def test_issue_client_profile_extensions(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    cert, _key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.client,
        "alice@lan",
        ["EMAIL:alice@lan"],
        days=30,
        key_type="ecdsa-p256",
    )

    eku = _extension(cert, x509.ExtendedKeyUsage)
    assert list(eku.value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    key_usage = _extension(cert, x509.KeyUsage)
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_encipherment is False
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.RFC822Name) == ["alice@lan"]


def test_issue_rsa_keyusage_includes_keyencipherment(issuer: Issuer) -> None:
    """FR-1: an RSA server leaf may still be used for RSA key transport, so
    it needs keyEncipherment; ECDSA/Ed25519 leaves must not carry it."""
    issuer_cert, issuer_key = issuer
    cert, key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.server,
        "rsa.lan",
        ["DNS:rsa.lan"],
        days=30,
        key_type="rsa-4096",
    )
    assert isinstance(key, rsa.RSAPrivateKey)
    key_usage = _extension(cert, x509.KeyUsage)
    assert key_usage.value.digital_signature is True
    assert key_usage.value.key_encipherment is True

    ed_cert, _ed_key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.server,
        "ed.lan",
        ["DNS:ed.lan"],
        days=30,
        key_type="ed25519",
    )
    assert _extension(ed_cert, x509.KeyUsage).value.key_encipherment is False


def test_issue_chain_verifies(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    cert, _key = issue_certificate(
        issuer_cert, issuer_key, Profile.server, "verify.lan", ["DNS:verify.lan"]
    )
    cert.verify_directly_issued_by(issuer_cert)  # raises if the chain is broken
    issuer_ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert _extension(cert, x509.AuthorityKeyIdentifier).value.key_identifier == issuer_ski.digest


def _custom_intermediate(
    ski: x509.SubjectKeyIdentifier | None = None,
    *,
    not_after: datetime | None = None,
) -> Issuer:
    """An intermediate with a hand-picked SubjectKeyIdentifier (or none) and
    a hand-picked expiry -- neither is something create_intermediate can
    produce."""
    root_cert, root_key = create_root("Custom Root CA", "ecdsa-p256")
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    expiry = not_after if not_after is not None else now + timedelta(days=365)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Custom CA")]))
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # an already-expired CA still needs notBefore < notAfter
        .not_valid_before(min(now - timedelta(minutes=5), expiry - timedelta(days=1)))
        .not_valid_after(expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if ski is not None:
        builder = builder.add_extension(ski, critical=False)
    return builder.sign(root_key, algorithm=hashes.SHA256()), key


def test_issue_aki_copies_issuer_ski() -> None:
    """The AKI must be COPIED from the issuer's SKI, never recomputed from
    its public key: an imported CA may use a non-method-1 SKI, and OpenSSL
    refuses to build a chain when our AKI doesn't match that SKI byte for
    byte."""
    foreign_digest = bytes(range(20))
    issuer_cert, issuer_key = _custom_intermediate(x509.SubjectKeyIdentifier(foreign_digest))

    cert, _key = issue_certificate(
        issuer_cert, issuer_key, Profile.server, "aki.lan", ["DNS:aki.lan"]
    )
    assert _extension(cert, x509.AuthorityKeyIdentifier).value.key_identifier == foreign_digest

    csr_cert = sign_csr(
        issuer_cert,
        issuer_key,
        _csr("aki.lan", sans=[x509.DNSName("aki.lan")]),
        Profile.server,
    )
    assert _extension(csr_cert, x509.AuthorityKeyIdentifier).value.key_identifier == foreign_digest


def test_issue_aki_falls_back_to_issuer_public_key_without_ski() -> None:
    """An imported CA certificate may carry no SKI at all; then the only
    thing left to derive the AKI from is the issuer's public key."""
    issuer_cert, issuer_key = _custom_intermediate(None)
    expected = x509.SubjectKeyIdentifier.from_public_key(issuer_cert.public_key()).digest

    cert, _key = issue_certificate(
        issuer_cert, issuer_key, Profile.server, "noski.lan", ["DNS:noski.lan"]
    )
    assert _extension(cert, x509.AuthorityKeyIdentifier).value.key_identifier == expected


def test_issue_rejects_unknown_key_type_and_bad_cn(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    with pytest.raises(IssueError, match="key type"):
        issue_certificate(
            issuer_cert,
            issuer_key,
            Profile.server,
            "x.lan",
            ["DNS:x.lan"],
            key_type="dsa-1024",
        )
    with pytest.raises(IssueError, match="64"):
        issue_certificate(issuer_cert, issuer_key, Profile.server, "a" * 65, ["DNS:x.lan"])
    with pytest.raises(IssueError, match="control"):
        issue_certificate(issuer_cert, issuer_key, Profile.server, "bad\x00cn", ["DNS:x.lan"])


# --- FR-2/AC-2: CSR signing ---------------------------------------------------


def test_sign_csr_preserves_sans(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    csr_pem = _csr(
        "app.lan",
        sans=[
            x509.DNSName("app.lan"),
            x509.IPAddress(ipaddress.ip_address("192.168.1.10")),
        ],
    )
    cert = sign_csr(issuer_cert, issuer_key, csr_pem, Profile.server, days=60)

    assert cert.subject.rfc4514_string() == "CN=app.lan"
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["app.lan"]
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("192.168.1.10")]
    cert.verify_directly_issued_by(issuer_cert)


def test_sign_csr_override_sans_win(issuer: Issuer) -> None:
    """FR-3: an explicit override replaces the CSR's SANs entirely."""
    issuer_cert, issuer_key = issuer
    csr_pem = _csr("app.lan", sans=[x509.DNSName("app.lan")])
    cert = sign_csr(
        issuer_cert,
        issuer_key,
        csr_pem,
        Profile.server,
        sans_override=["DNS:other.lan"],
    )
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["other.lan"]


def test_sign_csr_blocks_extension_smuggling(issuer: Issuer) -> None:
    """AC-2: a hostile CSR asking for CA:true / keyCertSign / an extra EKU
    must produce an ordinary leaf without any of it."""
    issuer_cert, issuer_key = issuer
    csr_pem = _csr(
        "evil.lan",
        sans=[x509.DNSName("evil.lan")],
        extra=[
            (x509.BasicConstraints(ca=True, path_length=3), True),
            (
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            ),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False),
        ],
    )
    cert = sign_csr(issuer_cert, issuer_key, csr_pem, Profile.server)

    basic_constraints = _extension(cert, x509.BasicConstraints).value
    assert basic_constraints.ca is False
    assert basic_constraints.path_length is None
    key_usage = _extension(cert, x509.KeyUsage).value
    assert key_usage.key_cert_sign is False
    assert key_usage.crl_sign is False
    assert list(_extension(cert, x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]
    # the SAN -- the one extension we do copy -- survived
    assert _extension(cert, x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ["evil.lan"]


def test_sign_csr_rejects_bad_signature(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.load_pem_x509_csr(_csr("tampered.lan", sans=[x509.DNSName("tampered.lan")], key=key))
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0xFF  # flip a byte of the RSA signature, structure untouched
    tampered_pem = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)

    with pytest.raises(IssueError, match="signature"):
        sign_csr(issuer_cert, issuer_key, tampered_pem, Profile.server)


def test_sign_csr_rejects_invalid_pem(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    with pytest.raises(IssueError, match="PEM"):
        sign_csr(
            issuer_cert,
            issuer_key,
            b"-----BEGIN CERTIFICATE REQUEST-----\nnope\n",
            Profile.server,
        )


def test_sign_csr_requires_subject_cn(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    with pytest.raises(IssueError, match="common name"):
        sign_csr(
            issuer_cert,
            issuer_key,
            _csr(None, sans=[x509.DNSName("x.lan")]),
            Profile.server,
        )


# --- FR-3/AC-3: SAN policy ----------------------------------------------------


def test_san_fallback_cn_dns(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    cert, _key = issue_certificate(issuer_cert, issuer_key, Profile.server, "printer.lan", [])
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["printer.lan"]

    # same ladder for a CSR without any SAN extension
    csr_cert = sign_csr(issuer_cert, issuer_key, _csr("plain.lan"), Profile.server)
    assert _extension(csr_cert, x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName
    ) == ["plain.lan"]


def test_san_fallback_cn_ip(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    cert, _key = issue_certificate(issuer_cert, issuer_key, Profile.server, "10.0.0.5", [])
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("10.0.0.5")]
    assert san.get_values_for_type(x509.DNSName) == []


def test_san_missing_errors(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    with pytest.raises(IssueError, match="no usable SAN"):
        issue_certificate(issuer_cert, issuer_key, Profile.server, "Thomas' Laptop", [])


def test_parse_san_lines_normalizes_and_validates() -> None:
    parsed = parse_san_lines(
        "dns:nas.lan\n10.0.0.5\n\n  IP: 192.168.0.1 \nadmin@lan\nEMAIL:ops@lan\n*.apps.lan"
    )
    assert parsed == [
        "DNS:nas.lan",
        "IP:10.0.0.5",
        "IP:192.168.0.1",
        "EMAIL:admin@lan",
        "EMAIL:ops@lan",
        "DNS:*.apps.lan",
    ]
    assert parse_san_lines("   \n\n") == []

    with pytest.raises(IssueError, match="hostname"):
        parse_san_lines("not a hostname")
    with pytest.raises(IssueError, match="IP"):
        parse_san_lines("ip:999.1.1.1")


def test_parse_profile() -> None:
    assert parse_profile("server") is Profile.server
    assert parse_profile("client") is Profile.client
    with pytest.raises(IssueError, match="profile"):
        parse_profile("wildcard")


# --- FR-4/AC-4: validity ------------------------------------------------------


def test_days_clamped_to_ca() -> None:
    """AC-4: an in-range request that would outlive the intermediate is cut
    back to the intermediate's own expiry -- here 3000 days against a CA
    with one year left. (Out-of-range days are a validation error instead,
    see test_days_range_validated.)"""
    root_cert, root_key = create_root("Clamp Root CA", "ecdsa-p256", years=2)
    issuer_cert, issuer_key = create_intermediate(
        root_cert, root_key, "Clamp Intermediate CA", "ecdsa-p256", years=1
    )

    cert, _key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.server,
        "clamp.lan",
        ["DNS:clamp.lan"],
        days=3000,
    )
    assert cert.not_valid_after_utc == issuer_cert.not_valid_after_utc

    short, _short_key = issue_certificate(
        issuer_cert, issuer_key, Profile.server, "short.lan", ["DNS:short.lan"], days=30
    )
    expected = datetime.now(UTC) + timedelta(days=30)
    assert abs((short.not_valid_after_utc - expected).total_seconds()) < 60

    csr_cert = sign_csr(
        issuer_cert,
        issuer_key,
        _csr("csrclamp.lan", sans=[x509.DNSName("csrclamp.lan")]),
        Profile.server,
        days=3000,
    )
    assert csr_cert.not_valid_after_utc == issuer_cert.not_valid_after_utc


def test_days_range_validated(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    for days in (0, 4000, -1):
        with pytest.raises(IssueError, match=f"{MIN_DAYS}.*{MAX_DAYS}"):
            issue_certificate(
                issuer_cert,
                issuer_key,
                Profile.server,
                "d.lan",
                ["DNS:d.lan"],
                days=days,
            )
        with pytest.raises(IssueError, match=f"{MIN_DAYS}.*{MAX_DAYS}"):
            sign_csr(
                issuer_cert,
                issuer_key,
                _csr("d.lan", sans=[x509.DNSName("d.lan")]),
                Profile.server,
                days=days,
            )


# --- FR-3: a CSR's SANs face the same policy as form input ------------------


@pytest.mark.parametrize(
    "name",
    [
        x509.DNSName(""),
        x509.DNSName("not a hostname!"),
        x509.DNSName("a.*.evil.lan"),
        x509.DNSName("*"),
        x509.DNSName("x" * 300),
        x509.DNSName(f"{'l' * 64}.lan"),
        x509.RFC822Name("no-at-sign"),
    ],
)
def test_sign_csr_rejects_malformed_csr_sans(issuer: Issuer, name: x509.GeneralName) -> None:
    """A CSR must not be a way around the SAN policy: whatever a form entry
    would be rejected for, a CSR entry is rejected for too -- loudly, not by
    silently dropping the entry."""
    issuer_cert, issuer_key = issuer
    with pytest.raises(IssueError):
        sign_csr(issuer_cert, issuer_key, _csr("evil.lan", sans=[name]), Profile.server)


def test_sign_csr_rejects_ip_network_san(issuer: Issuer) -> None:
    """x509.IPAddress legally holds a *network*; that must be a clean
    IssueError, not a bare ValueError escaping as a 500."""
    issuer_cert, issuer_key = issuer
    csr_pem = _csr("net.lan", sans=[x509.IPAddress(ipaddress.ip_network("10.0.0.0/24"))])
    with pytest.raises(IssueError, match="IP"):
        sign_csr(issuer_cert, issuer_key, csr_pem, Profile.server)


def test_sans_are_deduplicated(issuer: Issuer) -> None:
    """The same name written two ways must not end up in the certificate
    twice -- the stored SAN list would then disagree with the certificate."""
    issuer_cert, issuer_key = issuer
    cert, _key = issue_certificate(
        issuer_cert,
        issuer_key,
        Profile.server,
        "nas.lan",
        ["nas.lan", "dns:nas.lan", "DNS:nas.lan"],
    )
    san = _extension(cert, x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["nas.lan"]


def test_san_count_capped(issuer: Issuer) -> None:
    issuer_cert, issuer_key = issuer
    too_many = [f"DNS:host{index}.lan" for index in range(MAX_SANS + 1)]
    with pytest.raises(IssueError, match=str(MAX_SANS)):
        issue_certificate(issuer_cert, issuer_key, Profile.server, "nas.lan", too_many)

    just_enough = too_many[:MAX_SANS]
    cert, _key = issue_certificate(issuer_cert, issuer_key, Profile.server, "nas.lan", just_enough)
    assert len(_extension(cert, x509.SubjectAlternativeName).value) == MAX_SANS


def test_hostname_label_length_limit() -> None:
    assert parse_san_lines(f"{'l' * 63}.lan") == [f"DNS:{'l' * 63}.lan"]
    with pytest.raises(IssueError, match="hostname"):
        parse_san_lines(f"{'l' * 64}.lan")


def test_expired_signing_ca_errors() -> None:
    """Nothing can be issued under a CA whose own certificate has run out:
    the clamp would produce notAfter <= notBefore."""
    now = datetime.now(UTC)
    issuer_cert, issuer_key = _custom_intermediate(not_after=now - timedelta(days=1))
    with pytest.raises(IssueError, match="expired"):
        issue_certificate(issuer_cert, issuer_key, Profile.server, "late.lan", ["DNS:late.lan"])
    with pytest.raises(IssueError, match="expired"):
        sign_csr(
            issuer_cert,
            issuer_key,
            _csr("late.lan", sans=[x509.DNSName("late.lan")]),
            Profile.server,
        )
