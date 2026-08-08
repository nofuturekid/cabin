"""Tests for spec 0020 (name constraints): the matching rules and the
crypto layer -- ``cabin.ca.leaf``'s ``NameConstraintSpec``,
``parse_name_constraints``, ``name_constraints_extension``,
``constraints_of`` and ``check_name_constraints``, plus ``cabin.ca.x509``'s
``create_intermediate``/``create_root``/``renew_certificate`` handling of
the extension, and the schema claim that nothing is stored outside the
certificate (AC-9).

Enforcement *reaching* every issuance door lives in
``tests/test_name_constraints_doors.py`` -- this file is everything that can
be measured without an HTTP client: ``check_name_constraints`` is a pure
function of a certificate and a name list (Interface Contract), so a
matching bug belongs here, where it is cheap to find, rather than behind six
doors where it is expensive to find.

None of the names imported from ``cabin.ca.leaf`` below exist on disk yet --
this branch is red by design (spec 0020 has no implementation). Following
the technique ``tests/test_tls.py`` and ``tests/test_issuer_permissions.py``
already use for the same reason: the *module* is imported (``leaf_mod``),
never the not-yet-real names directly, so a missing symbol is an
``AttributeError``/``TypeError`` inside the one test that touches it rather
than a single collection error that swallows every other test's more
specific answer. Names that already exist today (``IssueError``,
``create_intermediate``, ``create_root``, ``renew_certificate``, ...) are
imported directly, since only their *signatures* change.

``openssl verify -CAfile`` does not check the self-signature of what it is
handed -- it is a trust anchor, not something examined. Every assertion here
about what a certificate's ``NameConstraints`` extension actually contains
uses ``cryptography`` directly against the parsed certificate.
"""

from collections.abc import Iterator
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path

import pytest
from cryptography import x509
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from cabin.ca import leaf as leaf_mod
from cabin.ca import service as ca_service
from cabin.ca.leaf import IssueError
from cabin.ca.x509 import create_intermediate, create_root, renew_certificate
from cabin.secrets import SecretStore
from cabin.store import create_session_factory, run_migrations

# --- fixtures (DB, for the service-layer wiring + schema tests only) ---------


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Session]:
    db_url = f"sqlite:///{tmp_path}/cabin.db"
    run_migrations(db_url)
    factory = create_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def secrets(tmp_path: Path) -> SecretStore:
    return SecretStore.open(tmp_path, None)


# --- helpers -------------------------------------------------------------------


def _spec(
    *,
    permitted_dns: tuple[str, ...] = (),
    permitted_ip: tuple[IPv4Network | IPv6Network, ...] = (),
    excluded_dns: tuple[str, ...] = (),
    excluded_ip: tuple[IPv4Network | IPv6Network, ...] = (),
) -> "leaf_mod.NameConstraintSpec":
    return leaf_mod.NameConstraintSpec(
        permitted_dns=permitted_dns,
        permitted_ip=permitted_ip,
        excluded_dns=excluded_dns,
        excluded_ip=excluded_ip,
    )


def _issuer(
    *,
    permitted_dns: tuple[str, ...] = (),
    permitted_ip: tuple[IPv4Network | IPv6Network, ...] = (),
    excluded_dns: tuple[str, ...] = (),
    excluded_ip: tuple[IPv4Network | IPv6Network, ...] = (),
    name_constraints: x509.NameConstraints | None = None,
    name: str = "Constrained",
) -> x509.Certificate:
    """An intermediate certificate carrying exactly the given constraints,
    never through the database -- ``check_name_constraints`` is a pure
    function of a certificate. ``name_constraints`` overrides the spec-built
    extension entirely, for the one case ``name_constraints_extension``
    cannot produce: an imported certificate carrying a form spec 0020 does
    not implement (FR-5 rule 8), e.g. ``rfc822Name``.
    """
    root_cert, root_key = create_root(f"{name} Root CA", "ecdsa-p256")
    extension = (
        name_constraints
        if name_constraints is not None
        else leaf_mod.name_constraints_extension(
            _spec(
                permitted_dns=permitted_dns,
                permitted_ip=permitted_ip,
                excluded_dns=excluded_dns,
                excluded_ip=excluded_ip,
            )
        )
    )
    intermediate_cert, _key = create_intermediate(
        root_cert,
        root_key,
        f"{name} Intermediate CA",
        "ecdsa-p256",
        name_constraints=extension,
    )
    return intermediate_cert


def _extension[T: x509.ExtensionType](cert: x509.Certificate, cls: type[T]) -> x509.Extension[T]:
    return cert.extensions.get_extension_for_class(cls)


def _no_name_constraints(cert: x509.Certificate) -> None:
    with pytest.raises(x509.ExtensionNotFound):
        _extension(cert, x509.NameConstraints)


def _check(cert: x509.Certificate, subject_cn: str | None, sans: list[str]) -> None:
    leaf_mod.check_name_constraints(cert, subject_cn, sans)


def _refused(cert: x509.Certificate, subject_cn: str | None, sans: list[str]) -> str:
    with pytest.raises(leaf_mod.NameConstraintError) as excinfo:
        _check(cert, subject_cn, sans)
    return str(excinfo.value)


# === NameConstraintSpec =========================================================


def test_name_constraint_spec_is_empty() -> None:
    assert leaf_mod.NameConstraintSpec().is_empty() is True
    assert _spec(permitted_dns=("example.com",)).is_empty() is False
    assert _spec(permitted_ip=(ip_network("10.0.0.0/8"),)).is_empty() is False
    assert _spec(excluded_dns=("example.com",)).is_empty() is False
    assert _spec(excluded_ip=(ip_network("10.0.0.0/8"),)).is_empty() is False


def test_constraint_error_is_an_issue_error_subclass() -> None:
    """FR-8: a subclass, not a sibling -- every existing door that already
    catches ``IssueError`` handles this with no change at all."""
    assert issubclass(leaf_mod.NameConstraintError, IssueError)


# === FR-3: parse_name_constraints ===============================================


def test_parse_name_constraints_dns_entry() -> None:
    spec = leaf_mod.parse_name_constraints("example.com", "")
    assert spec.permitted_dns == ("example.com",)
    assert spec.permitted_ip == ()
    assert spec.excluded_dns == ()


def test_parse_name_constraints_dns_entries_are_lower_cased() -> None:
    spec = leaf_mod.parse_name_constraints("EXAMPLE.com", "Other.EXAMPLE.com")
    assert spec.permitted_dns == ("example.com",)
    assert spec.excluded_dns == ("other.example.com",)


def test_parse_name_constraints_leading_dot_equals_bare_name() -> None:
    """The leading-dot spelling common in OpenSSL configuration is accepted
    and produces the exact same constraint as writing the hostname bare."""
    with_dot = leaf_mod.parse_name_constraints(".example.com", "")
    bare = leaf_mod.parse_name_constraints("example.com", "")
    assert with_dot == bare


def test_parse_name_constraints_bare_ip_becomes_a_host_network() -> None:
    spec = leaf_mod.parse_name_constraints("10.0.0.5\n2001:db8::1", "")
    assert spec.permitted_ip == (ip_network("10.0.0.5/32"), ip_network("2001:db8::1/128"))


def test_parse_name_constraints_explicit_cidr_is_preserved() -> None:
    spec = leaf_mod.parse_name_constraints("10.0.0.0/8", "")
    assert spec.permitted_ip == (ip_network("10.0.0.0/8"),)


def test_parse_name_constraints_host_bits_set_is_refused_not_widened() -> None:
    """``ipaddress.ip_network(..., strict=False)`` would silently widen
    ``10.1.2.3/8`` to ``10.0.0.0/8`` -- an order of magnitude wider than what
    was typed. FR-3 refuses it instead."""
    with pytest.raises(leaf_mod.NameConstraintError, match=r"10\.1\.2\.3/8"):
        leaf_mod.parse_name_constraints("10.1.2.3/8", "")


def test_parse_name_constraints_wildcard_is_refused() -> None:
    with pytest.raises(leaf_mod.NameConstraintError, match=r"\*\.example\.com"):
        leaf_mod.parse_name_constraints("*.example.com", "")


def test_parse_name_constraints_not_a_hostname_is_refused() -> None:
    with pytest.raises(leaf_mod.NameConstraintError, match="not a hostname"):
        leaf_mod.parse_name_constraints("not a hostname", "")


def test_parse_name_constraints_empty_entry_is_refused() -> None:
    """A stray blank-but-not-whitespace line -- here, a bare leading dot
    with nothing else -- must not become an empty dNSName constraint, which
    would match every name and turn a restriction into its opposite."""
    with pytest.raises(leaf_mod.NameConstraintError):
        leaf_mod.parse_name_constraints(".", "")


def test_parse_name_constraints_blank_lines_are_ignored() -> None:
    spec = leaf_mod.parse_name_constraints("example.com\n\n   \n", "")
    assert spec.permitted_dns == ("example.com",)
    assert leaf_mod.parse_name_constraints("   \n\n", "   \n") == leaf_mod.NameConstraintSpec()


def test_parse_name_constraints_too_many_entries_is_refused() -> None:
    just_enough = "\n".join(f"h{i}.example.com" for i in range(leaf_mod.MAX_NAME_CONSTRAINTS))
    spec = leaf_mod.parse_name_constraints(just_enough, "")
    assert len(spec.permitted_dns) == leaf_mod.MAX_NAME_CONSTRAINTS

    one_too_many = f"{just_enough}\nh999.example.com"
    with pytest.raises(leaf_mod.NameConstraintError, match=str(leaf_mod.MAX_NAME_CONSTRAINTS)):
        leaf_mod.parse_name_constraints(one_too_many, "")


def test_parse_name_constraints_caps_each_side_independently() -> None:
    """50 permitted AND 50 excluded in the same call is fine -- the cap is
    per side, not a combined total."""
    permitted = "\n".join(f"p{i}.example.com" for i in range(leaf_mod.MAX_NAME_CONSTRAINTS))
    excluded = "\n".join(f"e{i}.example.com" for i in range(leaf_mod.MAX_NAME_CONSTRAINTS))
    spec = leaf_mod.parse_name_constraints(permitted, excluded)
    assert len(spec.permitted_dns) == leaf_mod.MAX_NAME_CONSTRAINTS
    assert len(spec.excluded_dns) == leaf_mod.MAX_NAME_CONSTRAINTS


def test_parse_name_constraints_message_names_the_offending_line() -> None:
    with pytest.raises(leaf_mod.NameConstraintError) as excinfo:
        leaf_mod.parse_name_constraints("good.example.com\nbad hostname here", "")
    assert "bad hostname here" in str(excinfo.value)


# === FR-2: name_constraints_extension ===========================================


def test_empty_spec_writes_no_extension_rather_than_an_empty_one() -> None:
    assert leaf_mod.name_constraints_extension(leaf_mod.NameConstraintSpec()) is None


def test_permitted_subtrees_is_none_not_empty_list_when_only_excluded_is_given() -> None:
    extension = leaf_mod.name_constraints_extension(_spec(excluded_dns=("example.com",)))
    assert extension is not None
    assert extension.permitted_subtrees is None
    assert extension.excluded_subtrees == [x509.DNSName("example.com")]


def test_excluded_subtrees_is_none_not_empty_list_when_only_permitted_is_given() -> None:
    extension = leaf_mod.name_constraints_extension(_spec(permitted_dns=("example.com",)))
    assert extension is not None
    assert extension.excluded_subtrees is None
    assert extension.permitted_subtrees == [x509.DNSName("example.com")]


def test_name_constraints_extension_carries_dns_and_ip_subtrees() -> None:
    extension = leaf_mod.name_constraints_extension(
        _spec(
            permitted_dns=("example.com",),
            permitted_ip=(ip_network("10.0.0.0/8"),),
            excluded_dns=("secret.example.com",),
            excluded_ip=(ip_network("192.168.0.0/16"),),
        )
    )
    assert extension is not None
    assert extension.permitted_subtrees == [
        x509.DNSName("example.com"),
        x509.IPAddress(ip_network("10.0.0.0/8")),
    ]
    assert extension.excluded_subtrees == [
        x509.DNSName("secret.example.com"),
        x509.IPAddress(ip_network("192.168.0.0/16")),
    ]


def test_ip_subtree_holds_a_network_not_a_bare_address() -> None:
    """A bare address would encode to half the required DER length -- the
    IPAddress general name in a NameConstraints subtree MUST hold a network
    (RFC 5280 4.2.1.10)."""
    extension = leaf_mod.name_constraints_extension(
        _spec(permitted_ip=(ip_network("10.0.0.5/32"),))
    )
    assert extension is not None
    assert isinstance(extension.permitted_subtrees, list)
    ip_name = extension.permitted_subtrees[0]
    assert isinstance(ip_name, x509.IPAddress)
    assert isinstance(ip_name.value, IPv4Network)


# === AC-1/AC-9: the extension on a real certificate, read with cryptography ====
# ``openssl verify -CAfile`` never examines what it is handed as a trust
# anchor -- every assertion below parses ``cert_pem`` with ``cryptography``.


def test_intermediate_carries_a_critical_name_constraints_extension() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    extension = _extension(cert, x509.NameConstraints)
    assert extension.critical is True
    assert extension.value.permitted_subtrees == [x509.DNSName("example.com")]
    assert extension.value.excluded_subtrees is None


def test_unconstrained_intermediate_carries_no_such_extension() -> None:
    """``None`` and an empty spec both mean 'no constraints' -- absence, not
    an empty extension (RFC 5280 forbids one with both sides absent)."""
    root_cert, root_key = create_root("Plain Root CA", "ecdsa-p256")
    unconstrained, _key = create_intermediate(
        root_cert, root_key, "Plain Intermediate CA", "ecdsa-p256"
    )
    _no_name_constraints(unconstrained)

    also_unconstrained, _key2 = create_intermediate(
        root_cert, root_key, "Plain Intermediate CA 2", "ecdsa-p256", name_constraints=None
    )
    _no_name_constraints(also_unconstrained)


def test_root_never_carries_name_constraints() -> None:
    """``create_root`` takes no constraint argument at all -- a root does
    not sign leaves in cabin, so a constraint on it would only ever be
    evaluated by somebody else's validator."""
    import inspect

    assert "name_constraints" not in inspect.signature(create_root).parameters

    root_cert, _key = create_root("Unconstrained-by-design Root CA", "ecdsa-p256")
    _no_name_constraints(root_cert)


# === constraints_of: the one reader =============================================


def test_constraints_of_round_trips_dns_and_ip() -> None:
    cert = _issuer(
        permitted_dns=("example.com",),
        permitted_ip=(ip_network("10.0.0.0/8"),),
        excluded_dns=("secret.example.com",),
        excluded_ip=(ip_network("2001:db8::/32"),),
    )
    read_back = leaf_mod.constraints_of(cert)
    assert set(read_back.permitted_dns) == {"example.com"}
    assert set(read_back.permitted_ip) == {ip_network("10.0.0.0/8")}
    assert set(read_back.excluded_dns) == {"secret.example.com"}
    assert set(read_back.excluded_ip) == {ip_network("2001:db8::/32")}


def test_constraints_of_on_an_unconstrained_certificate_is_empty() -> None:
    root_cert, root_key = create_root("Reader Root CA", "ecdsa-p256")
    cert, _key = create_intermediate(root_cert, root_key, "Reader Intermediate CA", "ecdsa-p256")
    assert leaf_mod.constraints_of(cert).is_empty() is True


# === FR-6: renew_certificate carries the extension over, unchanged =============


def test_renewal_keeps_the_extension_bytes_identical() -> None:
    """AC-8, compared structurally through ``cryptography`` -- not a chain
    check, which cannot see any part of this criterion (a broken
    ``renew_in_place`` that dropped every extension still verifies against
    its parent)."""
    root_cert, root_key = create_root("Renew NC Root CA", "ecdsa-p256")
    cert, _key = create_intermediate(
        root_cert,
        root_key,
        "Renew NC Intermediate CA",
        "ecdsa-p256",
        name_constraints=leaf_mod.name_constraints_extension(
            _spec(permitted_dns=("example.com",), excluded_ip=(ip_network("::/0"),))
        ),
    )
    before = _extension(cert, x509.NameConstraints)

    # create_intermediate's default validity is 10 years (cabin.ca.x509's own
    # default) -- renewing for 12 must land later than that, not earlier, or
    # the assertion below could never hold no matter what renew_certificate
    # does.
    renewed = renew_certificate(cert, root_cert, root_key, years=12)

    after = _extension(renewed, x509.NameConstraints)
    assert after.critical is True
    assert after.value.permitted_subtrees == before.value.permitted_subtrees
    assert after.value.excluded_subtrees == before.value.excluded_subtrees
    # what actually changed -- proving this is a genuine renewal, not a
    # no-op that merely returned the same object.
    assert renewed.serial_number != cert.serial_number
    assert renewed.not_valid_after_utc > cert.not_valid_after_utc


def test_renewal_of_an_unconstrained_issuer_adds_no_extension() -> None:
    """The counter-check: renewal must not *invent* a constraint that was
    never there, any more than it may drop one that was."""
    root_cert, root_key = create_root("Renew Plain Root CA", "ecdsa-p256")
    cert, _key = create_intermediate(
        root_cert, root_key, "Renew Plain Intermediate CA", "ecdsa-p256"
    )
    renewed = renew_certificate(cert, root_cert, root_key, years=5)
    _no_name_constraints(renewed)


# === service-layer wiring: both creation paths (FR-1) ===========================


def test_create_hierarchy_applies_constraints_to_the_intermediate(
    db: Session, secrets: SecretStore
) -> None:
    """FR-1: ``create_hierarchy`` builds root and intermediate together, and
    only the intermediate may carry the constraint -- the root stays
    unconstrained even though the same call asked for it."""
    hierarchy = ca_service.create_hierarchy(
        db,
        secrets,
        "Wired",
        constraints=_spec(permitted_dns=("example.com",)),
    )
    intermediate_cert = x509.load_pem_x509_certificate(
        hierarchy.intermediate.cert_pem.encode("ascii")
    )
    extension = _extension(intermediate_cert, x509.NameConstraints)
    assert extension.critical is True
    assert extension.value.permitted_subtrees == [x509.DNSName("example.com")]

    root_cert = x509.load_pem_x509_certificate(hierarchy.root.cert_pem.encode("ascii"))
    _no_name_constraints(root_cert)


def test_create_hierarchy_without_constraints_is_unconstrained(
    db: Session, secrets: SecretStore
) -> None:
    hierarchy = ca_service.create_hierarchy(db, secrets, "Default")
    intermediate_cert = x509.load_pem_x509_certificate(
        hierarchy.intermediate.cert_pem.encode("ascii")
    )
    _no_name_constraints(intermediate_cert)


def test_create_intermediate_under_applies_constraints(db: Session, secrets: SecretStore) -> None:
    """FR-1: the rotation path (0017) gains the same parameter -- the only
    other way to add a further intermediate."""
    base = ca_service.create_hierarchy(db, secrets, "Rotation Base")
    row = ca_service.create_intermediate_under(
        db,
        secrets,
        base.root.id,
        "Rotated",
        constraints=_spec(excluded_dns=("lab.internal",)),
    )
    rotated_cert = x509.load_pem_x509_certificate(row.cert_pem.encode("ascii"))
    extension = _extension(rotated_cert, x509.NameConstraints)
    assert extension.critical is True
    assert extension.value.excluded_subtrees == [x509.DNSName("lab.internal")]
    assert extension.value.permitted_subtrees is None


# === AC-9: nothing is stored outside the certificate ============================


def test_no_constraint_column_exists_in_the_migrated_schema(db: Session) -> None:
    """Against the schema a fresh database migrates to -- not the
    migrations' source text. ``ca_certificates`` gains no column,
    ``certificates`` gains no column, and the chain still ends at 0010."""
    inspector = inspect(db.get_bind())
    ca_columns = {col["name"] for col in inspector.get_columns("ca_certificates")}
    assert ca_columns == {
        "id",
        "kind",
        "name",
        "parent_id",
        "status",
        "cert_pem",
        "key_sealed",
        "created_at",
    }, ca_columns

    cert_columns = {col["name"] for col in inspector.get_columns("certificates")}
    assert not any(
        "constraint" in name or "permitted" in name or "excluded" in name for name in cert_columns
    ), cert_columns

    versions_dir = (
        Path(__file__).parent.parent / "src" / "cabin" / "store" / "migrations" / "versions"
    )
    revisions = {p.stem.split("_", 1)[0] for p in versions_dir.glob("00*.py")}
    assert "0011" not in revisions, revisions
    assert "0010" in revisions, revisions


# === FR-5: the matching rules ====================================================
# The bulk of this file. Each rule below is a separate test with its own
# counter-case, per the spec's own framing: every one of these is a
# one-line mistake that leaves the feature looking like it works.


# --- rule 4/5: DNS matching is by label boundary, case-insensitive, and a
#     wildcard label is an ordinary label ----------------------------------------


def test_dns_constraint_covers_the_name_itself() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, None, ["DNS:example.com"])


def test_dns_constraint_covers_subdomains() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, None, ["DNS:a.example.com"])
    _check(cert, None, ["DNS:a.b.example.com"])


def test_dns_constraint_does_not_cover_a_longer_label() -> None:
    """The classic mistake: ``name.endswith(constraint)`` would let
    ``badexample.com`` through because it ends with ``example.com``."""
    cert = _issuer(permitted_dns=("example.com",))
    for bad in ("badexample.com", "notexample.com", "example.como"):
        _refused(cert, None, [f"DNS:{bad}"])


def test_dns_constraint_does_not_cover_a_name_it_is_a_prefix_of() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _refused(cert, None, ["DNS:example.com.evil.net"])


def test_dns_matching_is_case_insensitive() -> None:
    """Both sides are lower-cased by the matcher itself, not only by the
    parser -- proven by putting the mixed case directly into the
    certificate's own constraint, bypassing ``parse_name_constraints``."""
    mixed_case_constraint = _issuer(
        name_constraints=x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("Example.COM")], excluded_subtrees=None
        )
    )
    _check(mixed_case_constraint, None, ["DNS:example.com"])

    lower_constraint = _issuer(permitted_dns=("example.com",))
    _check(lower_constraint, None, ["DNS:EXAMPLE.COM"])


def test_wildcard_san_is_inside_its_own_subtree() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, None, ["DNS:*.example.com"])


def test_wildcard_san_does_not_widen_the_match() -> None:
    """``*.com`` is outside ``example.com``: it does not end at a label
    boundary of it, whatever a naive suffix check might conclude."""
    cert = _issuer(permitted_dns=("example.com",))
    _refused(cert, None, ["DNS:*.com"])
    _refused(cert, None, ["DNS:com"])


# --- rule 2: an empty permitted set permits everything --------------------------


def test_empty_permitted_set_allows_everything() -> None:
    """An implementation that reads an empty permitted set as 'deny all'
    refuses everything and looks safe -- this is the test that catches it."""
    cert = _issuer(excluded_dns=("lab.internal",))
    _check(cert, None, ["DNS:anything.at.all.test"])
    _check(cert, None, ["DNS:another.completely.different.example"])


def test_excluded_only_issuer_is_a_blocklist() -> None:
    cert = _issuer(excluded_dns=("lab.internal",))
    _refused(cert, None, ["DNS:lab.internal"])
    _refused(cert, None, ["DNS:x.lab.internal"])
    _check(cert, None, ["DNS:not-lab.internal.example"])


# --- rule 3/6: restrictions apply per name form ---------------------------------


def test_dns_constraints_do_not_apply_to_ip_sans() -> None:
    """A DNS-only permitted set does not stop an IP address literal -- the
    iPAddress form is simply not constrained. This is also cabin agreeing
    with OpenSSL/Go/NSS (FR-7); a stricter matcher would refuse this."""
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, None, ["IP:10.9.9.9"])


def test_excluding_the_whole_address_space_stops_ip_sans() -> None:
    cert = _issuer(
        permitted_dns=("example.com",), excluded_ip=(ip_network("0.0.0.0/0"), ip_network("::/0"))
    )
    _refused(cert, None, ["IP:10.9.9.9"])
    _refused(cert, None, ["IP:2001:db8::1"])
    _check(cert, None, ["DNS:www.example.com"])


def test_ip_constraint_matches_inside_the_network() -> None:
    cert = _issuer(permitted_ip=(ip_network("10.0.0.0/8"), ip_network("2001:db8::/32")))
    _check(cert, None, ["IP:10.5.5.5"])
    _check(cert, None, ["IP:2001:db8::1"])


def test_ip_constraint_refuses_outside_the_network() -> None:
    """Compares containment in a real network, never address strings: a
    prefix-string match would wrongly accept 192.168.1.1 against a
    192.168.0.0/24 constraint."""
    cert = _issuer(permitted_ip=(ip_network("10.0.0.0/8"), ip_network("2001:db8::/32")))
    _refused(cert, None, ["IP:192.168.1.1"])
    _refused(cert, None, ["IP:2001:db9::1"])

    narrow = _issuer(permitted_ip=(ip_network("192.168.0.0/24"),))
    _check(narrow, None, ["IP:192.168.0.5"])
    _refused(narrow, None, ["IP:192.168.1.1"])


def test_ipv6_address_is_not_inside_an_ipv4_network() -> None:
    """The iPAddress form covers both families: a permitted set with only
    IPv4 networks still constrains the form, so an IPv6 address is refused
    -- not waved through because 'no IPv6 constraint exists'."""
    cert = _issuer(permitted_ip=(ip_network("10.0.0.0/8"),))
    _refused(cert, None, ["IP:2001:db8::1"])
    _check(cert, None, ["IP:10.1.2.3"])


# --- rule 1: excluded beats permitted --------------------------------------------


def test_excluded_beats_permitted() -> None:
    cert = _issuer(permitted_dns=("example.com",), excluded_dns=("secret.example.com",))
    _check(cert, None, ["DNS:www.example.com"])
    _refused(cert, None, ["DNS:secret.example.com"])
    _refused(cert, None, ["DNS:a.secret.example.com"])


def test_excluded_subtree_named_in_the_message() -> None:
    """FR-5 rule 9: the message names the offending name and the constraint
    it violated -- here the excluded subtree, not the permitted one, which
    is what would appear if the natural (wrong) loop order evaluated
    permitted first and reported that instead."""
    cert = _issuer(permitted_dns=("example.com",), excluded_dns=("secret.example.com",))
    message = _refused(cert, None, ["DNS:secret.example.com"])
    assert "secret.example.com" in message


# --- rule 7: the CN is checked exactly when a validator would check it ---------


def test_cn_is_checked_when_no_dns_san_is_present() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _refused(cert, "evil.other.lan", ["IP:10.0.0.1"])


def test_cn_is_not_checked_when_a_dns_san_is_present() -> None:
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, "evil.other.lan", ["DNS:www.example.com"])


def test_empty_subject_contributes_no_name() -> None:
    """``sign_csr``'s ``allow_empty_subject`` produces ``subject_cn=None`` --
    the matcher must not invent a name to check from that."""
    cert = _issuer(permitted_dns=("example.com",))
    _check(cert, None, ["IP:10.0.0.1"])


# --- rule 8: a name form cabin cannot evaluate is refused, not ignored ---------


def test_unevaluable_constraint_form_refuses_that_san_form() -> None:
    """An imported CA may legitimately carry an ``rfc822Name`` subtree --
    a form spec 0020 does not implement. cabin refuses a leaf carrying that
    same SAN form rather than silently treating the constraint as absent,
    while every form it DOES implement stays governed by its own rules."""
    cert = _issuer(
        name_constraints=x509.NameConstraints(
            permitted_subtrees=[x509.RFC822Name("ops@example.com")], excluded_subtrees=None
        )
    )
    _refused(cert, None, ["EMAIL:someone@example.com"])
    # dNSName is not restricted by this certificate at all (no dNSName
    # subtree present) -- the refusal above is about the EMAIL SAN
    # specifically, not a blanket "this issuer refuses everything".
    _check(cert, None, ["DNS:anything.test"])


# === FR-7: cabin's check and the extension it writes say the same thing =========


def test_check_agrees_with_the_extension_it_was_built_from() -> None:
    """A belt-and-braces test that the whole matching suite above is really
    exercising the same vocabulary ``name_constraints_extension`` writes:
    build a spec, write it into a certificate, and confirm both the positive
    and negative case the spec itself claims for it."""
    spec = _spec(permitted_dns=("internal.example",), excluded_dns=("secret.internal.example",))
    cert = _issuer(
        permitted_dns=spec.permitted_dns,
        excluded_dns=spec.excluded_dns,
    )
    _check(cert, None, ["DNS:app.internal.example"])
    _refused(cert, None, ["DNS:secret.internal.example"])
    _refused(cert, None, ["DNS:outside.example"])
