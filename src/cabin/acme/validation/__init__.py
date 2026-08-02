"""Challenge validation (spec 0011 FR-3, FR-7, FR-8): pick the method, run
it, and write down what happened.

**Where this runs.** From the challenge trigger route, as a FastAPI
``BackgroundTasks`` job (FR-3). BackgroundTasks rather than a bare
``asyncio.create_task``, for three reasons: the task is a synchronous
function, so Starlette runs it in the same worker threadpool as every other
database-touching path in cabin, and no async DB layer has to be invented
for it; a task attached to the response cannot start before the client has
been answered, which is exactly what FR-2 asks for; and its lifetime is
owned by the server rather than by a coroutine nobody holds a reference to.

**With a session of its own.** The request's session is closed by the time
this runs, so the task opens one from the app's factory and closes it in a
``finally``. It never touches the request's.

**And it cannot fail.** An exception escaping a background task would go
nowhere useful and -- worse -- leave the challenge in ``processing``, a
state no client can get out of, since re-triggering a processing challenge
is a no-op by FR-2. So every exit path here ends in ``valid`` or
``invalid``: an unexpected exception becomes a serverInternal problem
document on the challenge itself, and only a database that cannot be
written at all is left to the log -- which is also the only place in cabin
that logs, because it is the only code with no request to answer.

**One gap, stated plainly:** a process that is stopped *during* an attempt
leaves that challenge in ``processing`` with nothing running behind it, and
v1 has no reaper to sweep those up. The blast radius is one challenge of
one authorization: the client's remedy is another challenge type on the
same authorization, or a new order. A sweeper that fails challenges left
processing across a restart belongs with the retry policy that spec 0011
deliberately leaves out.
"""

import ipaddress
import logging
from typing import Any, Protocol

from sqlalchemy.orm import Session, sessionmaker

from cabin import audit
from cabin.acme import service
from cabin.acme.errors import AcmeError, ErrorType
from cabin.acme.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeChallenge,
    ChallengeStatus,
)
from cabin.acme.validation import dns01, http01, keyauth, tlsalpn01
from cabin.acme.validation.targets import VALIDATION_TIMEOUT, Attempt
from cabin.audit import SYSTEM_ACTOR, Actor, AuditAction, acme_actor
from cabin.settings import (
    ALLOW_PRIVATE_VALIDATION_TARGETS,
    DNS_RESOLVERS,
    get_flag,
    get_setting,
)

__all__ = ["VALIDATION_TIMEOUT", "Attempt", "validate_challenge"]

_log = logging.getLogger(__name__)


class Method(Protocol):
    """What each of the three validator modules provides: one function that
    either returns or raises an :class:`AcmeError` saying why not."""

    def validate(self, attempt: Attempt) -> None: ...


#: The one place a challenge type turns into code that runs (FR-3). The
#: modules are held rather than their functions, so the mapping stays a
#: mapping of *methods* and not a snapshot of three function objects.
VALIDATORS: dict[str, Method] = {
    "http-01": http01,
    "dns-01": dns01,
    "tls-alpn-01": tlsalpn01,
}


def validate_challenge(db_factory: sessionmaker[Session], challenge_id: str) -> None:
    """Run one validation attempt to a conclusion. Never raises."""
    try:
        db = db_factory()
    except Exception:  # pragma: no cover - only a broken engine gets here
        _log.exception("acme: could not open a session to validate challenge %s", challenge_id)
        return
    try:
        _attempt_validation(db, challenge_id)
    except Exception:  # pragma: no cover - the database itself is unusable
        _log.exception("acme: validating challenge %s failed to record a result", challenge_id)
    finally:
        db.close()


def _attempt_validation(db: Session, challenge_id: str) -> None:
    challenge = service.get_challenge(db, challenge_id)
    if challenge is None or challenge.status != ChallengeStatus.processing:
        # Someone else already finished it, or the row is gone: either way
        # there is nothing left here to decide.
        return
    authz = service.get_authorization(db, challenge.authz_id)
    if authz is None:  # pragma: no cover - a challenge always has its authz
        return
    account = _account_of(db, authz)
    try:
        _validator(challenge).validate(_attempt(db, challenge, authz, account))
    except AcmeError as error:
        _failed(db, challenge, authz, account, error)
    except Exception as exc:
        # Not "cannot happen": a validator talks to hostile input over a
        # network, and the client is owed an answer either way.
        _log.exception("acme: %s validation of challenge %s crashed", challenge.type, challenge.id)
        _failed(
            db,
            challenge,
            authz,
            account,
            AcmeError(
                ErrorType.server_internal,
                f"validation failed inside cabin: {type(exc).__name__}",
            ),
        )
    else:
        _succeeded(db, challenge, authz, account)


def _validator(challenge: AcmeChallenge) -> Method:
    method = VALIDATORS.get(challenge.type)
    if method is None:  # pragma: no cover - 0010 only ever creates known types
        raise AcmeError(
            ErrorType.server_internal,
            f"cabin cannot validate a {challenge.type} challenge"[:200],
        )
    return method


def _attempt(
    db: Session,
    challenge: AcmeChallenge,
    authz: AcmeAuthorization,
    account: AcmeAccount | None,
) -> Attempt:
    if account is None:  # pragma: no cover - every authorization has an owner
        raise AcmeError(ErrorType.server_internal, "this authorization has no account")
    return Attempt(
        identifier_type=authz.identifier_type,
        identifier_value=authz.identifier_value,
        token=challenge.token,
        key_authorization=keyauth.key_authorization(challenge.token, account.jwk_thumbprint),
        allow_private=get_flag(db, ALLOW_PRIVATE_VALIDATION_TARGETS, default=True),
        resolvers=_resolvers(db),
    )


def _account_of(db: Session, authz: AcmeAuthorization) -> AcmeAccount | None:
    """Whose order this authorization belongs to.

    Returns None rather than raising, and is called *outside* the guarded
    block below on purpose: an exception here would be the one path that
    leaves a challenge in ``processing``, which no client can get out of.
    A missing account is instead reported like any other failure -- see
    :func:`_actor`.
    """
    order = service.get_order(db, authz.order_id)
    return db.get(AcmeAccount, order.account_id) if order is not None else None


def _actor(account: AcmeAccount | None) -> Actor:
    if account is None:  # pragma: no cover - every authorization has an owner
        return SYSTEM_ACTOR
    return acme_actor(account.jwk_thumbprint)


def _resolvers(db: Session) -> tuple[str, ...]:
    """FR-5: the ``dns_resolvers`` setting, as addresses.

    A malformed entry is refused rather than skipped: quietly falling back
    to the system resolver would validate against a different view of DNS
    than the operator configured, which is the one thing this setting exists
    to prevent.
    """
    raw = (get_setting(db, DNS_RESOLVERS) or "").strip()
    resolvers: list[str] = []
    for entry in raw.split(","):
        candidate = entry.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise AcmeError(
                ErrorType.server_internal,
                "the dns_resolvers setting is not a list of IP addresses",
            ) from exc
        resolvers.append(candidate)
    return tuple(resolvers)


def _identifier(authz: AcmeAuthorization) -> str:
    return f"{authz.identifier_type}:{authz.identifier_value}"


def _client_problem(error: AcmeError, authz: AcmeAuthorization) -> dict[str, Any]:
    """The problem document that goes on the challenge, where the account
    that placed the order can read it.

    Everything is passed through except the *reason* a connection failed.
    "Connection refused" and "refused by policy" and "timed out" are three
    different answers about an address the client chose, and a redirect can
    aim an attempt at another host -- so an account holder could otherwise
    read cabin's view of an internal network off this field, one challenge
    at a time. The precise sentence is kept, in the audit log, for the
    operator who is entitled to it (FR-8).
    """
    problem = error.problem()
    if error.kind is ErrorType.connection:
        problem["detail"] = (
            f"cabin could not reach {authz.identifier_value!r} to validate this challenge"
        )
    return problem


def _succeeded(
    db: Session,
    challenge: AcmeChallenge,
    authz: AcmeAuthorization,
    account: AcmeAccount | None,
) -> None:
    service.record_challenge_success(db, challenge, authz)
    audit.record(
        db,
        _actor(account),
        AuditAction.acme_challenge_validated,
        summary=f"validated {challenge.type} challenge for {authz.identifier_value!r}",
        target_type="acme_challenge",
        target_id=challenge.id,
        detail={"identifier": _identifier(authz), "type": challenge.type},
    )


def _failed(
    db: Session,
    challenge: AcmeChallenge,
    authz: AcmeAuthorization,
    account: AcmeAccount | None,
    error: AcmeError,
) -> None:
    """FR-7: the challenge carries the problem document; the authorization
    stays pending, so the client can still prove the name another way."""
    service.record_challenge_failure(db, challenge, _client_problem(error, authz))
    audit.record(
        db,
        _actor(account),
        AuditAction.acme_challenge_failed,
        summary=f"{challenge.type} challenge for {authz.identifier_value!r} failed",
        target_type="acme_challenge",
        target_id=challenge.id,
        detail={
            "identifier": _identifier(authz),
            "type": challenge.type,
            "error": error.detail,
        },
    )
