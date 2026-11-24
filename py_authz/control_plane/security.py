"""
Service-account credential hashing/verification (CP-3, CP-17).

This is the one place in the control-plane API — and in this library as
a whole — that authenticates a bearer secret directly against a stored
hash, rather than delegating to an IdP (that's `OIDCJWTValidator`'s job,
for operator logins). `argon2` is used deliberately, with parameters
picked rather than left at whatever the library's own default happens to
be, and a rotated/revoked secret's hash is never reused or recoverable.
"""

import re
import secrets

from py_authz.utils.deps import require_argon2

PasswordHasher, VerifyMismatchError = require_argon2()

#: Argon2id parameters, tuned deliberately (see CP-17) rather than left
#: at `argon2-cffi`'s own defaults. `memory_cost`/`parallelism` match
#: OWASP's current minimum-strength recommendation for Argon2id
#: (m=19 MiB, p=1); `time_cost=3` is one iteration above OWASP's stated
#: floor of 2, appropriate for a server-side credential check that runs
#: once per API call (not a hot path) rather than a login form submitted
#: by a human on every request — deliberately higher than `argon2-cffi`'s
#: own (lighter, general-purpose) default either way.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=19 * 1024,  # KiB
    parallelism=1,
)

#: Length (bytes of entropy, before base64url encoding) of a newly
#: generated service-account secret. 32 bytes = 256 bits, well above any
#: brute-force floor even before argon2's own cost factor is applied.
_SECRET_ENTROPY_BYTES = 32

#: Prefix on every generated secret — lets a secret accidentally leaked
#: into a log line or error message be recognized (and revoked) on sight,
#: the same convention GitHub/Stripe/AWS-style API tokens use.
SECRET_PREFIX = "pasa_"  # noqa: S105 — a prefix marker, not a credential itself


def generate_secret(account_id: str) -> str:
    """
    Generate a new, high-entropy service-account secret for `account_id`.

    The account id is embedded (`<prefix><account_id>.<random>`) so
    verifying a presented secret can look its row up directly (`SELECT
    ... WHERE id = $1`) instead of hashing it against every active
    account's `secret_hash` in turn — a lookup, not a linear scan, the
    same way an API-key-style credential (Stripe, GitHub) is normally
    shaped. This does not weaken the credential: `account_id` is not
    secret (it's returned by `GET /service-accounts` anyway), and the
    random suffix alone still carries the full entropy budget argon2
    verification is checked against.

    Returned to the caller exactly once — only `hash_secret()`'s output
    is ever persisted.
    """
    return f"{SECRET_PREFIX}{account_id}.{secrets.token_urlsafe(_SECRET_ENTROPY_BYTES)}"


#: Shape of a well-formed account id (`_new_id()` produces
#: `sa_<32 hex>`; the bound is looser to accept any id this store ever
#: issued). Anything else is rejected before touching the store or the
#: rate limiter (SEC3-9).
ACCOUNT_ID_PATTERN = re.compile(r"^sa_[A-Za-z0-9_-]{1,64}$")


class MalformedServiceAccountToken(ValueError):
    """The bearer has the service-account prefix but not its shape."""


def parse_account_id(secret: str) -> str | None:
    """
    Extract the `account_id` embedded by `generate_secret()`, or `None`
    if `secret` isn't shaped like a service-account secret at all (e.g.
    it's an operator's OIDC bearer token — the two are distinguished by
    this prefix before either verification path is attempted).

    Raises:
        MalformedServiceAccountToken: the token carries the prefix but its
            account id isn't well-formed (SEC3-9). Previously any string
            was accepted, looked up in Postgres, and recorded as a failed
            attempt under an attacker-chosen, unbounded key.
    """
    if not secret.startswith(SECRET_PREFIX):
        return None
    rest = secret[len(SECRET_PREFIX) :]
    account_id, sep, random_part = rest.partition(".")
    if not (sep and random_part and ACCOUNT_ID_PATTERN.fullmatch(account_id)):
        raise MalformedServiceAccountToken("malformed service-account token")
    return account_id


def hash_secret(secret: str) -> str:
    """Hash a secret for storage in `service_accounts.secret_hash`. Never
    store (or log) `secret` itself — only this hash."""
    return _HASHER.hash(secret)


def verify_secret(secret: str, secret_hash: str) -> bool:
    """
    Verify `secret` against a stored `secret_hash`.

    Returns `False` on any mismatch (including a malformed/foreign hash)
    rather than raising — a verification failure here is an expected,
    routine outcome (a wrong or revoked secret), not an error condition
    the caller needs to special-case.
    """
    try:
        return _HASHER.verify(secret_hash, secret)
    except VerifyMismatchError:
        return False
    except Exception:
        # A malformed hash (shouldn't happen against our own
        # `hash_secret()` output, but a corrupted row or a hash produced
        # by different parameters than `_HASHER`'s current ones raises a
        # different `argon2.exceptions` subclass, not `VerifyMismatchError`
        # specifically) is still just "doesn't verify", not a 500.
        return False
