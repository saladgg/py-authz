"""Public model exports for ``django_authz.models``.

Import these directly from ``django_authz.models`` for convenience::

    from django_authz.models import Principal, IDToken, AccessToken, RelationTuple
"""

from django_authz.models.relations import RelationTuple
from django_authz.models.tokens import AccessToken, IDToken, Principal

__all__ = ["IDToken", "AccessToken", "Principal", "RelationTuple"]
