"""Management command to sync relationship tuples into OpenFGA.

Usage::

    python manage.py sync_openfga

The command writes a set of relationship tuples to your configured OpenFGA
store.  By default it ships a single illustrative tuple; replace the
``get_policy_tuples()`` function body with your own registry logic.

Settings required (via ``DJANGO_AUTHZ``)::

    DJANGO_AUTHZ = {
        "OPENFGA_API_URL": "http://localhost:8080",
        "OPENFGA_STORE_ID": "<your-store-id>",
    }
"""

from django.core.management.base import BaseCommand, CommandError

from django_authz.authorization.openfga import OpenFGAClient
from django_authz.conf import CONFIG


def get_policy_tuples() -> list[dict]:
    """Return the list of relationship tuples to write to OpenFGA.

    Override or extend this function to define your own policy registry.
    Each tuple must have the keys ``user``, ``relation``, and ``object``.

    Example::

        return [
            {"user": "user:admin", "relation": "admin", "object": "project:*"},
            {"user": "user:alice", "relation": "reader", "object": "doc:42"},
        ]
    """
    return [
        {"user": "user:admin", "relation": "admin", "object": "project:*"},
    ]


class Command(BaseCommand):
    """Sync predefined policy tuples into the configured OpenFGA store."""

    help = "Writes predefined policy relationship tuples into the OpenFGA store."

    def handle(self, *args, **options):
        if not CONFIG.OPENFGA_API_URL or not CONFIG.OPENFGA_STORE_ID:
            raise CommandError(
                "OPENFGA_API_URL and OPENFGA_STORE_ID must be set in DJANGO_AUTHZ settings."
            )

        fga = OpenFGAClient(api_url=CONFIG.OPENFGA_API_URL, store_id=CONFIG.OPENFGA_STORE_ID)
        tuples = get_policy_tuples()

        if not tuples:
            self.stdout.write(self.style.WARNING("No policy tuples defined; nothing to sync."))
            return

        fga.write(tuples)
        self.stdout.write(
            self.style.SUCCESS(f"Successfully synced {len(tuples)} policy tuple(s) to OpenFGA.")
        )
