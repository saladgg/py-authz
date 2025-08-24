"""Management command to sync local policy definitions into OpenFGA."""

from django.core.management.base import BaseCommand
from drf_authz.authorization.openfga import OpenFGAClient


class Command(BaseCommand):
    help = "Syncs predefined policy tuples into OpenFGA store."

    def handle(self, *args, **options):
        fga = OpenFGAClient()
        # Example sync — replace with your own policy registry
        fga.add_tuple("user:admin", "admin", "project:*")
        self.stdout.write(self.style.SUCCESS("Successfully synced OpenFGA policies."))
