"""
Base classes and interfaces for OpenFGA authorization clients.

Common interface/base class (e.g. BaseOpenFGAClient) so that whether 
a project chooses REST or SDK, the higher-level DRF permissions/decorators 
don’t need to care which client is underneath?
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseOpenFGAClient(ABC):
    """
    Abstract base class for OpenFGA clients.

    Both the REST client (`openfga.py`) and the official SDK client
    (`openfga_sdk.py`) must implement this interface, ensuring they
    expose a consistent set of operations regardless of backend.
    """

    @abstractmethod
    def check(self, user: str, relation: str, object_: str) -> bool:
        """
        Check whether the given user has the specified relation on the object.

        Args:
            user: The subject/user performing the action.
            relation: The relation/action being checked.
            object_: The target object.

        Returns:
            True if authorized, False otherwise.
        """
        ...

    @abstractmethod
    def write(self, tuples: List[Dict[str, Any]]) -> None:
        """
        Write relationship tuples into the OpenFGA store.

        Args:
            tuples: List of relationship tuples to write, each
                represented as a dict containing 'user', 'relation',
                and 'object'.
        """
        ...

    @abstractmethod
    def list_relations(self, user: str, object_: str) -> List[str]:
        """
        List all relations that a given user has on an object.

        Args:
            user: The subject/user.
            object_: The target object.

        Returns:
            A list of relations the user holds for the object.
        """
        ...
