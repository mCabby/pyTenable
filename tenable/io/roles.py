"""
Roles
=====

The following methods allow for interaction into the
Tenable Vulnerability Management Access Control Roles API endpoints.

Methods available on ``tio.roles``:

.. rst-class:: hide-signature
.. autoclass:: RolesAPI
    :members:
"""

from typing import Dict, List
from uuid import UUID
from tenable.io.base import TIOEndpoint
from tenable.utils import scrub

class RolesAPI(TIOEndpoint):
    _path = 'access-control/v1/roles'
    _box = True

    def list(self) -> List:
        """
        Lists all roles defined for the Tenable Vulnerability Management
        instance, including standard and custom roles.

        :devportal:`roles: list <access-control-roles-list>`

        Returns:
            :obj:`list`:
                List of role records.

        Examples:
            >>> for role in tio.roles.list():
            ...     print(role['name'])
        """
        return self._get()
    
    def details(self, role_uuid: UUID) -> Dict:
        """
        Retrieves the details of the specified role.
        
        :devportal:`roles: details <access-control-roles-details>`
        
        Args:
            role_uuid (str):
                The UUID of the role to retrieve.
                
        Returns:
            :obj:`dict`:
                The role record.
                
        Examples:
            >>> tio.roles.details(
            ...     'b2c3d4e5-f6a7-8901-bcde-f12345678901'
            ... )
        """
        return self._get(scrub(role_uuid))
    
    def create(self, name: str, role_permission_strings: List[str], description: str = None, type: str = 'CUSTOM', status: str = 'ENABLED') -> Dict:
        """
        Creates a new custom role.
        
        :devportal:`roles: create <access-control-roles-create>`
        
        Args:
            name (str):
                The name of the role.
            role_permission_strings (list):
                The role permission strings to assign to the role.
            description (str, optional):
                The description of the role.
            type (str, optional):
                The role type. For custom roles, use ``CUSTOM``.
            status (str, optional):
                The role status. Supported values are ``ENABLED`` and
                ``DISABLED``.

        Returns:
            :obj:`dict`:
                The resource record for the newly created role.

        Examples:
            >>> role = tio.roles.create(
            ...     'Security Analyst',
            ...     [
            ...         'VM.TOGGLE_VM.USE',
            ...         'VM.VM_EXPLORE.VM_EXPLORE.READ'
            ...     ],
            ...     description='Custom security analyst role'
            ... )
        """
        payload = {
            'name': name,
            'role_permission_strings': role_permission_strings,
            'type': type,
            'status': status
        }

        if description is not None:
            payload['description'] = description

        return self._post(json=payload)
    
    def update(self, role_uuid: UUID, name: str = None, description: str = None, role_permission_strings: List[str] = None, type: str = None, status: str = None) -> Dict:
        """
        Updates an existing custom role.

        :devportal:`roles: update <access-control-roles-update>`

        Args:
            role_uuid (str):
                The UUID of the role to update.
            name (str, optional):
                The updated name of the role.
            description (str, optional):
                The updated description of the role.
            role_permission_strings (list, optional):
                The role permission strings to assign to the role.
                This replaces the existing permission set.
            type (str, optional):
                The updated role type.
            status (str, optional):
                The updated role status. Supported values are
                ``ENABLED`` and ``DISABLED``.

        Returns:
            :obj:`dict`:
                The resource record for the updated role.

        Examples:
            Disable a custom role:

            >>> role = tio.roles.update(
            ...     'b2c3d4e5-f6a7-8901-bcde-f12345678901',
            ...     status='DISABLED'
            ... )
        """
        payload = {}

        if name is not None:
            payload['name'] = name
        if description is not None:
            payload['description'] = description
        if role_permission_strings is not None:
            payload['role_permission_strings'] = role_permission_strings
        if type is not None:
            payload['type'] = type
        if status is not None:
            payload['status'] = status

        return self._put(scrub(role_uuid), json=payload)
    
    def delete(self, role_uuid: UUID) -> None:
        """
        def delete(self, role_uuid: UUID) -> None:
        Deletes the specified custom role.

        :devportal:`roles: delete <access-control-roles-delete>`

        Args:
            role_uuid (str):
                The UUID of the role to delete.

        Examples:
            >>> tio.roles.delete(
            ...     'b2c3d4e5-f6a7-8901-bcde-f12345678901'
            ... )
        """
        self._delete(scrub(role_uuid))

    def permissions(self) -> List:
        """
        Lists all available role permission strings and their metadata.

        :devportal:`roles: list permissions
            <access-control-roles-list-permissions>`

        Returns:
            :obj:`list`:
                The available role permission records.

        Examples:
            >>> permissions = tio.roles.permissions()
        """
        return self._api.get(
            'access-control/v1/role-permissions'
        ).json()