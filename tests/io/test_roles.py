"""
This file contains tests for the Roles endpoints.
"""

import responses
import json

@responses.activate
def test_list(tvm):
    responses.add(
        responses.GET,
        'https://nourl/access-control/v1/roles',
        json=[
            {
                'name': 'Administrator',
                'uuid': 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                'description': 'Full administrative access.',
                'role_permission_strings': [
                    'PS.ACCT_MGMT.AM_ACCESS_CONTROL.CREATE',
                ],
                'type': 'STANDARD',
                'status': 'ENABLED'
            },
            {
                'name': 'Security Analyst',
                'uuid': 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
                'description': 'Custom security analyst role.',
                'role_permission_strings': [
                    'VM.TOGGLE_VM.USE',
                ],
                'type': 'CUSTOM',
                'status': 'ENABLED'
            },
        ],
    )

    roles = tvm.roles.list()
    assert isinstance(roles, list)

@responses.activate
def test_details(tvm):
    role_uuid = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    responses.add(
        responses.GET,
        f'https://nourl/access-control/v1/roles/{role_uuid}',
        json={
            'name': 'Security Analyst',
            'uuid': role_uuid,
            'description': 'Custom security analyst role.',
            'role_permission_strings': [
                'VM.TOGGLE_VM.USE',
            ],
            'type': 'CUSTOM',
            'status': 'ENABLED'
        },
    )
    role = tvm.roles.details(role_uuid)
    assert isinstance(role, dict)

@responses.activate
def test_create(tvm):
    responses.add(
        responses.POST,
        'https://nourl/access-control/v1/roles',
        json={
            'name': 'Security Analyst',
            'uuid': 'b2c3d4e5-f6a7-8901-bcde-f12345678901',
            'description': 'Custom security analyst role.',
            'role_permission_strings': [
                'VM.TOGGLE_VM.USE',
                'VM.VM_EXPLORE.VM_EXPLORE.READ'
            ],
            'type': 'CUSTOM',
            'status': 'ENABLED'
        },
    )
    role = tvm.roles.create(
        'Security Analyst',
        [
            'VM.TOGGLE_VM.USE',
            'VM.VM_EXPLORE.VM_EXPLORE.READ',
        ],
        description='Custom security analyst role.'
    )

    assert isinstance(role, dict)
    request_body = json.loads(responses.calls[0].request.body)

    assert request_body == {
        'name': 'Security Analyst',
        'role_permission_strings': [
            'VM.TOGGLE_VM.USE',
            'VM.VM_EXPLORE.VM_EXPLORE.READ'
        ],
        'description': 'Custom security analyst role.',
        'type': 'CUSTOM',
        'status': 'ENABLED'
    }

@responses.activate
def test_update(tvm):
    role_uuid = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    responses.add(
        responses.PUT,
        f'https://nourl/access-control/v1/roles/{role_uuid}',
        json={
            'name': 'Security Analyst',
            'uuid': role_uuid,
            'description': 'Custom security analyst role.',
            'role_permission_strings': [
                'VM.TOGGLE_VM.USE'
            ],
            'type': 'CUSTOM',
            'status': 'DISABLED'
        },
    )

    role = tvm.roles.update(
        role_uuid,
        status='DISABLED'
    )

    assert isinstance(role, dict)
    request_body = json.loads(responses.calls[0].request.body)

    assert request_body == {
        'status': 'DISABLED'
    }

@responses.activate
def test_delete(tvm):
    role_uuid = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    responses.add(
        responses.DELETE,
        f'https://nourl/access-control/v1/roles/{role_uuid}',
        status=204
    )

    result = tvm.roles.delete(role_uuid)
    assert result is None

@responses.activate
def test_permissions(tvm):
    responses.add(
        responses.GET,
        'https://nourl/access-control/v1/role-permissions',
        json=[
            {
                'permission': 'VM.TOGGLE_VM.USE'
            },
            {
                'permission': 'VM.VM_EXPLORE.VM_EXPLORE.READ'
            },
        ],
    )

    permissions = tvm.roles.permissions()
    assert isinstance(permissions, list)