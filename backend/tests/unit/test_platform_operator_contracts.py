"""Mandatory policy cannot be satisfied by password-only or another factor's proof."""

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api.schemas.platform_operators import OperatorInvite, OperatorResponse
from app.authorization.permissions import PLATFORM_PERMISSION_CODES
from app.authorization.role_matrix import ROLE_PERMISSION_MAP
from app.core.errors import PermissionDeniedError
from app.core.time import utc_now
from app.models.identity import Session, User
from app.services.platform_access import require_recent_step_up, require_strong_step_up

pytestmark = pytest.mark.unit


def test_lifecycle_permissions_belong_only_to_platform_baseline():
    codes = {"platform.operators.read", "platform.operators.write"}
    assert codes <= PLATFORM_PERMISSION_CODES
    for role, grants in ROLE_PERMISSION_MAP.items():
        assert bool(codes & grants) is (role == "SUPER_ADMIN")


@pytest.mark.parametrize("required", [False, True])
def test_unenrolled_operator_policy(required):
    now = utc_now()
    live = Session(
        issued_at=now - timedelta(seconds=2),
        expires_at=now + timedelta(hours=1),
        platform_reauthenticated_at=now,
    )
    user = User(platform_mfa_required=required)
    if required:
        with pytest.raises(PermissionDeniedError):
            require_recent_step_up(live, user)
    else:
        require_recent_step_up(live, user)
    with pytest.raises(PermissionDeniedError):
        require_strong_step_up(live, user)


def test_operator_response_does_not_expose_credentials():
    assert set(OperatorResponse.model_fields) == {
        "id",
        "email",
        "full_name",
        "status",
        "platform_mfa_required",
        "email_verified_at",
        "last_login_at",
        "locked_until",
        "created_at",
        "updated_at",
    }
    with pytest.raises(ValidationError):
        OperatorInvite(
            email="operator@example.test",
            full_name="Operator",
            reason="Reviewed test invitation",
            tenant_id=uuid4(),
        )
