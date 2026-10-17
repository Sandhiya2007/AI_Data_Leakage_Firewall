
"""Rule-based RBAC policy engine for an AI data-leakage firewall.

Evaluates access requests before data retrieval.
Never fetches, returns, or logs customer data values.
"""

from collections.abc import Mapping
from typing import Any


ALLOW = "ALLOW"
MASK = "MASK"
BLOCK = "BLOCK"

_ALLOW = "allow"
_MASK = "mask"
_PROHIBIT = "prohibit"


# Role-based access control matrix
ROLE_PERMISSIONS: dict[str, dict[str, str]] = {
    "admin": {
        "customer_id": _ALLOW,
        "name": _ALLOW,
        "email": _ALLOW,
        "phone": _ALLOW,
        "balance": _ALLOW,
        "api_secret": _PROHIBIT,
    },
    "analyst": {
        "customer_id": _ALLOW,
        "name": _ALLOW,
        "email": _MASK,
        "phone": _MASK,
        "balance": _ALLOW,
        "api_secret": _PROHIBIT,
    },
    "support": {
        "customer_id": _ALLOW,
        "name": _ALLOW,
        "email": _MASK,
        "phone": _MASK,
        "balance": _PROHIBIT,
        "api_secret": _PROHIBIT,
    },
}


# Secrets are prohibited for every role, including Admin.
_PROHIBITED_CREDENTIAL_FIELDS = {
    "api_secret",
    "password",
    "password_hash",
    "credential",
    "credentials",
    "api_key",
    "access_token",
    "refresh_token",
    "secret",
}


# Transparent, rule-based risk scoring.
_SIGNAL_RISK_POINTS = {
    "suspicious_activity": 40,
    "untrusted_device": 20,
    "high_request_volume": 15,
}


def _result(
    decision: str,
    reason: str,
    risk_score: int,
    allowed_fields: list[str] | None = None,
    masked_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Return a consistent response and cap the risk score at 100."""
    return {
        "decision": decision,
        "reason": reason,
        "allowed_fields": allowed_fields or [],
        "masked_fields": masked_fields or [],
        "risk_score": min(max(risk_score, 0), 100),
    }


def _normalize_fields(
    requested_fields: object,
) -> list[str] | None:
    """Validate and normalize requested field names."""
    if not isinstance(
        requested_fields, (list, tuple, set, frozenset)
    ):
        return None

    normalized = set()

    for field in requested_fields:
        if not isinstance(field, str) or not field.strip():
            return None
        normalized.add(field.strip().casefold())

    return sorted(normalized)


def _validated_signals(
    signals: object,
) -> tuple[dict[str, bool] | None, str | None]:
    """Validate the names and types of risk signals."""
    if signals is None:
        return {}, None

    if not isinstance(signals, Mapping):
        return None, "Signals must be a mapping of supported names to booleans."

    validated: dict[str, bool] = {}

    for name, value in signals.items():
        if not isinstance(name, str) or name not in _SIGNAL_RISK_POINTS:
            return None, "Signals contain an unsupported signal name."

        if type(value) is not bool:
            return None, "Signal values must be booleans."

        validated[name] = value

    return validated, None


def evaluate_request(
    role: object,
    requested_fields: object,
    signals: object = None,
) -> dict[str, Any]:
    """Evaluate a request before retrieving any data.

    Args:
        role: Role obtained from a trusted authenticated identity.
        requested_fields: Requested field names.
        signals: Optional trusted, rule-based risk signals.

    Returns:
        A dictionary containing decision, reason, allowed_fields,
        masked_fields and risk_score.
    """

    # 1. Validate security signals.
    validated_signals, signal_error = _validated_signals(signals)

    if signal_error is not None:
        return _result(BLOCK, signal_error, 40)

    assert validated_signals is not None

    # 2. Calculate risk using explicit rules.
    risk_score = sum(
        points
        for name, points in _SIGNAL_RISK_POINTS.items()
        if validated_signals.get(name, False)
    )

    active_signals = [
        name
        for name in _SIGNAL_RISK_POINTS
        if validated_signals.get(name, False)
    ]

    signal_explanation = (
        " Detected rule-based risk signals: "
        + ", ".join(active_signals)
        + "."
        if active_signals
        else ""
    )

    # 3. Validate the role.
    if (
        not isinstance(role, str)
        or role.strip().casefold() not in ROLE_PERMISSIONS
    ):
        return _result(
            BLOCK,
            "Unknown or invalid role; access is denied."
            + signal_explanation,
            risk_score + 60,
        )

    normalized_role = role.strip().casefold()

    # 4. Validate requested fields.
    fields = _normalize_fields(requested_fields)

    if fields is None:
        return _result(
            BLOCK,
            "Requested fields must be a list, tuple, or set "
            "of non-empty strings."
            + signal_explanation,
            risk_score + 40,
        )

    # 5. Block suspicious activity.
    if validated_signals.get("suspicious_activity", False):
        return _result(
            BLOCK,
            "Suspicious activity is a blocking security signal."
            + signal_explanation,
            risk_score,
        )

    # 6. Prohibit credentials and secrets for every role.
    prohibited_credentials = [
        field
        for field in fields
        if field in _PROHIBITED_CREDENTIAL_FIELDS
    ]

    if prohibited_credentials:
        return _result(
            BLOCK,
            "Credential and API secret fields are always prohibited."
            + signal_explanation,
            risk_score + 60,
        )

    permissions = ROLE_PERMISSIONS[normalized_role]

    # 7. Reject unknown fields.
    unknown_fields = [
        field for field in fields if field not in permissions
    ]

    if unknown_fields:
        return _result(
            BLOCK,
            "The request contains an unknown field; "
            "the entire request is denied."
            + signal_explanation,
            risk_score + 50,
        )

    # 8. Block any field prohibited for this role.
    prohibited_fields = [
        field
        for field in fields
        if permissions[field] == _PROHIBIT
    ]

    if prohibited_fields:
        return _result(
            BLOCK,
            "The role is not permitted to access "
            "one or more requested fields."
            + signal_explanation,
            risk_score + 40,
        )

    # 9. Separate permitted fields from fields requiring masking.
    allowed_fields = [
        field for field in fields
        if permissions[field] == _ALLOW
    ]

    masked_fields = [
        field for field in fields
        if permissions[field] == _MASK
    ]

    masking_points = len(masked_fields) * 5
    risk_score += masking_points

    risk_explanation = (
        f" Masking adds {masking_points} rule-based risk points."
        if masked_fields
        else ""
    )

    # 10. Determine the final decision.
    if masked_fields:
        decision = MASK
        reason = (
            "Some requested fields are permitted only after "
            "the caller masks their values."
        )
    else:
        decision = ALLOW
        reason = "All requested fields are permitted by the role policy."

    return _result(
        decision,
        reason + risk_explanation + signal_explanation,
        risk_score,
        allowed_fields,
        masked_fields,
    )
