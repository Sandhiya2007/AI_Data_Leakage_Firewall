
import sqlite3
from seed_data import DB_PATH

# Only approved columns can be retrieved.
VALID_FIELDS = {
    "customer_id",
    "name",
    "email",
    "phone",
    "balance",
    "account_status",
}

# Defense-in-depth restrictions enforced by this module.
ROLE_PERMISSIONS = {
    "admin": {
        "customer_id",
        "name",
        "email",
        "phone",
        "balance",
        "account_status",
    },
    "analyst": {
        "customer_id",
        "balance",
        "account_status",
    },
    "support": {
        "customer_id",
        "name",
        "account_status",
    },
}


def validate_role(role):
    if not isinstance(role, str):
        raise ValueError("Invalid role")

    role = role.lower().strip()

    if role not in ROLE_PERMISSIONS:
        raise ValueError("Unknown or unauthorized role")

    return role


def get_customer(customer_id, role, allowed_fields):
    """
    Retrieve only authorized fields.

    Role is supplied by the trusted backend.
    allowed_fields is supplied by the policy engine.

    Returns:
        dict for an existing customer
        None if the customer does not exist
    """
    role = validate_role(role)

    if not isinstance(customer_id, str):
        raise ValueError("Invalid customer ID")

    if not isinstance(allowed_fields, (list, tuple, set)):
        raise ValueError("allowed_fields must be a collection")

    requested = set(allowed_fields)

    if not requested.issubset(VALID_FIELDS):
        raise ValueError("Unknown customer field requested")

    # Apply our own permission check, even after policy checks.
    permitted = requested & ROLE_PERMISSIONS[role]

    if not permitted:
        return {}

    # Use a fixed ordering for predictable results.
    fields = sorted(permitted)

    # Column names are safe because of strict whitelisting.
    columns = ", ".join(fields)

    query = (
        f"SELECT {columns} FROM customers "
        "WHERE customer_id = ?"
    )

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            query,
            (customer_id,)
        ).fetchone()

    return dict(row) if row else None


def get_customer_count(role):
    """
    Return only the total number of customers.
    This operation is available to all three roles.
    """
    validate_role(role)

    with sqlite3.connect(DB_PATH) as conn:
        result = conn.execute(
            "SELECT COUNT(*) FROM customers"
        ).fetchone()

    return result[0]


if __name__ == "__main__":
    print("=== DATA STORE TEST ===")

    print("\nAdmin:")
    print(get_customer(
        "C1001",
        "admin",
        ["customer_id", "name", "email", "balance"]
    ))

    print("\nAnalyst:")
    print(get_customer(
        "C1001",
        "analyst",
        ["customer_id", "name", "balance"]
    ))

    print("\nSupport:")
    print(get_customer(
        "C1001",
        "support",
        ["customer_id", "name", "email", "balance"]
    ))

    print("\nCustomer count:")
    print(get_customer_count("analyst"))
