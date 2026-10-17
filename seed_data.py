
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "data" / "firewall.db"


def create_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                customer_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL,
                balance REAL NOT NULL,
                account_status TEXT NOT NULL
            )
        """)

        conn.commit()


def seed_customers():
    create_database()

    statuses = ["Active", "Inactive", "Pending"]

    customers = []

    for i in range(1, 31):
        customer_id = f"C{1000 + i}"
        name = f"Customer {i:03d}"
        email = f"customer{i:03d}@example.com"
        phone = f"202-555-{99 + i:04d}"

        balance = float(5000 + i * 20000)
        account_status = statuses[(i - 1) % len(statuses)]

        customers.append((
            customer_id,
            name,
            email,
            phone,
            balance,
            account_status
        ))

    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany("""
            INSERT OR IGNORE INTO customers
            (
                customer_id,
                name,
                email,
                phone,
                balance,
                account_status
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, customers)

        total = conn.execute(
            "SELECT COUNT(*) FROM customers"
        ).fetchone()[0]

    print("Database initialized successfully!")
    print(f"Total customer records: {total}")
    print(f"Database path: {DB_PATH}")


if __name__ == "__main__":
    seed_customers()
