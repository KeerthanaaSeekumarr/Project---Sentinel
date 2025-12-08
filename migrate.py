#!/usr/bin/env python3
"""
Database migration runner for Sentinel-X Platform.
Manages SQL migrations from the migrations/ folder.

Usage:
    python migrate.py up        - Run all pending migrations
    python migrate.py status    - Show migration status
    python migrate.py reset     - Drop all tables and re-run migrations (DANGER!)
"""

import os
import sys
import glob
import psycopg2
from datetime import datetime
from config import Config


def get_connection():
    """Get a database connection."""
    return psycopg2.connect(**Config.get_database_params())


def ensure_migrations_table(conn):
    """Create the schema_migrations table if it doesn't exist."""
    with conn.cursor() as cursor:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id SERIAL PRIMARY KEY,
                migration_name VARCHAR(255) NOT NULL UNIQUE,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )
        conn.commit()
    print("[+] Ensured schema_migrations table exists")


def get_applied_migrations(conn):
    """Get list of already applied migrations."""
    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT migration_name FROM schema_migrations ORDER BY migration_name"
        )
        return {row[0] for row in cursor.fetchall()}


def get_pending_migrations(conn):
    """Get list of migrations that haven't been applied yet."""
    migrations_dir = os.path.join(os.path.dirname(__file__), "migrations")
    all_migrations = sorted(glob.glob(os.path.join(migrations_dir, "*.sql")))
    applied = get_applied_migrations(conn)

    pending = []
    for migration_path in all_migrations:
        migration_name = os.path.basename(migration_path)
        if migration_name not in applied:
            pending.append((migration_name, migration_path))

    return pending


def run_migration(conn, migration_name, migration_path):
    """Run a single migration file."""
    print(f"[*] Running migration: {migration_name}")

    with open(migration_path, "r") as f:
        sql = f.read()

    with conn.cursor() as cursor:
        cursor.execute(sql)
        cursor.execute(
            "INSERT INTO schema_migrations (migration_name) VALUES (%s)",
            (migration_name,),
        )
        conn.commit()

    print(f"[+] Applied migration: {migration_name}")


def migrate_up():
    """Run all pending migrations."""
    conn = None
    try:
        conn = get_connection()
        ensure_migrations_table(conn)

        pending = get_pending_migrations(conn)

        if not pending:
            print("[*] No pending migrations")
            return

        print(f"[*] Found {len(pending)} pending migration(s)")

        for migration_name, migration_path in pending:
            run_migration(conn, migration_name, migration_path)

        print(f"[+] Successfully applied {len(pending)} migration(s)")

    except psycopg2.Error as e:
        print(f"[!] Database error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()


def show_status():
    """Show current migration status."""
    conn = None
    try:
        conn = get_connection()
        ensure_migrations_table(conn)

        applied = get_applied_migrations(conn)
        pending = get_pending_migrations(conn)

        print("\n=== Migration Status ===\n")

        if applied:
            print("Applied migrations:")
            for name in sorted(applied):
                print(f"  [✓] {name}")
        else:
            print("No migrations applied yet.")

        print()

        if pending:
            print("Pending migrations:")
            for name, _ in pending:
                print(f"  [ ] {name}")
        else:
            print("No pending migrations.")

        print()

    except psycopg2.Error as e:
        print(f"[!] Database error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()


def reset_database():
    """Drop all tables and re-run migrations (DANGEROUS!)."""
    confirm = input("[!] WARNING: This will delete ALL data! Type 'YES' to confirm: ")
    if confirm != "YES":
        print("[*] Reset cancelled")
        return

    conn = None
    try:
        conn = get_connection()

        with conn.cursor() as cursor:
            # Drop all tables
            cursor.execute(
                """
                DROP TABLE IF EXISTS packets CASCADE;
                DROP TABLE IF EXISTS schema_migrations CASCADE;
            """
            )
            conn.commit()

        print("[+] All tables dropped")

    except psycopg2.Error as e:
        print(f"[!] Database error: {e}")
        sys.exit(1)
    finally:
        if conn:
            conn.close()

    # Re-run migrations
    migrate_up()


def print_usage():
    """Print usage information."""
    print(__doc__)


def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "up":
        migrate_up()
    elif command == "status":
        show_status()
    elif command == "reset":
        reset_database()
    else:
        print(f"[!] Unknown command: {command}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
