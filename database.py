"""
Database connection pool manager for PostgreSQL.
Provides thread-safe connection handling using psycopg2.
"""

import psycopg2
from psycopg2 import pool
from contextlib import contextmanager
from config import Config


class Database:
    """PostgreSQL database connection pool manager."""

    _pool = None

    @classmethod
    def initialize(cls):
        """Initialize the connection pool."""
        if cls._pool is None:
            try:
                cls._pool = pool.ThreadedConnectionPool(
                    minconn=Config.DATABASE_MIN_CONNECTIONS,
                    maxconn=Config.DATABASE_MAX_CONNECTIONS,
                    **Config.get_database_params(),
                )
                print("[+] Database connection pool initialized")
            except psycopg2.Error as e:
                print(f"[!] Failed to initialize database pool: {e}")
                raise

    @classmethod
    def close(cls):
        """Close all connections in the pool."""
        if cls._pool is not None:
            cls._pool.closeall()
            cls._pool = None
            print("[+] Database connection pool closed")

    @classmethod
    @contextmanager
    def get_connection(cls):
        """
        Get a connection from the pool.
        Use as context manager to ensure connection is returned to pool.

        Usage:
            with Database.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT * FROM packets")
        """
        if cls._pool is None:
            cls.initialize()

        conn = None
        try:
            conn = cls._pool.getconn()
            yield conn
        finally:
            if conn is not None:
                cls._pool.putconn(conn)

    @classmethod
    @contextmanager
    def get_cursor(cls, commit=True):
        """
        Get a cursor with automatic connection management.

        Args:
            commit: Whether to commit the transaction on success (default: True)

        Usage:
            with Database.get_cursor() as cursor:
                cursor.execute("INSERT INTO packets ...")
        """
        with cls.get_connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                if commit:
                    conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    @classmethod
    def execute(cls, query, params=None):
        """Execute a query and return affected row count."""
        with cls.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.rowcount

    @classmethod
    def fetch_one(cls, query, params=None):
        """Execute a query and return one row."""
        with cls.get_cursor(commit=False) as cursor:
            cursor.execute(query, params)
            return cursor.fetchone()

    @classmethod
    def fetch_all(cls, query, params=None):
        """Execute a query and return all rows."""
        with cls.get_cursor(commit=False) as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

    @classmethod
    def health_check(cls):
        """Check if database connection is healthy."""
        try:
            result = cls.fetch_one("SELECT 1")
            return result is not None
        except Exception as e:
            print(f"[!] Database health check failed: {e}")
            return False
