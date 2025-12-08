"""
Repository pattern implementation for packet data storage.
Provides abstraction layer between business logic and data persistence.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from database import Database
from config import Config


class PacketRepository(ABC):
    """Abstract base class for packet repository."""

    @abstractmethod
    def save(self, packet: Dict) -> int:
        """Save a single packet and return its ID."""
        pass

    @abstractmethod
    def save_batch(self, packets: List[Dict]) -> int:
        """Save multiple packets and return count of inserted rows."""
        pass

    @abstractmethod
    def get_all(self, limit: int = 500) -> List[Dict]:
        """Get all packets, most recent first, with optional limit."""
        pass

    @abstractmethod
    def get_by_id(self, packet_id: int) -> Optional[Dict]:
        """Get a single packet by ID."""
        pass

    @abstractmethod
    def clear(self) -> int:
        """Clear all packets and return count of deleted rows."""
        pass

    @abstractmethod
    def count(self) -> int:
        """Get total count of packets."""
        pass


class PostgresPacketRepository(PacketRepository):
    """PostgreSQL implementation of packet repository."""

    COLUMNS = [
        "id",
        "timestamp",
        "source",
        "destination",
        "protocol",
        "port",
        "length",
        "severity",
        "type",
        "is_successful",
        "rule_hit",
        "ml_score",
        "info",
        "created_at",
    ]

    def save(self, packet: Dict) -> int:
        """Save a single packet and return its ID."""
        query = """
            INSERT INTO packets (
                timestamp, source, destination, protocol, port,
                length, severity, type, is_successful, rule_hit, ml_score, info
            ) VALUES (
                %(timestamp)s, %(source)s, %(destination)s, %(protocol)s, %(port)s,
                %(length)s, %(severity)s, %(type)s, %(is_successful)s, %(rule_hit)s,
                %(ml_score)s, %(info)s
            ) RETURNING id
        """
        result = Database.fetch_one(query, packet)
        return result[0] if result else 0

    def save_batch(self, packets: List[Dict]) -> int:
        """Save multiple packets using batch insert."""
        if not packets:
            return 0

        query = """
            INSERT INTO packets (
                timestamp, source, destination, protocol, port,
                length, severity, type, is_successful, rule_hit, ml_score, info
            ) VALUES (
                %(timestamp)s, %(source)s, %(destination)s, %(protocol)s, %(port)s,
                %(length)s, %(severity)s, %(type)s, %(is_successful)s, %(rule_hit)s,
                %(ml_score)s, %(info)s
            )
        """

        with Database.get_cursor() as cursor:
            cursor.executemany(query, packets)
            return cursor.rowcount

    def get_all(self, limit: int = 500) -> List[Dict]:
        """Get all packets, most recent first."""
        query = f"""
            SELECT {', '.join(self.COLUMNS)}
            FROM packets
            ORDER BY created_at DESC, id DESC
            LIMIT %s
        """
        rows = Database.fetch_all(query, (limit,))
        return [self._row_to_dict(row) for row in rows]

    def get_by_id(self, packet_id: int) -> Optional[Dict]:
        """Get a single packet by ID."""
        query = f"""
            SELECT {', '.join(self.COLUMNS)}
            FROM packets
            WHERE id = %s
        """
        row = Database.fetch_one(query, (packet_id,))
        return self._row_to_dict(row) if row else None

    def get_by_severity(self, severity: str, limit: int = 100) -> List[Dict]:
        """Get packets filtered by severity."""
        query = f"""
            SELECT {', '.join(self.COLUMNS)}
            FROM packets
            WHERE severity = %s
            ORDER BY created_at DESC, id DESC
            LIMIT %s
        """
        rows = Database.fetch_all(query, (severity, limit))
        return [self._row_to_dict(row) for row in rows]

    def get_by_source_range(
        self, start_ip: str, end_ip: str, limit: int = 500
    ) -> List[Dict]:
        """Get packets within a source IP range."""
        query = f"""
            SELECT {', '.join(self.COLUMNS)}
            FROM packets
            WHERE source >= %s AND source <= %s
            ORDER BY created_at DESC, id DESC
            LIMIT %s
        """
        rows = Database.fetch_all(query, (start_ip, end_ip, limit))
        return [self._row_to_dict(row) for row in rows]

    def clear(self) -> int:
        """Clear all packets."""
        return Database.execute("DELETE FROM packets")

    def count(self) -> int:
        """Get total count of packets."""
        result = Database.fetch_one("SELECT COUNT(*) FROM packets")
        return result[0] if result else 0

    def get_statistics(self) -> Dict:
        """Get summary statistics about stored packets."""
        query = """
            SELECT
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
                COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
                COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
                COUNT(*) FILTER (WHERE severity = 'Low') as low,
                COUNT(*) FILTER (WHERE is_successful = true) as successful_attacks
            FROM packets
        """
        row = Database.fetch_one(query)
        if row:
            return {
                "total": row[0],
                "critical": row[1],
                "high": row[2],
                "medium": row[3],
                "low": row[4],
                "successful_attacks": row[5],
            }
        return {}

    def _row_to_dict(self, row: tuple) -> Dict:
        """Convert a database row to a dictionary."""
        if not row:
            return {}

        result = dict(zip(self.COLUMNS, row))
        # Convert datetime to string for JSON serialization
        if result.get("created_at"):
            result["created_at"] = result["created_at"].isoformat()
        return result


class InMemoryPacketRepository(PacketRepository):
    """In-memory implementation for testing or fallback."""

    def __init__(self, max_size: int = 500):
        self._packets: List[Dict] = []
        self._counter: int = 0
        self._max_size = max_size

    def save(self, packet: Dict) -> int:
        self._counter += 1
        packet_copy = packet.copy()
        packet_copy["id"] = self._counter
        self._packets.append(packet_copy)
        self._prune()
        return self._counter

    def save_batch(self, packets: List[Dict]) -> int:
        for packet in packets:
            self.save(packet)
        return len(packets)

    def get_all(self, limit: int = 500) -> List[Dict]:
        return list(reversed(self._packets[-limit:]))

    def get_by_id(self, packet_id: int) -> Optional[Dict]:
        for packet in self._packets:
            if packet.get("id") == packet_id:
                return packet
        return None

    def clear(self) -> int:
        count = len(self._packets)
        self._packets.clear()
        return count

    def count(self) -> int:
        return len(self._packets)

    def _prune(self):
        """Remove oldest packets if over max size."""
        if len(self._packets) > self._max_size:
            self._packets = self._packets[-self._max_size :]
