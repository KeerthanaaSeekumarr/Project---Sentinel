"""
Service layer for Sentinel-X Platform.
Orchestrates business logic between REST API and data/engine layers.
"""

from typing import Dict, List, Tuple, Optional
from traffic_engine import TrafficEngine
from repository import (
    PacketRepository,
    PostgresPacketRepository,
    InMemoryPacketRepository,
)
from database import Database
from config import Config


class TrafficService:
    """
    Service layer that orchestrates traffic engine and repository.
    Provides a clean API for the REST endpoints.
    """

    def __init__(self, repository: Optional[PacketRepository] = None):
        """
        Initialize the traffic service.

        Args:
            repository: Optional repository instance. If not provided,
                       will attempt to use PostgreSQL, falling back to in-memory.
        """
        self.repository = repository or self._create_default_repository()
        self.engine = TrafficEngine(self.repository)

    def _create_default_repository(self) -> PacketRepository:
        """Create the default repository, with fallback to in-memory."""
        try:
            Database.initialize()
            if Database.health_check():
                print("[+] Using PostgreSQL repository")
                return PostgresPacketRepository()
        except Exception as e:
            print(f"[!] PostgreSQL unavailable: {e}")

        print("[!] Falling back to in-memory repository")
        return InMemoryPacketRepository(max_size=Config.PACKET_BUFFER_LIMIT)

    # --- Traffic Control ---

    def start_traffic(self) -> Dict:
        """Start the traffic generator."""
        self.engine.start_generator()
        return {
            "status": "started",
            "message": "Traffic Generator Active",
            "is_running": self.engine.is_running,
        }

    def stop_traffic(self) -> Dict:
        """Stop the traffic generator."""
        self.engine.stop_generator()
        return {
            "status": "stopped",
            "message": "Traffic Generator Halted",
            "is_running": self.engine.is_running,
        }

    def clear_packets(self) -> Dict:
        """Clear all stored packets."""
        deleted_count = self.engine.clear_packets()
        return {
            "status": "cleared",
            "message": "Buffer Cleared",
            "deleted_count": deleted_count,
        }

    def get_status(self) -> Dict:
        """Get current engine status."""
        return {
            "is_running": self.engine.is_running,
            "packet_count": self.engine.get_packet_count(),
        }

    # --- Packet Retrieval ---

    def get_packets(self, limit: int = 500) -> List[Dict]:
        """Get stored packets."""
        return self.engine.get_packets(limit=limit)

    def get_packet_by_id(self, packet_id: int) -> Optional[Dict]:
        """Get a specific packet by ID."""
        return self.repository.get_by_id(packet_id)

    def get_packet_count(self) -> int:
        """Get total packet count."""
        return self.engine.get_packet_count()

    def get_statistics(self) -> Dict:
        """Get packet statistics."""
        if isinstance(self.repository, PostgresPacketRepository):
            return self.repository.get_statistics()

        # Fallback for in-memory repository
        packets = self.get_packets(limit=10000)
        return {
            "total": len(packets),
            "critical": sum(1 for p in packets if p.get("severity") == "CRITICAL"),
            "high": sum(1 for p in packets if p.get("severity") == "HIGH"),
            "medium": sum(1 for p in packets if p.get("severity") == "MEDIUM"),
            "low": sum(1 for p in packets if p.get("severity") == "Low"),
            "successful_attacks": sum(1 for p in packets if p.get("is_successful")),
        }

    # --- IP Range Processing ---

    def process_ip_range(self, start_ip: str, end_ip: str) -> Tuple[Dict, List[Dict]]:
        """
        Generate and store IPDR data for an IP range.

        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address

        Returns:
            Tuple of (status dict, filtered packets list)
        """
        # Generate simulated data
        status, packets = self.engine.generate_simulated_ipdr_data(start_ip, end_ip)

        if status.get("error"):
            return status, []

        # Store packets in repository
        if packets:
            try:
                self.repository.save_batch(packets)
            except Exception as e:
                print(f"[!] Error saving IPDR packets: {e}")
                # Continue anyway - data is in the response

        return status, packets

    # --- Cleanup ---

    def shutdown(self):
        """Gracefully shutdown the service."""
        print("[*] Shutting down traffic service...")
        self.engine.stop_generator()

        # Wait for thread to stop
        if self.engine.thread and self.engine.thread.is_alive():
            self.engine.thread.join(timeout=2.0)

        print("[+] Traffic service shutdown complete")


# Singleton instance for the application
_service_instance: Optional[TrafficService] = None


def get_traffic_service() -> TrafficService:
    """
    Get or create the singleton TrafficService instance.

    Returns:
        The TrafficService singleton
    """
    global _service_instance
    if _service_instance is None:
        _service_instance = TrafficService()
    return _service_instance


def shutdown_service():
    """Shutdown the singleton service if it exists."""
    global _service_instance
    if _service_instance is not None:
        _service_instance.shutdown()
        _service_instance = None
