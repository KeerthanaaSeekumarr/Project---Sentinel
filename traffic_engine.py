"""
Traffic Engine for Sentinel-X Platform.
Generates simulated network traffic with attack patterns.
"""

import time
import random
import threading
from datetime import datetime
from ipaddress import IPv4Address
from typing import Optional, Tuple, List, Dict
from repository import PacketRepository


# Enhanced Attack Signatures
ATTACK_SIGNATURES = [
    {
        "type": "SQL Injection",
        "url": "http://api/v2/user?id=' OR '1'='1 --",
        "risk": "CRITICAL",
    },
    {
        "type": "XSS Attempt",
        "url": "purpelle-security.org/account-locked('xss')</script>",
        "risk": "HIGH",
    },
    {"type": "Path Traversal", "url": "nyka.co.in/flashsale-vouche", "risk": "HIGH"},
    {
        "type": "Brute Force",
        "url": "http:/meeshologin.authenticate/075.//.",
        "risk": "MEDIUM",
    },
    {
        "type": "Buffer Overflow",
        "url": "http://rnicrosoft/service/cmd?data=A" * 50,
        "risk": "CRITICAL",
    },
    {
        "type": "DDoS Payload",
        "url": "http://githob/loadtest.js?q=stress/",
        "risk": "MEDIUM",
    },
    {
        "type": "Zero-Day Exploit",
        "url": "http://terabox/film/download?file=exploit.dll/",
        "risk": "CRITICAL",
    },
    {
        "type": "Directory Traversal",
        "url": "myntra-order-support.com/update-shipping",
        "risk": "CRITICAL",
    },
    {
        "type": "URL SPOOFING",
        "url": "http://rnicrosoft/service/cmd?data=A" * 10,
        "risk": "CRITICAL",
    },
    {
        "type": "COMMAND INJECTION",
        "url": "http://githob/loadtest.js?q=stress/",
        "risk": "MEDIUM",
    },
    {
        "type": "SSRF ATTEMPT",
        "url": "terabox-storage-full.com/upgrade-free",
        "risk": "CRITICAL",
    },
    {
        "type": "URL SPOOFING",
        "url": "bkmyshow-free-tix.live/redeem/code/",
        "risk": "CRITICAL",
    },
    {
        "type": "LFI/RFI ATTEMPT",
        "url": "telegram-security-alert.cc/reset-password",
        "risk": "CRITICAL",
    },
    {
        "type": "CREDENTIAL STUFFING",
        "url": "http://rnicrosoft/service/cmd?data=A",
        "risk": "CRITICAL",
    },
    {
        "type": "HTTP PARAMETER POLLUTION",
        "url": "makemytrip-session-verify.net/check",
        "risk": "MEDIUM",
    },
    {
        "type": "XML EXTERNAL ENTITY INJECTION",
        "url": "http://terabox/film/download?file=exploit.dll/",
        "risk": "CRITICAL",
    },
    {
        "type": "BACKDOOR.ASP UPLOAD",
        "url": "https://www.netflux.in/",
        "risk": "CRITICAL",
    },
    {
        "type": "CMD.JSP",
        "url": "spotify-premium-mod-download.net/latest.apk/",
        "risk": "MEDIUM",
    },
    {
        "type": "XSS ATTEMPT",
        "url": "shopzy-beta-access.xyz/sign-up",
        "risk": "CRITICAL",
    },
    {"type": "SQL INJECTION", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
    {
        "type": "SQL Injection",
        "url": "http://api/v2/user?id=' OR '1'='1 --",
        "risk": "CRITICAL",
    },
    {
        "type": "XSS Attempt",
        "url": "purpelle-security.org/account-locked('xss')</script>",
        "risk": "HIGH",
    },
    {"type": "Path Traversal", "url": "nyka.co.in/flashsale-vouche", "risk": "HIGH"},
    {
        "type": "Brute Force",
        "url": "http:/meeshologin.authenticate/075.//.",
        "risk": "MEDIUM",
    },
    {
        "type": "Buffer Overflow",
        "url": "http://rnicrosoft/service/cmd?data=A" * 50,
        "risk": "CRITICAL",
    },
    {
        "type": "DDoS Payload",
        "url": "http://githob/loadtest.js?q=stress/",
        "risk": "MEDIUM",
    },
    {
        "type": "Zero-Day Exploit",
        "url": "http://terabox/film/download?file=exploit.dll/",
        "risk": "CRITICAL",
    },
    {
        "type": "Directory Traversal",
        "url": "myntra-order-support.com/update-shipping",
        "risk": "CRITICAL",
    },
    {
        "type": "URL SPOOFING",
        "url": "http://rnicrosoft/service/cmd?data=A" * 10,
        "risk": "CRITICAL",
    },
    {
        "type": "COMMAND INJECTION",
        "url": "http://githob/loadtest.js?q=stress/",
        "risk": "MEDIUM",
    },
    {
        "type": "SSRF ATTEMPT",
        "url": "terabox-storage-full.com/upgrade-free",
        "risk": "CRITICAL",
    },
    {
        "type": "URL SPOOFING",
        "url": "bkmyshow-free-tix.live/redeem/code/",
        "risk": "CRITICAL",
    },
    {
        "type": "LFI/RFI ATTEMPT",
        "url": "telegram-security-alert.cc/reset-password",
        "risk": "CRITICAL",
    },
    {
        "type": "CREDENTIAL STUFFING",
        "url": "http://rnicrosoft/service/cmd?data=A",
        "risk": "CRITICAL",
    },
    {
        "type": "HTTP PARAMETER POLLUTION",
        "url": "makemytrip-session-verify.net/check",
        "risk": "MEDIUM",
    },
    {
        "type": "XML EXTERNAL ENTITY INJECTION",
        "url": "http://terabox/film/download?file=exploit.dll/",
        "risk": "CRITICAL",
    },
    {
        "type": "BACKDOOR.ASP UPLOAD",
        "url": "https://www.netflux.in/",
        "risk": "CRITICAL",
    },
    {
        "type": "CMD.JSP",
        "url": "spotify-premium-mod-download.net/latest.apk/",
        "risk": "MEDIUM",
    },
    {
        "type": "XSS ATTEMPT",
        "url": "shopzy-beta-access.xyz/sign-up",
        "risk": "CRITICAL",
    },
    {"type": "SQL INJECTION", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
]

COMMON_URLS = [
    "/index.html",
    "/about",
    "/contact",
    "/products/view",
    "/api/v1/status",
    "/assets/images/logo.png",
]


class TrafficEngine:
    """
    Traffic generator engine that creates simulated network packets.
    Uses repository pattern for data persistence.
    """

    def __init__(self, repository: PacketRepository):
        """
        Initialize the traffic engine.

        Args:
            repository: PacketRepository implementation for data storage
        """
        self.repository = repository
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def is_running(self) -> bool:
        """Check if the generator thread is running."""
        return self.thread is not None and self.thread.is_alive()

    def start_generator(self):
        """Start the traffic generator thread."""
        if self.is_running:
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._generate_traffic, daemon=True)
        self.thread.start()

    def stop_generator(self):
        """Stop the traffic generator thread."""
        self.stop_event.set()

    def clear_packets(self) -> int:
        """Clear all stored packets and return deleted count."""
        return self.repository.clear()

    def get_packets(self, limit: int = 500) -> List[Dict]:
        """Get stored packets."""
        return self.repository.get_all(limit=limit)

    def get_packet_count(self) -> int:
        """Get total packet count."""
        return self.repository.count()

    def _generate_traffic(self):
        """Background thread that generates traffic packets."""
        while not self.stop_event.is_set():
            packet = self._create_packet()

            with self._lock:
                try:
                    self.repository.save(packet)
                except Exception as e:
                    print(f"[!] Error saving packet: {e}")

            time.sleep(random.uniform(0.1, 0.8))

    def _create_packet(self) -> Dict:
        """Create a single traffic packet."""
        is_attack = random.random() < 0.25  # 25% chance of being an attack
        protocol = random.choice(["HTTP", "HTTPS", "DNS", "FTP", "UDP"])
        port = random.randint(1, 65535)
        src_ip = "192.168.1." + str(random.randint(10, 254))
        dst_ip = random.choice(["10.0.0.5", "172.16.0.8", "8.8.8.8", "192.168.1.1"])

        rule_hit = False
        ml_score = 0.0
        is_successful = False

        if is_attack and protocol in ["HTTP", "HTTPS"]:
            attack = random.choice(ATTACK_SIGNATURES)
            info = f"{protocol} GET {attack['url']}"
            alert_type = attack["type"]

            # SIMULATION: Hybrid Detection Logic
            if attack["risk"] in ["CRITICAL", "HIGH"] and random.random() < 0.8:
                rule_hit = True
                ml_score = random.uniform(0.90, 0.99)
            else:
                ml_score = random.uniform(0.60, 0.95)

            # Determine Severity based on simulated hybrid result
            if rule_hit or ml_score > 0.95:
                severity = "CRITICAL"
            elif ml_score > 0.80:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            # SIMULATION: Successful Attack Segregation
            if severity in ["CRITICAL", "HIGH"] and random.random() < 0.3:
                is_successful = True
        else:
            if protocol in ["HTTP", "HTTPS"]:
                info = f"{protocol} GET {random.choice(COMMON_URLS)}"
            else:
                info = f"{protocol} CMD: {random.choice(['Query', 'Request', 'SYN'])}"
            alert_type = "Normal"
            severity = "Low"

        return {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "source": src_ip,
            "destination": dst_ip,
            "protocol": protocol,
            "port": port,
            "length": random.randint(64, 1500),
            "info": info,
            "type": alert_type,
            "severity": severity,
            "is_successful": is_successful,
            "rule_hit": rule_hit,
            "ml_score": ml_score,
        }

    def generate_simulated_ipdr_data(
        self, start_ip_str: str, end_ip_str: str
    ) -> Tuple[Dict, List[Dict]]:
        """
        Generate simulated IPDR (IP Detail Record) data for IP range analysis.

        Args:
            start_ip_str: Starting IP address of range
            end_ip_str: Ending IP address of range

        Returns:
            Tuple of (status dict, list of generated packets)
        """
        try:
            start_ip = IPv4Address(start_ip_str)
            end_ip = IPv4Address(end_ip_str)
        except ValueError:
            return {"error": "Invalid IP address format."}, []

        if start_ip > end_ip:
            return {"error": "Start IP must be less than or equal to End IP."}, []

        # Use IP range as seed for consistent results
        seed_value = int(start_ip) + int(end_ip)
        random.seed(seed_value)

        # Define full IP space for simulation
        FULL_RANGE_START = IPv4Address("192.168.0.1")
        FULL_RANGE_END = IPv4Address("192.168.10.254")
        TOTAL_PACKETS = random.randint(500, 1000)

        all_generated_packets = []

        for i in range(TOTAL_PACKETS):
            random_ip_int = random.randint(int(FULL_RANGE_START), int(FULL_RANGE_END))
            src_ip = str(IPv4Address(random_ip_int))

            src_ip_obj = IPv4Address(src_ip)
            is_in_user_range = start_ip <= src_ip_obj <= end_ip

            if is_in_user_range:
                is_attack = random.random() < 0.50
            else:
                is_attack = random.random() < 0.10

            rule_hit = False
            ml_score = 0.0
            is_successful = False

            if is_attack:
                attack = random.choice(ATTACK_SIGNATURES)
                info = f"TARGETED SCAN: {attack['url']} (Attempting {attack['type']})"

                if attack["risk"] in ["CRITICAL", "HIGH"] and random.random() < 0.7:
                    rule_hit = True
                    ml_score = random.uniform(0.85, 0.98)
                else:
                    ml_score = random.uniform(0.70, 0.90)

                if rule_hit or ml_score > 0.95:
                    severity = "CRITICAL"
                elif ml_score > 0.80:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                alert_type = attack["type"]

                if severity == "CRITICAL" and random.random() < 0.4:
                    is_successful = True
            else:
                info = "IPDR Record: Normal connection established."
                severity = (
                    random.choice(["Low", "Medium"]) if is_in_user_range else "Low"
                )
                alert_type = "IPDR"

            packet = {
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source": src_ip,
                "destination": random.choice(["10.0.0.1", "10.0.0.254"]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "port": random.randint(80, 50000),
                "length": random.randint(100, 1000),
                "info": info,
                "type": alert_type,
                "severity": severity,
                "is_successful": is_successful,
                "rule_hit": rule_hit,
                "ml_score": ml_score,
            }
            all_generated_packets.append(packet)

        # Filter packets by user's IP range
        filtered_packets = [
            p
            for p in all_generated_packets
            if start_ip <= IPv4Address(p["source"]) <= end_ip
        ]

        # Reset random seed
        random.seed()

        message = f"Found {len(filtered_packets)} records in range {start_ip_str} - {end_ip_str} (from {len(all_generated_packets)} total)"
        return {
            "message": message,
            "status": "success",
            "total_generated": len(all_generated_packets),
            "filtered_count": len(filtered_packets),
        }, filtered_packets
