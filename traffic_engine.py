import time
import random
import threading
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

# Thread-safe storage for packets
packet_buffer = []
is_generating = False
lock = threading.Lock()

# Enhanced Attack Signatures
ATTACK_SIGNATURES = [
    {"type": "SQL Injection", "url": "http://api/v2/user?id=' OR '1'='1 --", "risk": "CRITICAL"},
    {"type": "XSS Attempt", "url": "purpelle-security.org/account-locked('xss')</script>", "risk": "HIGH"},
    {"type": "Path Traversal", "url": "nyka.co.in/flashsale-vouche", "risk": "HIGH"},
    {"type": "Brute Force", "url": "http:/meeshologin.authenticate/075.//.", "risk": "MEDIUM"},
    {"type": "Buffer Overflow", "url": "http://rnicrosoft/service/cmd?data=A" *50, "risk": "CRITICAL"},
    {"type": "DDoS Payload", "url": "http://githob/loadtest.js?q=stress/", "risk": "MEDIUM"},
    {"type": "Zero-Day Exploit", "url": "http://terabox/film/download?file=exploit.dll/", "risk": "CRITICAL"},
    {"type": "Directory Traversal", "url": "myntra-order-support.com/update-shipping", "risk": "CRITICAL"},
    {"type": "URL SPOOFING", "url": "http://rnicrosoft/service/cmd?data=A" *10, "risk": "CRITICAL"},
    {"type": "COMMAND INJECTION", "url": "http://githob/loadtest.js?q=stress/", "risk": "MEDIUM"},
    {"type": "SSRF ATTEMPT", "url": "terabox-storage-full.com/upgrade-free", "risk": "CRITICAL"},
    {"type": "URL SPOOFING", "url": "bkmyshow-free-tix.live/redeem/code/", "risk": "CRITICAL"},
    {"type": "LFI/RFI ATTEMPT", "url": "telegram-security-alert.cc/reset-password", "risk": "CRITICAL"},
    {"type": "CREDENTIAL STUFFING", "url": "http://rnicrosoft/service/cmd?data=A", "risk": "CRITICAL"},
    {"type": "HTTP PARAMETER POLLUTION", "url": "makemytrip-session-verify.net/check", "risk": "MEDIUM"},
    {"type": "XML EXTERNAL ENTITY INJECTION", "url": "http://terabox/film/download?file=exploit.dll/", "risk": "CRITICAL"},
    {"type": "BACKDOOR.ASP UPLOAD", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
    {"type": "CMD.JSP", "url": "spotify-premium-mod-download.net/latest.apk/", "risk": "MEDIUM"},
    {"type": "XSS ATTEMPT", "url": "shopzy-beta-access.xyz/sign-up", "risk": "CRITICAL"},
    {"type": "SQL INJECTION", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
     {"type": "SQL Injection", "url": "http://api/v2/user?id=' OR '1'='1 --", "risk": "CRITICAL"},
    {"type": "XSS Attempt", "url": "purpelle-security.org/account-locked('xss')</script>", "risk": "HIGH"},
    {"type": "Path Traversal", "url": "nyka.co.in/flashsale-vouche", "risk": "HIGH"},
    {"type": "Brute Force", "url": "http:/meeshologin.authenticate/075.//.", "risk": "MEDIUM"},
    {"type": "Buffer Overflow", "url": "http://rnicrosoft/service/cmd?data=A" *50, "risk": "CRITICAL"},
    {"type": "DDoS Payload", "url": "http://githob/loadtest.js?q=stress/", "risk": "MEDIUM"},
    {"type": "Zero-Day Exploit", "url": "http://terabox/film/download?file=exploit.dll/", "risk": "CRITICAL"},
    {"type": "Directory Traversal", "url": "myntra-order-support.com/update-shipping", "risk": "CRITICAL"},
    {"type": "URL SPOOFING", "url": "http://rnicrosoft/service/cmd?data=A" *10, "risk": "CRITICAL"},
    {"type": "COMMAND INJECTION", "url": "http://githob/loadtest.js?q=stress/", "risk": "MEDIUM"},
    {"type": "SSRF ATTEMPT", "url": "terabox-storage-full.com/upgrade-free", "risk": "CRITICAL"},
    {"type": "URL SPOOFING", "url": "bkmyshow-free-tix.live/redeem/code/", "risk": "CRITICAL"},
    {"type": "LFI/RFI ATTEMPT", "url": "telegram-security-alert.cc/reset-password", "risk": "CRITICAL"},
    {"type": "CREDENTIAL STUFFING", "url": "http://rnicrosoft/service/cmd?data=A", "risk": "CRITICAL"},
    {"type": "HTTP PARAMETER POLLUTION", "url": "makemytrip-session-verify.net/check", "risk": "MEDIUM"},
    {"type": "XML EXTERNAL ENTITY INJECTION", "url": "http://terabox/film/download?file=exploit.dll/", "risk": "CRITICAL"},
    {"type": "BACKDOOR.ASP UPLOAD", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
    {"type": "CMD.JSP", "url": "spotify-premium-mod-download.net/latest.apk/", "risk": "MEDIUM"},
    {"type": "XSS ATTEMPT", "url": "shopzy-beta-access.xyz/sign-up", "risk": "CRITICAL"},
    {"type": "SQL INJECTION", "url": "https://www.netflux.in/", "risk": "CRITICAL"},
]


COMMON_URLS = ["/index.html", "/about", "/contact", "/products/view", "/api/v1/status", "/assets/images/logo.png"]

class TrafficEngine:
    def __init__(self):
        self.stop_event = threading.Event()
        self.thread = None
        self.packet_buffer = packet_buffer
        self.lock = lock

    def start_generator(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._generate_traffic, daemon=True)
        self.thread.start()

    def stop_generator(self):
        self.stop_event.set()

    def clear_packets(self):
        with self.lock:
            self.packet_buffer.clear()

    def get_packets(self):
        with self.lock:
            return list(self.packet_buffer)

    def _generate_traffic(self):
        id_counter = 1
        while not self.stop_event.is_set():
            is_attack = random.random() < 0.25 # 25% chance of being an attack
            protocol = random.choice(["HTTP", "HTTPS", "DNS", "FTP", "UDP"])
            port = random.randint(1, 65535)
            src_ip = "192.168.1." + str(random.randint(10, 254))
            dst_ip = random.choice(["10.0.0.5", "172.16.0.8", "8.8.8.8", "192.168.1.1"])
            
            # --- START NEW SIMULATION LOGIC FOR ATTACK TRAFFIC ---
            rule_hit = False
            ml_score = 0.0
            is_successful = False
            
            if is_attack and protocol in ["HTTP", "HTTPS"]:
                attack = random.choice(ATTACK_SIGNATURES)
                info = f"{protocol} GET {attack['url']}"
                alert_type = attack['type']
                
                # SIMULATION: Hybrid Detection Logic
                # Simulate a strong rule hit for known signatures (80% chance)
                if attack['risk'] in ["CRITICAL", "HIGH"] and random.random() < 0.8:
                    rule_hit = True
                    ml_score = random.uniform(0.90, 0.99) # High confidence
                else:
                    ml_score = random.uniform(0.60, 0.95) # ML score for obfuscated/novel

                # Determine Severity based on simulated hybrid result
                if rule_hit or ml_score > 0.95:
                    severity = "CRITICAL"
                elif ml_score > 0.80:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                    
                # SIMULATION: Successful Attack Segregation (30% chance for high risk to be successful)
                if severity in ["CRITICAL", "HIGH"] and random.random() < 0.3:
                    is_successful = True
                
            else:
                info = f"{protocol} GET {random.choice(COMMON_URLS)}" if protocol in ["HTTP", "HTTPS"] else f"{protocol} CMD: {random.choice(['Query', 'Request', 'SYN'])}"
                alert_type = "Normal"
                severity = "Low"
                # is_successful is already False

            packet = {
                "id": id_counter,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source": src_ip,
                "destination": dst_ip,
                "protocol": protocol,
                "port": port,
                "length": random.randint(64, 1500),
                "info": info,
                "type": alert_type,
                "severity": severity,
                "is_successful": is_successful, # <-- NEW FIELD
                "rule_hit": rule_hit,          # <-- NEW FIELD
                "ml_score": ml_score           # <-- NEW FIELD
            }

            with self.lock:
                self.packet_buffer.append(packet)
                if len(self.packet_buffer) > 500: # Keep buffer manageable
                    self.packet_buffer.pop(0)

            id_counter += 1
            time.sleep(random.uniform(0.1, 0.8)) # Random delay between packets

    # --- New Function for IP Range Analysis (Simulation) ---
    def generate_simulated_ipdr_data(self, start_ip_str, end_ip_str, count=50):
        try:
            start_ip = IPv4Address(start_ip_str)
            end_ip = IPv4Address(end_ip_str)
        except ValueError:
            return {"error": "Invalid IP address format."}, []

        if start_ip > end_ip:
            return {"error": "Start IP must be less than or equal to End IP."}, []

        generated_packets = []
        
        # Determine if the range is small enough to be interesting
        is_targeted_range = (int(end_ip) - int(start_ip)) < 100

        for i in range(count):
            # Generate a random IP within the range
            random_ip_int = random.randint(int(start_ip), int(end_ip))
            src_ip = str(IPv4Address(random_ip_int))
            
            # 30% chance of a high-severity event in a targeted range
            is_attack = is_targeted_range and random.random() < 0.30
            
            rule_hit = False
            ml_score = 0.0
            is_successful = False

            if is_attack:
                attack = random.choice(ATTACK_SIGNATURES)
                info = f"TARGETED SCAN: {attack['url']} (Attempting {attack['type']})"
                
                # SIMULATION: Hybrid Detection Logic for IPDR
                if attack['risk'] in ["CRITICAL", "HIGH"] and random.random() < 0.7:
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
                
                alert_type = attack['type']
                
                # SIMULATION: Successful Attack Segregation
                if severity == "CRITICAL" and random.random() < 0.4:
                    is_successful = True
                    
            else:
                info = f"IPDR Record: Normal connection established."
                severity = random.choice(["Low", "Medium"]) if is_targeted_range else "Low"
                alert_type = "IPDR"

            packet = {
                "id": i + 1,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "source": src_ip,
                "destination": random.choice(["10.0.0.1", "10.0.0.254"]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "port": random.randint(80, 50000),
                "length": random.randint(100, 1000),
                "info": info,
                "type": alert_type,
                "severity": severity,
                "is_successful": is_successful, # <-- NEW FIELD
                "rule_hit": rule_hit,
                "ml_score": ml_score
            }
            generated_packets.append(packet)

        message = f"Successfully generated {count} simulated IPDR records for range {start_ip_str} to {end_ip_str}."
        return {"message": message, "status": "success"}, generated_packets
