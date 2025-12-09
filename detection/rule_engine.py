"""
Rule-Based Detection Engine

Implements high-speed pattern matching using compiled regex patterns
to detect known attack signatures in network traffic payloads.
"""

import re
from typing import Tuple, Optional


class RuleEngine:
    """
    Fast signature-based detection using pre-compiled regex patterns.

    Detects known attack patterns including:
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Path Traversal
    - Command Injection
    - Buffer Overflow attempts
    - And more...
    """

    def __init__(self):
        """Initialize the rule engine with compiled regex patterns."""
        # Define attack signatures with regex patterns
        self.signatures = [
            {
                "type": "SQL Injection",
                "pattern": re.compile(
                    r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|"
                    r"delete\s+from|drop\s+table|drop\s+database|'(\s)*or(\s)*'|--(\s)*$|"
                    r";(\s)*drop|;(\s)*delete|;(\s)*update|exec\s*\(|execute\s*\(|"
                    r"xp_cmdshell|sp_executesql|'\s*=\s*'|1\s*=\s*1|admin'--|' or 1=1)"
                ),
                "priority": 1
            },
            {
                "type": "XSS Attempt",
                "pattern": re.compile(
                    r"(?i)(<script|</script>|javascript:|onerror\s*=|onload\s*=|onclick\s*=|"
                    r"onmouseover\s*=|onfocus\s*=|<iframe|eval\s*\(|alert\s*\(|"
                    r"document\.cookie|document\.write|<img\s+.*onerror|<svg.*onload|"
                    r"expression\s*\(|vbscript:|<embed|<object)"
                ),
                "priority": 1
            },
            {
                "type": "Path Traversal",
                "pattern": re.compile(
                    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|"
                    r"etc\/passwd|etc\\passwd|windows\/system32|windows\\system32|"
                    r"boot\.ini|win\.ini|\/etc\/shadow|c:\\windows|"
                    r"\.\.;\/|\.\.;\\)"
                ),
                "priority": 1
            },
            {
                "type": "Command Injection",
                "pattern": re.compile(
                    r"(?i)(;\s*(ls|cat|nc|wget|curl|bash|sh|cmd|powershell|python)|"
                    r"\|\s*(ls|cat|nc|wget|curl|bash|sh|cmd)|"
                    r"&&\s*(ls|cat|nc|wget|curl|bash|sh|cmd)|"
                    r"`[^`]*`|\$\([^)]*\)|system\s*\(|exec\s*\(|passthru\s*\(|"
                    r"shell_exec\s*\(|popen\s*\()"
                ),
                "priority": 1
            },
            {
                "type": "LDAP Injection",
                "pattern": re.compile(
                    r"(?i)(\*\)|&\||!\(|\|\||&&|\(\|\(|"
                    r"cn\s*=|ou\s*=|dc\s*=|objectClass\s*=)"
                ),
                "priority": 2
            },
            {
                "type": "XML Injection",
                "pattern": re.compile(
                    r"(?i)(<!ENTITY|<!DOCTYPE|SYSTEM\s+['\"]|PUBLIC\s+['\"]|"
                    r"<\?xml|xmlns:|<!ELEMENT|<!ATTLIST)"
                ),
                "priority": 2
            },
            {
                "type": "Server Side Request Forgery",
                "pattern": re.compile(
                    r"(?i)(file:\/\/|dict:\/\/|gopher:\/\/|ftp:\/\/.*@|"
                    r"localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|"
                    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)"
                ),
                "priority": 2
            },
            {
                "type": "Local File Inclusion",
                "pattern": re.compile(
                    r"(?i)(php:\/\/filter|php:\/\/input|expect:\/\/|data:\/\/|"
                    r"file=\/etc\/|file=\/proc\/|file=\.\.\/|"
                    r"include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\()"
                ),
                "priority": 1
            },
            {
                "type": "Remote File Inclusion",
                "pattern": re.compile(
                    r"(?i)(http:\/\/.*\.(txt|php|asp|jsp|xml)|https:\/\/.*\.(txt|php|asp|jsp|xml)|"
                    r"ftp:\/\/.*\.(txt|php|asp|jsp|xml)|include.*http|require.*http)"
                ),
                "priority": 1
            },
            {
                "type": "Buffer Overflow",
                "pattern": re.compile(
                    r"(A{50,}|(%u[0-9a-fA-F]{4}){20,}|(\\x[0-9a-fA-F]{2}){50,}|"
                    r"\x90{20,}|NOP{20,})"
                ),
                "priority": 1
            },
            {
                "type": "HTTP Parameter Pollution",
                "pattern": re.compile(
                    r"([?&][^=&]+=[^&]*){10,}"
                ),
                "priority": 2
            },
            {
                "type": "Credential Stuffing",
                "pattern": re.compile(
                    r"(?i)(login|signin|authenticate|auth|password).*"
                    r"(admin|root|test|user|guest|password|123456|letmein)"
                ),
                "priority": 2
            },
            {
                "type": "Directory Traversal",
                "pattern": re.compile(
                    r"(?i)(\/\.\.\/|\\\.\.\\|\/\.\.\;|%5c%2e%2e%5c|"
                    r"\.\.%c0%af|\.\.%c1%9c|\.\.%255c)"
                ),
                "priority": 1
            },
            {
                "type": "Shell Upload",
                "pattern": re.compile(
                    r"(?i)(\.php\d?|\.asp|\.aspx|\.jsp|\.jspx|\.cgi|\.pl|\.py|\.rb|\.sh)$|"
                    r"(c99|r57|b374k|wso|shell|webshell|backdoor|cmd|phpshell)"
                ),
                "priority": 1
            },
            {
                "type": "Brute Force",
                "pattern": re.compile(
                    r"(?i)(login|signin|authenticate|auth).*(attempt|try|fail|"
                    r"invalid|incorrect|wrong)|(password.*){3,}"
                ),
                "priority": 3
            },
            {
                "type": "URL Spoofing",
                "pattern": re.compile(
                    r"(?i)(@[^/]*@|%40.*%40|"
                    r"[a-z0-9\-]+\.com\.[a-z0-9\-]+\.com|"
                    r"https?:\/\/[^/]*@)"
                ),
                "priority": 2
            },
            {
                "type": "DDoS Payload",
                "pattern": re.compile(
                    r"([\x00-\x1f\x7f-\xff]{100,}|"
                    r"POST.*Content-Length:\s*[0-9]{8,}|"
                    r"(\r\n){50,})"
                ),
                "priority": 2
            },
            {
                "type": "Zero-Day Exploit",
                "pattern": re.compile(
                    r"(?i)(exploit|payload|shellcode|metasploit|meterpreter|"
                    r"0day|zeroday|CVE-\d{4}-\d{4,}|"
                    r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2})"
                ),
                "priority": 1
            }
        ]

        # Sort signatures by priority (lower number = higher priority)
        self.signatures.sort(key=lambda x: x.get('priority', 99))

    def match(self, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Match payload against all signature patterns.

        Args:
            payload: The network payload to analyze (URL, request body, etc.)

        Returns:
            Tuple of (rule_hit: bool, attack_type: str or None)
            - rule_hit: True if any signature matched
            - attack_type: The type of attack detected, or None if no match
        """
        if not payload or not isinstance(payload, str):
            return False, None

        # Try to match against all signatures (ordered by priority)
        for signature in self.signatures:
            if signature['pattern'].search(payload):
                return True, signature['type']

        # No match found
        return False, None

    def get_signature_count(self) -> int:
        """Return the total number of signatures loaded."""
        return len(self.signatures)

    def get_signature_types(self) -> list:
        """Return list of all detectable attack types."""
        return [sig['type'] for sig in self.signatures]
