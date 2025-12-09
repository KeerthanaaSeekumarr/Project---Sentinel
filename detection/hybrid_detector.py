"""
Hybrid Detection System - Integration Layer

Combines Rule-Based detection with ML-Based anomaly detection
to create a comprehensive threat detection engine.
"""

from typing import Dict, Optional
from .rule_engine import RuleEngine
from .ml_engine import MLEngine


class HybridDetector:
    """
    Rule-First, ML-Fallback Hybrid Detection Engine.

    This class integrates signature-based pattern matching with
    machine learning-based anomaly detection to provide:
    1. Fast detection of known threats (Rule Engine)
    2. Detection of obfuscated/novel threats (ML Engine)
    3. Weighted threat scoring and severity classification
    """

    def __init__(self):
        """Initialize both detection engines."""
        self.rule_engine = RuleEngine()
        self.ml_engine = MLEngine()

        # Statistics for monitoring
        self.stats = {
            'total_analyzed': 0,
            'rule_hits': 0,
            'ml_detections': 0,
            'hybrid_detections': 0,
            'critical_threats': 0,
            'high_threats': 0,
            'medium_threats': 0,
            'low_threats': 0
        }

    def analyze_packet(self, packet_info: str, protocol: str = "HTTP") -> Dict:
        """
        Analyze a network packet using hybrid detection.

        Args:
            packet_info: The payload to analyze (URL, request body, etc.)
            protocol: The network protocol (HTTP, HTTPS, etc.)

        Returns:
            Dictionary containing:
            - rule_hit: Boolean indicating if a signature matched
            - attack_type: Type of attack detected (or "Normal")
            - ml_score: ML confidence score (0.0-1.0)
            - severity: Final severity level (CRITICAL, HIGH, MEDIUM, Low)
            - detection_method: How the threat was detected
        """
        self.stats['total_analyzed'] += 1

        # Initialize result
        result = {
            'rule_hit': False,
            'attack_type': 'Normal',
            'ml_score': 0.0,
            'severity': 'Low',
            'detection_method': 'None'
        }

        # Skip analysis for non-HTTP protocols (for MVP)
        if protocol not in ["HTTP", "HTTPS"]:
            return result

        # STEP 1: Rule-Based Detection (Fast Path)
        rule_hit, attack_type = self.rule_engine.match(packet_info)

        if rule_hit:
            result['rule_hit'] = True
            result['attack_type'] = attack_type
            self.stats['rule_hits'] += 1

        # STEP 2: ML-Based Analysis (Always Run for Comprehensive Coverage)
        ml_score = self.ml_engine.calculate_score(packet_info)
        result['ml_score'] = round(ml_score, 4)

        # STEP 3: Boost ML Score for Rule Hits (High Confidence)
        if rule_hit:
            # When rule hits, ensure ML score is at least 0.90 for high confidence
            result['ml_score'] = max(result['ml_score'], 0.90)
            result['detection_method'] = 'Rule + ML'
        elif ml_score > 0.60:
            # ML detected something suspicious without rule hit
            result['detection_method'] = 'ML Only'
            self.stats['ml_detections'] += 1

            # Try to infer attack type from ML features
            if not rule_hit:
                result['attack_type'] = self._infer_attack_type(packet_info, ml_score)
        else:
            result['detection_method'] = 'None'

        # STEP 4: Calculate Final Severity
        result['severity'] = self._calculate_severity(
            rule_hit,
            result['ml_score'],
            result['attack_type']
        )

        # Update statistics
        self._update_stats(result['severity'])

        # Track hybrid detections (both rule and ML agree)
        if rule_hit and ml_score > 0.70:
            self.stats['hybrid_detections'] += 1

        return result

    def _calculate_severity(
        self,
        rule_hit: bool,
        ml_score: float,
        attack_type: str
    ) -> str:
        """
        Calculate final severity based on hybrid detection results.

        Severity Levels (as per requirements):
        - CRITICAL: High confidence Rule Hit OR ML score > 0.95
        - HIGH: Strong ML score without rule hit (possible evasion)
        - MEDIUM: Moderate suspicion
        - Low: Normal traffic
        """
        # CRITICAL: High confidence from both OR very high ML score
        if rule_hit and ml_score >= 0.90:
            return "CRITICAL"

        if ml_score > 0.95:
            return "CRITICAL"

        # HIGH: Strong ML score (indicates anomaly/evasion)
        if ml_score > 0.80:
            return "HIGH"

        # MEDIUM: Moderate suspicion
        if ml_score > 0.60:
            return "MEDIUM"

        # MEDIUM: Rule hit but low ML score (might be false positive)
        if rule_hit and ml_score < 0.90:
            return "MEDIUM"

        # Low: Normal traffic
        return "Low"

    def _infer_attack_type(self, payload: str, ml_score: float) -> str:
        """
        Infer likely attack type when ML detects threat without rule hit.

        This handles obfuscated attacks that bypass signature detection.
        """
        payload_lower = payload.lower()

        # Check for common attack indicators
        if any(keyword in payload_lower for keyword in ['select', 'union', 'sql', 'drop', 'insert']):
            return "SQL Injection (Obfuscated)"

        if any(keyword in payload_lower for keyword in ['script', 'javascript', 'onerror', 'alert', 'xss']):
            return "XSS Attempt (Obfuscated)"

        if any(keyword in payload_lower for keyword in ['../', '..\\', 'etc/passwd', 'windows']):
            return "Path Traversal (Obfuscated)"

        if any(keyword in payload_lower for keyword in ['cmd', 'exec', 'system', 'bash', 'powershell']):
            return "Command Injection (Obfuscated)"

        # Check for encoding/obfuscation patterns
        if '%' in payload and payload.count('%') > 3:
            return "Encoded Payload"

        if '\\x' in payload_lower:
            return "Hex Encoded Payload"

        # High ML score but no clear pattern - likely novel attack
        if ml_score > 0.85:
            return "Novel Attack Pattern"

        # Default to anomalous behavior
        return "Anomalous Behavior"

    def _update_stats(self, severity: str):
        """Update detection statistics."""
        if severity == "CRITICAL":
            self.stats['critical_threats'] += 1
        elif severity == "HIGH":
            self.stats['high_threats'] += 1
        elif severity == "MEDIUM":
            self.stats['medium_threats'] += 1
        else:
            self.stats['low_threats'] += 1

    def get_stats(self) -> Dict:
        """
        Get detection statistics.

        Useful for monitoring and demo purposes.
        """
        return self.stats.copy()

    def get_detection_summary(self, packet_info: str) -> Dict:
        """
        Get detailed detection summary with feature explanation.

        Useful for debugging and demonstrating how detection works.
        """
        # Get basic detection result
        result = self.analyze_packet(packet_info)

        # Get ML feature breakdown
        ml_details = self.ml_engine.get_feature_explanation(packet_info)

        # Combine results
        summary = {
            **result,
            'ml_features': ml_details['features'],
            'top_ml_indicators': ml_details['top_indicators'],
            'rule_signatures_loaded': self.rule_engine.get_signature_count(),
            'detection_explanation': self._generate_explanation(result)
        }

        return summary

    def _generate_explanation(self, result: Dict) -> str:
        """
        Generate human-readable explanation of detection.

        Perfect for hackathon demo to show how the system works.
        """
        if result['severity'] == 'Low':
            return "Normal traffic - no threats detected"

        explanation_parts = []

        if result['rule_hit']:
            explanation_parts.append(
                f"Rule Engine detected: {result['attack_type']}"
            )

        ml_score = result['ml_score']
        if ml_score > 0.60:
            confidence = "high" if ml_score > 0.80 else "moderate"
            explanation_parts.append(
                f"ML Engine shows {confidence} confidence ({ml_score:.2f}) "
                f"based on payload features"
            )

        if result['rule_hit'] and ml_score > 0.90:
            explanation_parts.append(
                "Both engines agree - HIGH CONFIDENCE detection"
            )
        elif not result['rule_hit'] and ml_score > 0.80:
            explanation_parts.append(
                "ML-only detection suggests possible evasion attempt"
            )

        return " | ".join(explanation_parts)

    def reset_stats(self):
        """Reset detection statistics."""
        for key in self.stats:
            self.stats[key] = 0
