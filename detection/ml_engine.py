"""
ML-Based Feature Extraction and Scoring Engine

Implements machine learning-based anomaly detection using feature engineering
and heuristic scoring to detect obfuscated and novel attacks.
"""

import re
import math
from typing import Dict
from collections import Counter


class MLEngine:
    """
    Feature-based machine learning engine for threat detection.

    Analyzes payload characteristics to detect evasion attempts and
    novel attack patterns that might bypass signature-based detection.
    """

    def __init__(self):
        """Initialize the ML engine with baseline thresholds."""
        # Baseline values for normal traffic (estimated)
        self.normal_url_length = 50
        self.normal_entropy = 3.5
        self.normal_special_char_ratio = 0.15

        # Suspicious keywords that might be obfuscated
        self.suspicious_keywords = [
            'union', 'select', 'insert', 'update', 'delete', 'drop',
            'script', 'javascript', 'onerror', 'onload', 'eval', 'alert',
            'exec', 'system', 'cmd', 'powershell', 'bash', 'wget', 'curl',
            'passwd', 'shadow', 'boot.ini', 'win.ini'
        ]

        # Suspicious encoded patterns
        self.encoded_patterns = [
            r'%[0-9a-fA-F]{2}',      # URL encoding
            r'\\x[0-9a-fA-F]{2}',    # Hex encoding
            r'\\u[0-9a-fA-F]{4}',    # Unicode encoding
            r'&#x[0-9a-fA-F]+;',     # HTML hex entity
            r'&#\d+;',                # HTML decimal entity
        ]

    def calculate_score(self, payload: str) -> float:
        """
        Calculate ML-based threat score for a payload.

        Args:
            payload: The network payload to analyze (URL, request body, etc.)

        Returns:
            Float score between 0.0 (benign) and 1.0 (malicious)
        """
        if not payload or not isinstance(payload, str):
            return 0.0

        # Extract features
        features = self._extract_features(payload)

        # Calculate weighted score
        score = self._calculate_weighted_score(features)

        # Clamp score between 0.0 and 1.0
        return max(0.0, min(1.0, score))

    def _extract_features(self, payload: str) -> Dict[str, float]:
        """
        Extract all features from the payload.

        Returns:
            Dictionary of feature names and their normalized values
        """
        features = {}

        # 1. Structural Features
        features['length'] = len(payload)
        features['special_char_count'] = self._count_special_chars(payload)
        features['special_char_ratio'] = features['special_char_count'] / max(len(payload), 1)
        features['slash_count'] = payload.count('/') + payload.count('\\')
        features['dot_count'] = payload.count('.')
        features['query_param_count'] = payload.count('&') + payload.count('?')

        # 2. Entropy-Based Features
        features['entropy'] = self._calculate_entropy(payload)
        features['char_diversity'] = len(set(payload)) / max(len(payload), 1)

        # 3. Encoding Detection
        features['encoding_score'] = self._detect_encoding(payload)
        features['has_url_encoding'] = 1.0 if '%' in payload else 0.0
        features['has_hex_encoding'] = 1.0 if '\\x' in payload.lower() else 0.0

        # 4. Suspicious Pattern Features
        features['suspicious_keyword_score'] = self._detect_suspicious_keywords(payload)
        features['sql_keyword_density'] = self._detect_sql_patterns(payload)
        features['script_tag_obfuscation'] = self._detect_script_obfuscation(payload)

        # 5. Anomaly Features
        features['length_anomaly'] = self._calculate_length_anomaly(features['length'])
        features['entropy_anomaly'] = self._calculate_entropy_anomaly(features['entropy'])
        features['consecutive_special_chars'] = self._detect_consecutive_special_chars(payload)

        return features

    def _calculate_weighted_score(self, features: Dict[str, float]) -> float:
        """
        Calculate final ML score using weighted feature combination.

        Weights are tuned for hackathon demo to balance detection and false positives.
        """
        score = 0.0

        # High entropy indicates obfuscation or encoding (30% weight)
        entropy_score = min(features['entropy_anomaly'], 1.0)
        score += entropy_score * 0.30

        # High special character ratio indicates attack payloads (25% weight)
        special_char_score = min(features['special_char_ratio'] * 3, 1.0)
        score += special_char_score * 0.25

        # Encoding presence suggests evasion attempts (20% weight)
        encoding_score = min(features['encoding_score'], 1.0)
        score += encoding_score * 0.20

        # Abnormal length (too long or too short) is suspicious (15% weight)
        length_score = min(features['length_anomaly'], 1.0)
        score += length_score * 0.15

        # Suspicious keywords (even if obfuscated) (10% weight)
        keyword_score = features['suspicious_keyword_score']
        keyword_score += features['sql_keyword_density']
        keyword_score += features['script_tag_obfuscation']
        keyword_score = min(keyword_score, 1.0)
        score += keyword_score * 0.10

        return score

    def _count_special_chars(self, payload: str) -> int:
        """Count special characters commonly used in attacks."""
        special_chars = r'''!@#$%^&*()_+-=[]{}|;':",.<>?/\`~'''
        return sum(1 for char in payload if char in special_chars)

    def _calculate_entropy(self, payload: str) -> float:
        """
        Calculate Shannon entropy of the payload.

        Higher entropy indicates more randomness/obfuscation.
        """
        if not payload:
            return 0.0

        # Count character frequencies
        counter = Counter(payload)
        length = len(payload)

        # Calculate Shannon entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _detect_encoding(self, payload: str) -> float:
        """
        Detect presence of various encoding schemes.

        Returns a score between 0.0 and 1.0 based on encoding density.
        """
        encoding_count = 0
        total_patterns = len(self.encoded_patterns)

        for pattern in self.encoded_patterns:
            matches = re.findall(pattern, payload)
            if matches:
                # Score based on density of encoded characters
                encoding_count += min(len(matches) / 5.0, 1.0)

        return min(encoding_count / total_patterns, 1.0)

    def _detect_suspicious_keywords(self, payload: str) -> float:
        """
        Detect suspicious keywords even if partially obfuscated.

        Returns score between 0.0 and 1.0.
        """
        payload_lower = payload.lower()
        matched_keywords = 0

        for keyword in self.suspicious_keywords:
            # Check for exact match
            if keyword in payload_lower:
                matched_keywords += 1
            # Check for partial match (obfuscation)
            elif any(char in payload_lower for char in keyword):
                # Give partial credit for potential obfuscation
                if len([c for c in keyword if c in payload_lower]) >= len(keyword) * 0.6:
                    matched_keywords += 0.5

        # Normalize by number of keywords
        return min(matched_keywords / 5.0, 1.0)

    def _detect_sql_patterns(self, payload: str) -> float:
        """
        Detect SQL-specific patterns and keywords.

        Returns score between 0.0 and 1.0.
        """
        sql_indicators = 0
        payload_lower = payload.lower()

        # Check for SQL operators and patterns
        sql_patterns = [
            (r"'\s*or\s*'", 1.0),
            (r"1\s*=\s*1", 0.8),
            (r"--", 0.7),
            (r";", 0.5),
            (r"union\s+select", 1.0),
            (r"drop\s+table", 1.0),
        ]

        for pattern, weight in sql_patterns:
            if re.search(pattern, payload_lower):
                sql_indicators += weight

        return min(sql_indicators / 3.0, 1.0)

    def _detect_script_obfuscation(self, payload: str) -> float:
        """
        Detect obfuscated script tags or JavaScript.

        Returns score between 0.0 and 1.0.
        """
        script_indicators = 0
        payload_lower = payload.lower()

        # Check for script-related patterns
        script_patterns = [
            r'<\s*script',
            r'javascript\s*:',
            r'on\w+\s*=',  # Event handlers
            r'eval\s*\(',
            r'alert\s*\(',
            r'<\s*iframe',
        ]

        for pattern in script_patterns:
            if re.search(pattern, payload_lower):
                script_indicators += 1

        return min(script_indicators / 3.0, 1.0)

    def _calculate_length_anomaly(self, length: int) -> float:
        """
        Calculate how abnormal the payload length is.

        Returns score between 0.0 and 1.0.
        """
        # Very short or very long payloads are suspicious
        if length < 10:
            return 0.3  # Suspiciously short
        elif length > 200:
            # Scale score based on how much longer than normal
            excess = (length - 200) / 200
            return min(excess, 1.0)
        else:
            # Normal length range
            return 0.0

    def _calculate_entropy_anomaly(self, entropy: float) -> float:
        """
        Calculate how abnormal the entropy is compared to normal traffic.

        Returns score between 0.0 and 1.0.
        """
        # Normal entropy is around 3.5-4.5 for typical URLs
        # Higher entropy suggests obfuscation or encoding
        if entropy > 4.5:
            anomaly = (entropy - 4.5) / 3.5  # Max entropy is ~8
            return min(anomaly, 1.0)
        elif entropy < 2.0:
            # Very low entropy is also suspicious (might be padding/overflow)
            anomaly = (2.0 - entropy) / 2.0
            return min(anomaly * 0.5, 1.0)  # Lower weight for low entropy
        else:
            return 0.0

    def _detect_consecutive_special_chars(self, payload: str) -> float:
        """
        Detect unusual sequences of special characters.

        Returns score between 0.0 and 1.0.
        """
        special_chars = r'''!@#$%^&*()_+-=[]{}|;':",.<>?/\`~'''

        max_consecutive = 0
        current_consecutive = 0

        for char in payload:
            if char in special_chars:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 0

        # More than 3 consecutive special chars is suspicious
        if max_consecutive > 3:
            return min((max_consecutive - 3) / 7.0, 1.0)
        return 0.0

    def get_feature_explanation(self, payload: str) -> Dict[str, any]:
        """
        Get detailed feature breakdown for explainability.

        Useful for debugging and demonstrating how the ML engine works.
        """
        features = self._extract_features(payload)
        score = self._calculate_weighted_score(features)

        return {
            'ml_score': score,
            'features': features,
            'top_indicators': self._get_top_indicators(features)
        }

    def _get_top_indicators(self, features: Dict[str, float]) -> list:
        """Get the top 3 features contributing to the score."""
        feature_scores = {
            'entropy': features.get('entropy_anomaly', 0) * 0.30,
            'special_chars': min(features.get('special_char_ratio', 0) * 3, 1.0) * 0.25,
            'encoding': features.get('encoding_score', 0) * 0.20,
            'length': features.get('length_anomaly', 0) * 0.15,
            'keywords': (features.get('suspicious_keyword_score', 0) +
                        features.get('sql_keyword_density', 0) +
                        features.get('script_tag_obfuscation', 0)) * 0.10
        }

        # Sort by score and return top 3
        sorted_features = sorted(feature_scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_features[:3]
