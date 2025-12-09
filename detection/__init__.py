"""
Hybrid Detection System for Sentinel-X

This package implements a Rule-First, ML-Fallback hybrid threat detection engine
that combines signature-based pattern matching with machine learning-based anomaly detection.
"""

from .rule_engine import RuleEngine
from .ml_engine import MLEngine
from .hybrid_detector import HybridDetector

__all__ = ['RuleEngine', 'MLEngine', 'HybridDetector']
