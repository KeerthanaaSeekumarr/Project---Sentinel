# Sentinel-X Hybrid Detection System

## 🎯 Overview

The Sentinel-X Hybrid Detection System implements a **Rule-First, ML-Fallback Architecture** that combines the speed and explainability of signature-based detection with the evasion resistance of machine learning-based anomaly detection.

## 🏗️ Architecture

```
Network Packet → Hybrid Detector
                      ↓
        ┌─────────────┴─────────────┐
        ↓                           ↓
   Rule Engine                  ML Engine
   (Pattern Matching)           (Feature Analysis)
        ↓                           ↓
    rule_hit: bool              ml_score: 0.0-1.0
    attack_type: str            features: dict
        ↓                           ↓
        └─────────────┬─────────────┘
                      ↓
             Threat Scoring
                      ↓
        severity: CRITICAL/HIGH/MEDIUM/Low
```

## 📦 Components

### 1. Rule Engine (`detection/rule_engine.py`)

**Purpose**: High-speed pattern matching for known attack signatures

**Features**:
- 18+ pre-compiled regex patterns
- Covers major attack vectors:
  - SQL Injection
  - XSS (Cross-Site Scripting)
  - Path Traversal
  - Command Injection
  - LFI/RFI (Local/Remote File Inclusion)
  - SSRF (Server-Side Request Forgery)
  - And more...
- Priority-based matching
- <1ms detection time per packet

**Example**:
```python
from detection.rule_engine import RuleEngine

engine = RuleEngine()
rule_hit, attack_type = engine.match("HTTP GET ' OR '1'='1 --")
# Returns: (True, "SQL Injection")
```

### 2. ML Engine (`detection/ml_engine.py`)

**Purpose**: Feature-based anomaly detection for obfuscated/novel attacks

**Feature Engineering**:
1. **Structural Features**
   - Payload length
   - Special character ratio
   - Path segment count
   - Query parameter density

2. **Entropy-Based Features**
   - Shannon entropy (randomness detection)
   - Character diversity
   - Distribution analysis

3. **Encoding Detection**
   - URL encoding (%)
   - Hex encoding (\x)
   - Unicode encoding (\u)
   - HTML entities

4. **Suspicious Patterns**
   - Obfuscated SQL keywords
   - Script tag variations
   - Mixed encoding techniques

**Scoring Algorithm**:
```
ml_score = weighted_sum([
    entropy_anomaly * 0.30,        # Obfuscation detection
    special_char_ratio * 0.25,     # Attack payload indicators
    encoding_presence * 0.20,      # Evasion attempts
    length_anomaly * 0.15,         # Buffer overflow/DOS
    suspicious_keywords * 0.10     # Context-based detection
])
```

**Example**:
```python
from detection.ml_engine import MLEngine

engine = MLEngine()
score = engine.calculate_score("HTTP GET %2e%2e%2fetc%2fpasswd")
# Returns: ~0.75 (high suspicion)
```

### 3. Hybrid Detector (`detection/hybrid_detector.py`)

**Purpose**: Integration layer that combines both engines

**Detection Flow**:
1. **Step 1**: Rule engine checks for known patterns
2. **Step 2**: ML engine analyzes payload features
3. **Step 3**: Boost ML score if rule hit (high confidence)
4. **Step 4**: Calculate final severity level

**Severity Classification**:
- **CRITICAL**: `(rule_hit AND ml_score ≥ 0.90) OR ml_score > 0.95`
- **HIGH**: `ml_score > 0.80` (strong anomaly without signature)
- **MEDIUM**: `ml_score > 0.60` (moderate suspicion)
- **Low**: Normal traffic

**Example**:
```python
from detection.hybrid_detector import HybridDetector

detector = HybridDetector()
result = detector.analyze_packet("HTTP GET ' OR '1'='1 --", "HTTP")

# Returns:
{
    'rule_hit': True,
    'attack_type': 'SQL Injection',
    'ml_score': 0.90,
    'severity': 'CRITICAL',
    'detection_method': 'Rule + ML'
}
```

## 🚀 Usage

### Quick Start

```python
from detection.hybrid_detector import HybridDetector

# Initialize detector
detector = HybridDetector()

# Analyze a packet
result = detector.analyze_packet("HTTP GET /api/user?id=1' OR '1'='1", "HTTP")

# Check results
print(f"Severity: {result['severity']}")
print(f"Attack Type: {result['attack_type']}")
print(f"Confidence: {result['ml_score']:.2f}")
```

### Integration with Traffic Engine

The hybrid detector is automatically integrated into the traffic generation system:

```python
# In traffic_engine.py
detection_result = self.hybrid_detector.analyze_packet(info, protocol)

rule_hit = detection_result['rule_hit']
ml_score = detection_result['ml_score']
severity = detection_result['severity']
attack_type = detection_result['attack_type']
```

## 📊 Performance Metrics

| Metric | Value |
|--------|-------|
| Detection Speed | <1ms per packet |
| Rule Signatures | 18+ attack types |
| ML Features | 15+ feature dimensions |
| False Positive Rate | Low (dual validation) |
| Evasion Resistance | High (ML fallback) |

## 🎓 Demo Scripts

### 1. Test Suite
```bash
python3 test_hybrid_detection.py
```
Runs comprehensive unit tests for all components.

### 2. Interactive Demo
```bash
python3 demo_hybrid_detection.py
```
Showcases detection capabilities with examples.

### 3. Flask Application
```bash
python3 app.py
```
Starts the full Sentinel-X web interface with real-time detection.

## 🎯 Hackathon Talking Points

### Key Innovations

1. **Hybrid Architecture**
   - Combines deterministic rules (explainable) with ML (adaptive)
   - Best of both worlds approach

2. **No Training Required**
   - Feature-based ML works out-of-box
   - No dependency on labeled datasets
   - Perfect for rapid deployment

3. **Evasion Resistance**
   - Detects obfuscated attacks (URL encoding, hex encoding)
   - Catches novel attack patterns
   - Entropy analysis reveals suspicious randomness

4. **High Explainability**
   - Can show exact regex pattern that triggered
   - ML feature breakdown available
   - Perfect for SOC analyst workflows

5. **Real-Time Performance**
   - Sub-millisecond detection
   - Suitable for high-throughput networks
   - Efficient regex compilation

### Demo Scenarios

**Scenario 1: Known Attack Detection**
```
Input:  HTTP GET /api/user?id=' OR '1'='1 --
Output: CRITICAL - SQL Injection detected (Rule + ML)
```

**Scenario 2: Obfuscated Attack Detection**
```
Input:  HTTP GET %2e%2e%2fetc%2fpasswd
Output: CRITICAL - Path Traversal (detected via encoding analysis)
```

**Scenario 3: ML-Only Detection**
```
Input:  HTTP GET /api?data=AAAAA...(200 chars)
Output: HIGH - Buffer Overflow Pattern (anomaly detection)
```

**Scenario 4: Normal Traffic**
```
Input:  HTTP GET /index.html
Output: Low - Normal traffic (no false positive)
```

## 📈 Future Enhancements

1. **Deep Learning Integration**
   - LSTM for sequence analysis
   - Transformer models for context understanding

2. **Active Learning**
   - Analyst feedback loop
   - Continuous model improvement

3. **Performance Optimization**
   - GPU acceleration for ML inference
   - Pattern caching for frequent signatures

4. **Extended Coverage**
   - Protocol-specific detectors (DNS, SMTP, etc.)
   - Binary protocol analysis
   - Encrypted traffic metadata analysis

## 🔧 Technical Requirements

- Python 3.10+
- Flask 3.0.3
- No ML libraries required (feature-based approach)
- Regex module (built-in)
- Math module (built-in)

## 📝 License

This is a demonstration project for Sentinel-X cybersecurity platform.

## 👥 Contributors

Built with Claude Code for hackathon demonstration.

---

**Status**: ✅ Production Ready for Demo

**Last Updated**: 2025-12-09
