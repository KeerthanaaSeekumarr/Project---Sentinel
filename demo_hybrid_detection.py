#!/usr/bin/env python3
"""
Hybrid Detection System Demo Script

This script demonstrates the key capabilities of the Sentinel-X
Hybrid Detection Engine for hackathon presentation.
"""

from detection.hybrid_detector import HybridDetector


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def demo_rule_based_detection():
    """Demonstrate rule-based pattern matching."""
    print_section("DEMO 1: Rule-Based Detection (Known Threats)")

    detector = HybridDetector()

    # Test cases showing different attack types
    attacks = [
        ("HTTP GET /api/user?id=' OR '1'='1 --", "SQL Injection"),
        ("HTTP GET <script>alert('xss')</script>", "XSS Attack"),
        ("HTTP GET ../../etc/passwd", "Path Traversal"),
        ("HTTP GET cmd.exe;whoami", "Command Injection"),
    ]

    for payload, attack_type in attacks:
        result = detector.analyze_packet(payload, "HTTP")
        print(f"Attack: {attack_type}")
        print(f"Payload: {payload}")
        print(f"✓ Rule Hit: {result['rule_hit']}")
        print(f"✓ Detected As: {result['attack_type']}")
        print(f"✓ Severity: {result['severity']}")
        print(f"✓ ML Score: {result['ml_score']:.3f}")
        print()


def demo_ml_based_detection():
    """Demonstrate ML-based feature analysis."""
    print_section("DEMO 2: ML-Based Detection (Obfuscated Threats)")

    detector = HybridDetector()

    # Obfuscated attacks that might bypass simple signatures
    obfuscated_attacks = [
        ("HTTP GET %2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-Encoded Path Traversal"),
        ("HTTP GET " + "A" * 150, "Buffer Overflow Pattern"),
        ("HTTP GET /api?param=test&user=admin&pass=admin", "Suspicious Parameters"),
    ]

    for payload, description in obfuscated_attacks:
        result = detector.analyze_packet(payload, "HTTP")
        summary = detector.get_detection_summary(payload)

        print(f"Attack: {description}")
        print(f"Payload: {payload[:60]}...")
        print(f"✓ Detection Method: {result['detection_method']}")
        print(f"✓ Attack Type: {result['attack_type']}")
        print(f"✓ Severity: {result['severity']}")
        print(f"✓ ML Score: {result['ml_score']:.3f}")

        # Show top ML features
        print(f"  Top ML Indicators:")
        for feature, score in summary['top_ml_indicators'][:3]:
            print(f"    - {feature}: {score:.3f}")
        print()


def demo_hybrid_synergy():
    """Demonstrate how hybrid detection provides better results."""
    print_section("DEMO 3: Hybrid Synergy (Rule + ML)")

    detector = HybridDetector()

    print("Comparing detection methods:\n")

    # Test payload
    payload = "HTTP GET /api/user?id=1' UNION SELECT password FROM users--"

    result = detector.analyze_packet(payload, "HTTP")

    print(f"Payload: {payload}")
    print()
    print("Individual Components:")
    print(f"  Rule Engine → {result['rule_hit']} (Detected: {result['attack_type']})")
    print(f"  ML Engine   → Score: {result['ml_score']:.3f}")
    print()
    print("Hybrid Result:")
    print(f"  ✓ Combined Detection: {result['detection_method']}")
    print(f"  ✓ Final Severity: {result['severity']}")
    print(f"  ✓ Confidence: {'HIGH' if result['ml_score'] >= 0.90 else 'MEDIUM'}")
    print()
    print("Why Hybrid is Better:")
    print("  • Rule engine provides exact attack identification")
    print("  • ML engine confirms with feature analysis")
    print("  • Combined score (0.90+) gives high confidence")
    print("  • Reduces false positives through dual validation")


def demo_normal_traffic():
    """Show that normal traffic is not flagged."""
    print_section("DEMO 4: Normal Traffic (No False Positives)")

    detector = HybridDetector()

    normal_payloads = [
        "HTTP GET /index.html",
        "HTTP GET /api/v1/status",
        "HTTP GET /products/view?id=123",
        "HTTP GET /assets/images/logo.png",
    ]

    print("Testing normal traffic patterns:\n")

    for payload in normal_payloads:
        result = detector.analyze_packet(payload, "HTTP")
        status = "✓ SAFE" if result['severity'] == 'Low' else "⚠ FLAGGED"
        print(f"{status} | {payload}")
        print(f"         Severity: {result['severity']}, ML Score: {result['ml_score']:.3f}")
        print()


def demo_severity_levels():
    """Demonstrate different severity classifications."""
    print_section("DEMO 5: Severity Classification")

    detector = HybridDetector()

    examples = [
        ("HTTP GET ' OR '1'='1--", "CRITICAL - Known SQL Injection with high ML score"),
        ("HTTP GET <img src=x onerror=alert(1)>", "CRITICAL - Known XSS pattern"),
        ("HTTP GET " + "suspicious" * 20, "HIGH/MEDIUM - Anomalous pattern"),
        ("HTTP GET /normal/page", "LOW - Benign traffic"),
    ]

    print("Severity Level Examples:\n")

    for payload, description in examples:
        result = detector.analyze_packet(payload, "HTTP")

        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'Low': '🟢'
        }

        emoji = severity_emoji.get(result['severity'], '⚪')

        print(f"{emoji} {result['severity']}: {description}")
        print(f"   Payload: {payload[:50]}...")
        print(f"   Rule Hit: {result['rule_hit']}, ML Score: {result['ml_score']:.3f}")
        print()


def demo_statistics():
    """Show detection statistics."""
    print_section("DEMO 6: Detection Statistics")

    detector = HybridDetector()

    # Analyze various payloads
    test_payloads = [
        "HTTP GET ' OR '1'='1--",
        "HTTP GET <script>alert(1)</script>",
        "HTTP GET ../../etc/passwd",
        "HTTP GET /normal/page",
        "HTTP GET /api/status",
        "HTTP GET cmd.exe;whoami",
        "HTTP GET " + "A" * 200,
    ]

    print("Analyzing sample traffic...\n")

    for payload in test_payloads:
        detector.analyze_packet(payload, "HTTP")

    stats = detector.get_stats()

    print("Detection Statistics:")
    print(f"  Total Packets Analyzed: {stats['total_analyzed']}")
    print(f"  Rule-Based Detections:  {stats['rule_hits']}")
    print(f"  ML-Only Detections:     {stats['ml_detections']}")
    print(f"  Hybrid Detections:      {stats['hybrid_detections']}")
    print()
    print("Threat Distribution:")
    print(f"  🔴 Critical: {stats['critical_threats']}")
    print(f"  🟠 High:     {stats['high_threats']}")
    print(f"  🟡 Medium:   {stats['medium_threats']}")
    print(f"  🟢 Low:      {stats['low_threats']}")


def main():
    """Run all demos."""
    print("\n" + "="*70)
    print("  SENTINEL-X HYBRID DETECTION SYSTEM")
    print("  Rule-First, ML-Fallback Architecture")
    print("="*70)

    demo_rule_based_detection()
    demo_ml_based_detection()
    demo_hybrid_synergy()
    demo_normal_traffic()
    demo_severity_levels()
    demo_statistics()

    print("\n" + "="*70)
    print("  🎯 DEMO COMPLETE")
    print("  The hybrid detection system is ready for production!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
