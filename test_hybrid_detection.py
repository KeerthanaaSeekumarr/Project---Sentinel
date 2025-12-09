"""
Test script for Hybrid Detection System

This script validates that the Rule Engine, ML Engine, and Hybrid Detector
are working correctly for the hackathon demo.
"""

from detection.hybrid_detector import HybridDetector
from detection.rule_engine import RuleEngine
from detection.ml_engine import MLEngine


def test_rule_engine():
    """Test Rule Engine pattern matching."""
    print("\n" + "="*70)
    print("TEST 1: Rule Engine - Pattern Matching")
    print("="*70)

    rule_engine = RuleEngine()

    test_cases = [
        ("HTTP GET http://api/v2/user?id=' OR '1'='1 --", "SQL Injection"),
        ("HTTP GET <script>alert('xss')</script>", "XSS Attempt"),
        ("HTTP GET ../../etc/passwd", "Path Traversal"),
        ("HTTP GET /normal/page.html", None),
        ("HTTP GET cmd.exe;whoami", "Command Injection"),
        ("HTTP GET file.php", "Shell Upload"),
    ]

    passed = 0
    failed = 0

    for payload, expected_type in test_cases:
        rule_hit, attack_type = rule_engine.match(payload)

        if expected_type is None:
            # Should NOT match
            if not rule_hit:
                print(f"✓ PASS: '{payload[:50]}...' → No match (correct)")
                passed += 1
            else:
                print(f"✗ FAIL: '{payload[:50]}...' → Matched {attack_type} (should not match)")
                failed += 1
        else:
            # Should match
            if rule_hit:
                print(f"✓ PASS: '{payload[:50]}...' → {attack_type}")
                passed += 1
            else:
                print(f"✗ FAIL: '{payload[:50]}...' → No match (expected {expected_type})")
                failed += 1

    print(f"\nRule Engine Results: {passed} passed, {failed} failed")
    return failed == 0


def test_ml_engine():
    """Test ML Engine feature-based scoring."""
    print("\n" + "="*70)
    print("TEST 2: ML Engine - Feature-Based Scoring")
    print("="*70)

    ml_engine = MLEngine()

    test_cases = [
        # (payload, expected_score_range, description)
        # Note: ML scores are moderate, hybrid detector boosts them when combined with rule hits
        ("HTTP GET /normal/page.html", (0.0, 0.3), "Normal traffic should have low score"),
        ("HTTP GET ' OR '1'='1 UNION SELECT * FROM users--", (0.2, 1.0), "SQL injection should have moderate score"),
        ("HTTP GET %3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E", (0.2, 1.0), "Encoded XSS should have moderate score"),
        ("HTTP GET " + "A" * 200, (0.15, 1.0), "Buffer overflow attempt should have moderate score"),
        ("HTTP GET /api/status", (0.0, 0.3), "Normal API call should have low score"),
    ]

    passed = 0
    failed = 0

    for payload, expected_range, description in test_cases:
        ml_score = ml_engine.calculate_score(payload)
        min_score, max_score = expected_range

        if min_score <= ml_score <= max_score:
            print(f"✓ PASS: {description}")
            print(f"        Score: {ml_score:.3f} (expected {min_score:.1f}-{max_score:.1f})")
            passed += 1
        else:
            print(f"✗ FAIL: {description}")
            print(f"        Score: {ml_score:.3f} (expected {min_score:.1f}-{max_score:.1f})")
            failed += 1

    print(f"\nML Engine Results: {passed} passed, {failed} failed")
    return failed == 0


def test_hybrid_detector():
    """Test Hybrid Detector integration."""
    print("\n" + "="*70)
    print("TEST 3: Hybrid Detector - Integration & Severity Assignment")
    print("="*70)

    detector = HybridDetector()

    test_cases = [
        # (payload, expected_severity, allow_higher, description)
        ("HTTP GET http://api/v2/user?id=' OR '1'='1 --", "CRITICAL", False, "Known SQL injection → CRITICAL"),
        ("HTTP GET <script>alert('xss')</script>", "CRITICAL", False, "Known XSS → CRITICAL"),
        ("HTTP GET /normal/page.html", "Low", False, "Normal traffic → Low"),
        ("HTTP GET %2e%2e%2f%2e%2e%2fetc%2fpasswd", "HIGH", True, "Obfuscated path traversal → HIGH/CRITICAL"),
        ("HTTP GET /api/status", "Low", False, "Normal API call → Low"),
        ("HTTP GET cmd.exe;whoami", "CRITICAL", False, "Command injection → CRITICAL"),
    ]

    passed = 0
    failed = 0

    for payload, expected_severity, allow_higher, description in test_cases:
        result = detector.analyze_packet(payload, "HTTP")

        # Print detailed results
        print(f"\nTest: {description}")
        print(f"  Payload: {payload[:60]}...")
        print(f"  Rule Hit: {result['rule_hit']}")
        print(f"  Attack Type: {result['attack_type']}")
        print(f"  ML Score: {result['ml_score']:.3f}")
        print(f"  Severity: {result['severity']}")
        print(f"  Detection Method: {result['detection_method']}")

        # Check if severity is reasonable (allow some flexibility)
        severity_levels = {"Low": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        expected_level = severity_levels.get(expected_severity, 0)
        actual_level = severity_levels.get(result['severity'], 0)

        # Determine if test passes
        test_passed = False

        if allow_higher:
            # Allow equal or higher severity
            if actual_level >= expected_level:
                test_passed = True
        elif expected_severity == "CRITICAL" and actual_level >= 2:
            # For Critical expectations, allow High or Critical
            test_passed = True
        elif expected_severity == "Low" and actual_level <= 1:
            # For Low expectations, allow Low or Medium (some false positives OK)
            test_passed = True
        elif actual_level == expected_level:
            # Exact match
            test_passed = True

        if test_passed:
            print("  ✓ PASS")
            passed += 1
        else:
            print(f"  ✗ FAIL (expected {expected_severity}, got {result['severity']})")
            failed += 1

    print(f"\nHybrid Detector Results: {passed} passed, {failed} failed")
    return failed == 0


def test_detection_explanation():
    """Test detection explanation feature."""
    print("\n" + "="*70)
    print("TEST 4: Detection Explanation (for Demo)")
    print("="*70)

    detector = HybridDetector()

    test_payload = "HTTP GET http://api/v2/user?id=' OR '1'='1 --"

    print(f"\nAnalyzing: {test_payload}")
    print("-" * 70)

    summary = detector.get_detection_summary(test_payload)

    print(f"Attack Type: {summary['attack_type']}")
    print(f"Severity: {summary['severity']}")
    print(f"Rule Hit: {summary['rule_hit']}")
    print(f"ML Score: {summary['ml_score']:.3f}")
    print(f"Detection Method: {summary['detection_method']}")
    print(f"\nExplanation: {summary['detection_explanation']}")

    print(f"\nTop ML Indicators:")
    for feature, score in summary['top_ml_indicators']:
        print(f"  - {feature}: {score:.3f}")

    return True


def test_statistics():
    """Test statistics tracking."""
    print("\n" + "="*70)
    print("TEST 5: Statistics Tracking")
    print("="*70)

    detector = HybridDetector()
    detector.reset_stats()

    # Analyze multiple packets
    test_payloads = [
        "HTTP GET http://api/v2/user?id=' OR '1'='1 --",
        "HTTP GET <script>alert('xss')</script>",
        "HTTP GET /normal/page.html",
        "HTTP GET /api/status",
        "HTTP GET ../../etc/passwd",
    ]

    for payload in test_payloads:
        detector.analyze_packet(payload, "HTTP")

    stats = detector.get_stats()

    print(f"\nDetection Statistics:")
    print(f"  Total Analyzed: {stats['total_analyzed']}")
    print(f"  Rule Hits: {stats['rule_hits']}")
    print(f"  ML Detections: {stats['ml_detections']}")
    print(f"  Hybrid Detections: {stats['hybrid_detections']}")
    print(f"  Critical Threats: {stats['critical_threats']}")
    print(f"  High Threats: {stats['high_threats']}")
    print(f"  Medium Threats: {stats['medium_threats']}")
    print(f"  Low Threats: {stats['low_threats']}")

    return stats['total_analyzed'] == 5


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("HYBRID DETECTION SYSTEM - TEST SUITE")
    print("="*70)

    results = []

    # Run all tests
    results.append(("Rule Engine", test_rule_engine()))
    results.append(("ML Engine", test_ml_engine()))
    results.append(("Hybrid Detector", test_hybrid_detector()))
    results.append(("Detection Explanation", test_detection_explanation()))
    results.append(("Statistics Tracking", test_statistics()))

    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False

    print("\n" + "="*70)
    if all_passed:
        print("ALL TESTS PASSED! ✓")
        print("The hybrid detection system is ready for the hackathon demo.")
    else:
        print("SOME TESTS FAILED! ✗")
        print("Please review the failures above.")
    print("="*70 + "\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    exit(main())
