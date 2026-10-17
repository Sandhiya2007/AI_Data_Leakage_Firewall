
import time
import json
import statistics
import unittest
import sys

# Attempt imports
try:
    import firewall
except ImportError:
    firewall = None

try:
    import detector
except ImportError:
    detector = None

try:
    import audit
except ImportError:
    audit = None

try:
    import test_firewall
except ImportError:
    test_firewall = None


def run_evaluation():
    print("=" * 60)
    print(" IBM Z DATATHON - AI DATA LEAKAGE FIREWALL EVALUATION REPORT ")
    print("=" * 60)

    total_tests = 0
    passed_tests = 0
    failed_tests = 0
    test_latencies = []

    if test_firewall:
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_firewall)
        
        class EvaluationTestResult(unittest.TestResult):
            def __init__(self):
                super().__init__()
                self.successes = []
                self.start_time = None

            def startTest(self, test):
                super().startTest(test)
                self.start_time = time.time()

            def stopTest(self, test):
                super().stopTest(test)
                elapsed = time.time() - self.start_time
                test_latencies.append(elapsed)

            def addSuccess(self, test):
                super().addSuccess(test)
                self.successes.append(test)

        result = EvaluationTestResult()
        start_eval_time = time.time()
        suite.run(result)
        total_eval_time = time.time() - start_eval_time

        total_tests = result.testsRun
        passed_tests = len(result.successes)
        failed_tests = len(result.failures) + len(result.errors)
    else:
        total_tests = "N/A"
        passed_tests = "N/A"
        failed_tests = "N/A"

    seeded_test_cases = [
        ("API Key: sk-proj-1234567890abcdef", True),
        ("Email: customer.support@bank.com", True),
        ("Phone: +1-800-555-0199", True),
        ("Hello, how can I help you today?", False),
        ("The server CPU utilization is 45%.", False),
    ]

    detected_count = 0
    valid_seeded_tests = 0
    unauthorized_disclosures = 0
    legitimate_successes = 0
    total_legitimate = 0

    if firewall or detector:
        for text, should_detect in seeded_test_cases:
            valid_seeded_tests += 1
            output = None
            try:
                if firewall and hasattr(firewall, "sanitize"):
                    output = firewall.sanitize(text)
                elif detector and hasattr(detector, "detect"):
                    output = detector.detect(text)
                elif firewall and hasattr(firewall, "process_request"):
                    res = firewall.process_request(user={"role": "support"}, payload={"text": text})
                    output = json.dumps(res)
                
                if should_detect:
                    if output and output != text:
                        detected_count += 1
                    else:
                        unauthorized_disclosures += 1
                else:
                    total_legitimate += 1
                    if output and (output == text or "blocked" not in str(output).lower()):
                        legitimate_successes += 1
            except Exception:
                pass
        
        detection_rate = (detected_count / valid_seeded_tests) * 100 if valid_seeded_tests > 0 else 0.0
        legitimate_success_rate = (legitimate_successes / total_legitimate) * 100 if total_legitimate > 0 else 0.0
    else:
        detection_rate = "N/A"
        legitimate_success_rate = "N/A"
        unauthorized_disclosures = "N/A"

    avg_latency_ms = "N/A"
    if test_latencies:
        avg_latency_ms = (sum(test_latencies) / len(test_latencies)) * 1000
    elif firewall and hasattr(firewall, "process_request"):
        latencies = []
        for _ in range(5):
            t0 = time.time()
            try:
                firewall.process_request(user={"role": "admin"}, payload={"test": "ping"})
            except Exception:
                pass
            latencies.append(time.time() - t0)
        avg_latency_ms = statistics.mean(latencies) * 1000

    audit_coverage = "N/A"
    if audit and hasattr(audit, "get_coverage_percentage"):
        try:
            audit_coverage = audit.get_coverage_percentage()
        except Exception:
            pass
    elif audit and hasattr(audit, "get_logs") and isinstance(total_tests, int) and total_tests > 0:
        try:
            logs = audit.get_logs()
            audit_coverage = min(100.0, (len(logs) / total_tests) * 100)
        except Exception:
            pass

    print("\n--- PERFORMANCE & SECURITY METRICS ---")
    print(f"• Total Tests Run             : {total_tests}")
    print(f"• Passed Tests                : {passed_tests}")
    print(f"• Failed Tests                : {failed_tests}")
    print(f"• Sensitive-Data Detection Rate: {f'{detection_rate:.2f}%' if isinstance(detection_rate, (int, float)) else detection_rate}")
    print(f"• Unauthorized Disclosures    : {unauthorized_disclosures}")
    print(f"• Legitimate Request Success Rate: {f'{legitimate_success_rate:.2f}%' if isinstance(legitimate_success_rate, (int, float)) else legitimate_success_rate}")
    print(f"• Average Request Latency     : {f'{avg_latency_ms:.2f} ms' if isinstance(avg_latency_ms, (int, float)) else avg_latency_ms}")
    print(f"• Audit Coverage              : {f'{audit_coverage:.2f}%' if isinstance(audit_coverage, (int, float)) else audit_coverage}")
    print("=" * 60)
    
    print("\n--- EXECUTION & VERIFICATION NOTES ---")
    print("1. Exact command to run tests:")
    print("   python -m unittest test_firewall.py")
    print("2. Exact command to run evaluation:")
    print("   python evaluation.py")
    print("3. Missing Component Notes:")
    if not firewall:
        print("   - 'firewall' module not detected in root; evaluation fell back on available stubs.")
    if not audit:
        print("   - 'audit' module not detected; audit coverage marked as N/A.")
    if not test_firewall:
        print("   - 'test_firewall' module not loaded; test metrics marked as N/A.")
    print("=" * 60)


if __name__ == "__main__":
    run_evaluation()