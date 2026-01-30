#!/usr/bin/env python3
"""
Extra security tests for PipeForge v1.1.0
Tests OWASP-style security edge cases.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeforge import (
    PipelineConfig, Platform, Language, Target, Registry,
    ValidationError, SecurityError,
    sanitize_string, validate_service_name, validate_aws_region,
    generate_pipeline
)

passed = 0
failed = 0


def test_security(name, fn, should_raise=None):
    """Test security scenario"""
    global passed, failed
    try:
        result = fn()
        if should_raise:
            print(f"  [FAIL] {name}: Expected {should_raise.__name__} but got result")
            failed += 1
        else:
            print(f"  [PASS] {name}")
            passed += 1
    except (ValidationError, SecurityError) as e:
        if should_raise and isinstance(e, should_raise):
            print(f"  [PASS] {name}")
            passed += 1
        else:
            print(f"  [FAIL] {name}: Got {type(e).__name__} - {e}")
            failed += 1
    except Exception as e:
        print(f"  [FAIL] {name}: Unexpected {type(e).__name__} - {e}")
        failed += 1


def run_security_tests():
    """Run extra security tests"""
    global passed, failed

    print("\n" + "="*60)
    print("  PipeForge - Extra Security Tests")
    print("="*60)

    # ============================================
    # COMMAND INJECTION TESTS
    # ============================================
    print("\n--- Command Injection Prevention ---")

    test_security("Blocks semicolon injection",
        lambda: sanitize_string("test; rm -rf /", "test"),
        SecurityError)

    test_security("Blocks pipe injection",
        lambda: sanitize_string("test | cat /etc/passwd", "test"),
        SecurityError)

    test_security("Blocks and injection",
        lambda: sanitize_string("test && malicious", "test"),
        SecurityError)

    test_security("Blocks backtick injection",
        lambda: sanitize_string("test `whoami`", "test"),
        SecurityError)

    test_security("Blocks dollar sign injection",
        lambda: sanitize_string("test $(id)", "test"),
        SecurityError)

    test_security("Blocks variable expansion",
        lambda: sanitize_string("test ${PATH}", "test"),
        SecurityError)

    test_security("Blocks newline injection",
        lambda: sanitize_string("test\nmalicious", "test"),
        SecurityError)

    test_security("Blocks carriage return injection",
        lambda: sanitize_string("test\rmalicious", "test"),
        SecurityError)

    test_security("Blocks null byte injection",
        lambda: sanitize_string("test\x00malicious", "test"),
        SecurityError)

    # ============================================
    # PATH TRAVERSAL TESTS
    # ============================================
    print("\n--- Path Traversal Prevention ---")

    test_security("Blocks ../ traversal",
        lambda: sanitize_string("../etc/passwd", "test"),
        SecurityError)

    test_security("Blocks ..\\ traversal",
        lambda: sanitize_string("..\\windows\\system32", "test"),
        SecurityError)

    test_security("Blocks encoded traversal",
        lambda: sanitize_string("test/..\\etc", "test"),
        SecurityError)

    # ============================================
    # XSS/HTML INJECTION TESTS
    # ============================================
    print("\n--- HTML/XSS Prevention ---")

    test_security("Blocks HTML tags",
        lambda: sanitize_string("<script>alert(1)</script>", "test"),
        SecurityError)

    test_security("Blocks single quotes",
        lambda: sanitize_string("test'onclick='alert(1)", "test"),
        SecurityError)

    test_security("Blocks double quotes",
        lambda: sanitize_string('test"onclick="alert(1)', "test"),
        SecurityError)

    # ============================================
    # SERVICE NAME SECURITY
    # ============================================
    print("\n--- Service Name Security ---")

    test_security("Service name: sanitizes injection attempt",
        lambda: validate_service_name("my-app; rm -rf"),
        SecurityError)

    test_security("Service name: rejects path traversal",
        lambda: validate_service_name("../etc/app"),
        SecurityError)

    test_security("Service name: handles unicode safely",
        lambda: validate_service_name("myàpp-teśt"))

    # ============================================
    # GENERATED OUTPUT SECURITY
    # ============================================
    print("\n--- Generated Output Security ---")

    def check_no_unescaped_vars():
        """Check generated files don't have unescaped user vars"""
        config = PipelineConfig(
            service_name="test-app",
            platform=Platform.GITHUB_ACTIONS,
            language=Language.NODEJS,
            target=Target.ECS
        )
        files = generate_pipeline(config)

        # Check service name appears safely in all files
        for filename, content in files.items():
            # Ensure no raw shell expansion patterns
            if "${" in content and "{{" not in content:
                # Only check non-workflow files (workflows use GitHub syntax)
                if "workflows" not in filename:
                    raise AssertionError(f"Unsafe variable pattern in {filename}")

    test_security("Generated files have safe variable patterns",
        check_no_unescaped_vars)

    def check_strict_mode_everywhere():
        """Check all bash scripts have strict mode"""
        config = PipelineConfig(
            platform=Platform.CIRCLECI,
            language=Language.GO,
            target=Target.EC2_SSH
        )
        files = generate_pipeline(config)

        for filename, content in files.items():
            if filename.endswith(".sh"):
                if "set -euo pipefail" not in content:
                    raise AssertionError(f"Missing strict mode in {filename}")

    test_security("All bash scripts have strict mode",
        check_strict_mode_everywhere)

    def check_no_shell_expansion_in_heredoc():
        """Check heredocs don't have dangerous shell expansions"""
        config = PipelineConfig(
            platform=Platform.GITHUB_ACTIONS,
            language=Language.NODEJS,
            target=Target.EC2_SSH
        )
        files = generate_pipeline(config)

        dangerous = ["$(rm", "$(cat /etc", "`rm", "`cat /etc"]
        for filename, content in files.items():
            for pattern in dangerous:
                if pattern in content:
                    raise AssertionError(f"Dangerous pattern '{pattern}' in {filename}")

    test_security("No dangerous shell patterns in generated files",
        check_no_shell_expansion_in_heredoc)

    # ============================================
    # DOCKERFILE SECURITY
    # ============================================
    print("\n--- Dockerfile Security ---")

    def check_dockerfile_nonroot():
        """Check Dockerfiles run as non-root"""
        for lang in [Language.NODEJS, Language.PYTHON, Language.GO]:
            config = PipelineConfig(language=lang)
            files = generate_pipeline(config)
            dockerfile = files.get("Dockerfile", "")
            if "USER" not in dockerfile and "nonroot" not in dockerfile:
                raise AssertionError(f"Missing non-root user for {lang.value}")

    test_security("Dockerfiles use non-root user",
        check_dockerfile_nonroot)

    def check_dockerfile_healthcheck():
        """Check Dockerfiles have health checks or document why not"""
        for lang in [Language.NODEJS, Language.PYTHON, Language.GO]:
            config = PipelineConfig(language=lang)
            files = generate_pipeline(config)
            dockerfile = files.get("Dockerfile", "")
            # Distroless images (Go) don't support HEALTHCHECK CMD
            # but should have documentation about orchestration-level health checks
            if "HEALTHCHECK" not in dockerfile and "distroless" not in dockerfile.lower():
                raise AssertionError(f"Missing HEALTHCHECK for {lang.value}")
            if "distroless" in dockerfile.lower() and "health" not in dockerfile.lower():
                raise AssertionError(f"Missing health check documentation for distroless {lang.value}")

    test_security("Dockerfiles have HEALTHCHECK or documentation",
        check_dockerfile_healthcheck)

    # ============================================
    # SUMMARY
    # ============================================
    print("\n" + "="*60)
    print("  Security Test Summary")
    print("="*60)
    print(f"  Passed:  {passed}")
    print(f"  Failed:  {failed}")
    print("="*60)

    if failed == 0:
        print("\n  All security tests passed!")
        return 0
    else:
        print(f"\n  {failed} security test(s) failed!")
        return 1


if __name__ == "__main__":
    sys.exit(run_security_tests())
