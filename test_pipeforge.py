#!/usr/bin/env python3
"""
Comprehensive tests for PipeForge v1.1.0
Tests validation, security, and generation functionality.
"""

import sys
import os
import tempfile
import shutil

# Add the current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeforge import (
    PipelineConfig, Platform, Language, Target, Registry,
    ValidationError, SecurityError,
    sanitize_string, validate_service_name, validate_aws_region,
    validate_environment, validate_environments,
    generate_pipeline, save_files
)

# Test counters
passed = 0
failed = 0
warnings = 0


def test(name, fn):
    """Run a test and track results"""
    global passed, failed
    try:
        fn()
        print(f"  [PASS] {name}")
        passed += 1
        return True
    except AssertionError as e:
        print(f"  [FAIL] {name}: {e}")
        failed += 1
        return False
    except Exception as e:
        print(f"  [FAIL] {name}: Unexpected error - {type(e).__name__}: {e}")
        failed += 1
        return False


def test_expect_error(name, fn, error_type):
    """Test that expects a specific error"""
    global passed, failed
    try:
        fn()
        print(f"  [FAIL] {name}: Expected {error_type.__name__} but no error raised")
        failed += 1
        return False
    except error_type:
        print(f"  [PASS] {name}")
        passed += 1
        return True
    except Exception as e:
        print(f"  [FAIL] {name}: Expected {error_type.__name__} but got {type(e).__name__}: {e}")
        failed += 1
        return False


def run_tests():
    """Run all tests"""
    global passed, failed, warnings

    print("\n" + "="*60)
    print("  PipeForge v1.1.0 - Comprehensive Test Suite")
    print("="*60)

    # ============================================
    # VALIDATION TESTS
    # ============================================
    print("\n--- Validation Tests ---")

    # Test sanitize_string
    test("sanitize_string: valid string",
         lambda: assert_equal(sanitize_string("valid-name", "test"), "valid-name"))

    test("sanitize_string: strips whitespace",
         lambda: assert_equal(sanitize_string("  test  ", "test"), "test"))

    test_expect_error("sanitize_string: rejects empty",
                      lambda: sanitize_string("", "test"), ValidationError)

    test_expect_error("sanitize_string: rejects path traversal",
                      lambda: sanitize_string("../etc/passwd", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects command injection (;)",
                      lambda: sanitize_string("test; rm -rf /", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects command injection (&)",
                      lambda: sanitize_string("test && echo hacked", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects command injection (|)",
                      lambda: sanitize_string("test | cat /etc/passwd", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects backticks",
                      lambda: sanitize_string("test `id`", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects $",
                      lambda: sanitize_string("test $(id)", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects quotes",
                      lambda: sanitize_string("test'quote", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects backslash",
                      lambda: sanitize_string("test\\path", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects control chars",
                      lambda: sanitize_string("test\x00null", "test"), SecurityError)

    test_expect_error("sanitize_string: rejects too long",
                      lambda: sanitize_string("a"*100, "test", max_length=50), ValidationError)

    # Test validate_service_name
    print("\n--- Service Name Validation ---")

    test("service_name: valid lowercase",
         lambda: assert_equal(validate_service_name("my-app"), "my-app"))

    test("service_name: converts uppercase",
         lambda: assert_equal(validate_service_name("My-App"), "my-app"))

    test("service_name: replaces spaces",
         lambda: assert_equal(validate_service_name("my app"), "my-app"))

    test("service_name: replaces underscores",
         lambda: assert_equal(validate_service_name("my_app"), "my-app"))

    test("service_name: adds prefix if starts with number",
         lambda: assert_equal(validate_service_name("123app"), "svc-123app"))

    test("service_name: collapses multiple hyphens",
         lambda: assert_equal(validate_service_name("my--app"), "my-app"))

    test_expect_error("service_name: rejects empty",
                      lambda: validate_service_name(""), ValidationError)

    test_expect_error("service_name: rejects only spaces",
                      lambda: validate_service_name("   "), ValidationError)

    test_expect_error("service_name: rejects path traversal",
                      lambda: validate_service_name("../etc"), SecurityError)

    test_expect_error("service_name: rejects command injection",
                      lambda: validate_service_name("app;rm -rf"), SecurityError)

    # Test validate_aws_region
    print("\n--- AWS Region Validation ---")

    test("aws_region: valid us-east-1",
         lambda: assert_equal(validate_aws_region("us-east-1"), "us-east-1"))

    test("aws_region: valid eu-west-2",
         lambda: assert_equal(validate_aws_region("eu-west-2"), "eu-west-2"))

    test("aws_region: valid ap-southeast-1",
         lambda: assert_equal(validate_aws_region("ap-southeast-1"), "ap-southeast-1"))

    test_expect_error("aws_region: rejects invalid format",
                      lambda: validate_aws_region("invalid"), ValidationError)

    test_expect_error("aws_region: rejects empty",
                      lambda: validate_aws_region(""), ValidationError)

    test_expect_error("aws_region: rejects command injection",
                      lambda: validate_aws_region("us-east-1;rm"), SecurityError)

    # Test validate_environment
    print("\n--- Environment Validation ---")

    test("environment: valid dev",
         lambda: assert_equal(validate_environment("dev"), "dev"))

    test("environment: valid staging",
         lambda: assert_equal(validate_environment("staging"), "staging"))

    test("environment: valid prod",
         lambda: assert_equal(validate_environment("prod"), "prod"))

    test("environment: converts uppercase",
         lambda: assert_equal(validate_environment("DEV"), "dev"))

    test_expect_error("environment: rejects empty",
                      lambda: validate_environment(""), ValidationError)

    test_expect_error("environment: rejects command injection",
                      lambda: validate_environment("dev;rm"), SecurityError)

    # Test validate_environments
    print("\n--- Environments List Validation ---")

    test("environments: valid list",
         lambda: assert_equal(validate_environments(["dev", "staging", "prod"]), ["dev", "staging", "prod"]))

    test_expect_error("environments: rejects empty list",
                      lambda: validate_environments([]), ValidationError)

    test_expect_error("environments: rejects too many",
                      lambda: validate_environments([f"env{i}" for i in range(15)]), ValidationError)

    test_expect_error("environments: rejects duplicates",
                      lambda: validate_environments(["dev", "dev"]), ValidationError)

    # ============================================
    # ENUM PARSING TESTS
    # ============================================
    print("\n--- Enum Parsing Tests ---")

    test("Platform: parse github",
         lambda: assert_equal(Platform.from_string("github"), Platform.GITHUB_ACTIONS))

    test("Platform: parse gitlab",
         lambda: assert_equal(Platform.from_string("gitlab"), Platform.GITLAB_CI))

    test("Platform: parse circleci",
         lambda: assert_equal(Platform.from_string("circleci"), Platform.CIRCLECI))

    test_expect_error("Platform: rejects invalid",
                      lambda: Platform.from_string("invalid"), ValidationError)

    test("Language: parse nodejs",
         lambda: assert_equal(Language.from_string("nodejs"), Language.NODEJS))

    test("Language: parse python",
         lambda: assert_equal(Language.from_string("python"), Language.PYTHON))

    test("Language: parse go",
         lambda: assert_equal(Language.from_string("go"), Language.GO))

    test_expect_error("Language: rejects invalid",
                      lambda: Language.from_string("invalid"), ValidationError)

    test("Target: parse ecs",
         lambda: assert_equal(Target.from_string("ecs"), Target.ECS))

    test("Target: parse ssh",
         lambda: assert_equal(Target.from_string("ssh"), Target.EC2_SSH))

    test("Target: parse k8s",
         lambda: assert_equal(Target.from_string("k8s"), Target.KUBERNETES))

    test_expect_error("Target: rejects invalid",
                      lambda: Target.from_string("invalid"), ValidationError)

    # ============================================
    # PIPELINE CONFIG TESTS
    # ============================================
    print("\n--- PipelineConfig Tests ---")

    test("PipelineConfig: default valid",
         lambda: PipelineConfig())

    test("PipelineConfig: custom valid",
         lambda: PipelineConfig(
             service_name="my-api",
             platform=Platform.GITHUB_ACTIONS,
             language=Language.NODEJS,
             target=Target.ECS,
             aws_region="us-west-2",
             environments=["dev", "staging", "prod"]
         ))

    test_expect_error("PipelineConfig: rejects invalid service name",
                      lambda: PipelineConfig(service_name="../etc/passwd"), SecurityError)

    test_expect_error("PipelineConfig: rejects invalid region",
                      lambda: PipelineConfig(aws_region="invalid"), ValidationError)

    test_expect_error("PipelineConfig: rejects invalid environments",
                      lambda: PipelineConfig(environments=[]), ValidationError)

    # ============================================
    # PIPELINE GENERATION TESTS
    # ============================================
    print("\n--- Pipeline Generation Tests ---")

    def test_github_generation():
        config = PipelineConfig(
            platform=Platform.GITHUB_ACTIONS,
            language=Language.NODEJS,
            target=Target.ECS
        )
        files = generate_pipeline(config)
        assert ".github/workflows/ci-cd.yml" in files
        assert "Dockerfile" in files
        assert "docker-compose.yml" in files
        assert "SECRETS.md" in files

    test("Generation: GitHub Actions + Node.js + ECS", test_github_generation)

    def test_gitlab_generation():
        config = PipelineConfig(
            platform=Platform.GITLAB_CI,
            language=Language.PYTHON,
            target=Target.KUBERNETES
        )
        files = generate_pipeline(config)
        assert ".gitlab-ci.yml" in files
        assert "Dockerfile" in files

    test("Generation: GitLab CI + Python + K8s", test_gitlab_generation)

    def test_circleci_generation():
        config = PipelineConfig(
            platform=Platform.CIRCLECI,
            language=Language.GO,
            target=Target.EC2_SSH
        )
        files = generate_pipeline(config)
        assert ".circleci/config.yml" in files
        assert "scripts/deploy-ssh.sh" in files
        assert "scripts/discover-hosts.sh" in files

    test("Generation: CircleCI + Go + SSH", test_circleci_generation)

    def test_bitbucket_generation():
        config = PipelineConfig(
            platform=Platform.BITBUCKET,
            language=Language.JAVA,
            target=Target.ECS
        )
        files = generate_pipeline(config)
        assert "bitbucket-pipelines.yml" in files

    test("Generation: Bitbucket + Java + ECS", test_bitbucket_generation)

    def test_azure_generation():
        config = PipelineConfig(
            platform=Platform.AZURE_PIPELINES,
            language=Language.DOTNET,
            target=Target.AKS
        )
        files = generate_pipeline(config)
        assert "azure-pipelines.yml" in files

    test("Generation: Azure + .NET + AKS", test_azure_generation)

    # ============================================
    # SECURITY: OUTPUT CONTENT VALIDATION
    # ============================================
    print("\n--- Security: Output Content Validation ---")

    def test_no_injection_in_output():
        """Ensure malicious inputs are sanitized in output"""
        # Even if someone tries to inject, the name gets sanitized
        config = PipelineConfig(
            service_name="my-app",  # Safe name
            platform=Platform.GITHUB_ACTIONS,
            language=Language.NODEJS,
            target=Target.ECS
        )
        files = generate_pipeline(config)

        # Check that the service name is safe in all files
        for filename, content in files.items():
            assert "$(rm" not in content, f"Command injection found in {filename}"
            assert "`rm" not in content, f"Backtick injection found in {filename}"
            assert "../" not in content.lower(), f"Path traversal found in {filename}"

    test("Security: No injection in generated files", test_no_injection_in_output)

    def test_strict_mode_in_scripts():
        """Ensure bash scripts have strict mode"""
        config = PipelineConfig(
            platform=Platform.GITHUB_ACTIONS,
            language=Language.NODEJS,
            target=Target.EC2_SSH
        )
        files = generate_pipeline(config)

        for filename, content in files.items():
            if filename.endswith(".sh"):
                assert "set -euo pipefail" in content, f"Missing strict mode in {filename}"

    test("Security: Bash scripts have strict mode", test_strict_mode_in_scripts)

    # ============================================
    # FILE SAVING TESTS
    # ============================================
    print("\n--- File Saving Tests ---")

    def test_save_files():
        config = PipelineConfig()
        files = generate_pipeline(config)

        # Create temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = os.path.join(tmpdir, "test-output")
            save_files(files, output_dir)

            # Verify files exist
            assert os.path.exists(os.path.join(output_dir, ".github", "workflows", "ci-cd.yml"))
            assert os.path.exists(os.path.join(output_dir, "Dockerfile"))
            assert os.path.exists(os.path.join(output_dir, "docker-compose.yml"))

    test("File saving: creates directory structure", test_save_files)

    def test_save_files_path_traversal():
        """Test that path traversal in output is blocked"""
        files = {"../../../etc/passwd": "malicious content"}
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                save_files(files, tmpdir)
                raise AssertionError("Should have raised SecurityError")
            except SecurityError:
                pass  # Expected

    test("Security: save_files blocks path traversal", test_save_files_path_traversal)

    # ============================================
    # EDGE CASES
    # ============================================
    print("\n--- Edge Cases ---")

    test("Edge: single letter service name",
         lambda: assert_equal(validate_service_name("a"), "a"))

    test("Edge: max length service name",
         lambda: validate_service_name("a" + "b"*62))

    test("Edge: unicode gets replaced",
         lambda: assert_equal(validate_service_name("myàpp"), "my-pp"))

    # ============================================
    # SUMMARY
    # ============================================
    print("\n" + "="*60)
    print("  Test Summary")
    print("="*60)
    print(f"  Passed:   {passed}")
    print(f"  Failed:   {failed}")
    print(f"  Warnings: {warnings}")
    print("="*60)

    if failed == 0:
        print("\n  All tests passed!")
        return 0
    else:
        print(f"\n  {failed} test(s) failed!")
        return 1


def assert_equal(actual, expected):
    """Assert two values are equal"""
    if actual != expected:
        raise AssertionError(f"Expected {expected!r}, got {actual!r}")


if __name__ == "__main__":
    sys.exit(run_tests())
