#!/usr/bin/env python3
"""
PipeForge - Production-Ready CI/CD Pipeline Generator
======================================================

Generate enterprise-grade CI/CD pipelines in seconds.
No AI, no API keys, no external dependencies.

Author: Sheraz Khan (@Sheraz-k)
License: MIT
Repository: https://github.com/Sheraz-k/pipeforge

Security: All user inputs are validated and sanitized.
"""

__version__ = "1.1.0"
__author__ = "Sheraz Khan"

import os
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum


# ============================================
# SECURITY & VALIDATION
# ============================================

class ValidationError(Exception):
    """Raised when input validation fails"""
    pass


class SecurityError(Exception):
    """Raised when security check fails"""
    pass


# Regex patterns for validation
PATTERNS = {
    'service_name': re.compile(r'^[a-z][a-z0-9-]{0,62}[a-z0-9]$|^[a-z]$'),
    'aws_region': re.compile(r'^[a-z]{2}-[a-z]+-\d$'),
    'environment': re.compile(r'^[a-z][a-z0-9-]{0,30}[a-z0-9]$|^[a-z]$'),
    'version': re.compile(r'^\d+(\.\d+)*$'),
}

# Dangerous patterns to reject
DANGEROUS_PATTERNS = [
    r'\.\.',           # Path traversal
    r'[;&|`$]',        # Command injection
    r'[\x00-\x1f]',    # Control characters
    r'[<>"\']',        # HTML/Shell special chars
    r'\\',             # Backslash
]


def sanitize_string(value: str, field_name: str, max_length: int = 63) -> str:
    """
    Sanitize and validate a string input.

    Args:
        value: The input string to sanitize
        field_name: Name of the field (for error messages)
        max_length: Maximum allowed length

    Returns:
        Sanitized string

    Raises:
        ValidationError: If validation fails
        SecurityError: If dangerous patterns detected
    """
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a string, got {type(value).__name__}")

    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value):
            raise SecurityError(f"{field_name} contains potentially dangerous characters")

    # Strip whitespace
    value = value.strip()

    # Check empty
    if not value:
        raise ValidationError(f"{field_name} cannot be empty")

    # Check length
    if len(value) > max_length:
        raise ValidationError(f"{field_name} exceeds maximum length of {max_length} characters")

    return value


def validate_service_name(name: str) -> str:
    """
    Validate and sanitize service name.
    Must be lowercase alphanumeric with hyphens, start with letter.

    Args:
        name: Service name to validate

    Returns:
        Validated service name

    Raises:
        ValidationError: If validation fails
    """
    name = sanitize_string(name, "service_name", max_length=63)

    # Convert to lowercase and replace invalid chars
    name = name.lower()
    name = re.sub(r'[^a-z0-9-]', '-', name)
    name = re.sub(r'-+', '-', name)  # Collapse multiple hyphens
    name = name.strip('-')  # Remove leading/trailing hyphens

    if not name:
        raise ValidationError("service_name results in empty string after sanitization")

    # Ensure starts with letter
    if not name[0].isalpha():
        name = 'svc-' + name

    if not PATTERNS['service_name'].match(name):
        raise ValidationError(
            f"service_name '{name}' is invalid. Must be lowercase alphanumeric with hyphens, "
            "start with a letter, max 63 chars."
        )

    return name


def validate_aws_region(region: str) -> str:
    """
    Validate AWS region format.

    Args:
        region: AWS region string

    Returns:
        Validated region

    Raises:
        ValidationError: If validation fails
    """
    region = sanitize_string(region, "aws_region", max_length=20)
    region = region.lower()

    if not PATTERNS['aws_region'].match(region):
        raise ValidationError(
            f"aws_region '{region}' is invalid. Expected format: us-east-1, eu-west-2, etc."
        )

    return region


def validate_environment(env: str) -> str:
    """
    Validate environment name.

    Args:
        env: Environment name

    Returns:
        Validated environment name

    Raises:
        ValidationError: If validation fails
    """
    env = sanitize_string(env, "environment", max_length=32)
    env = env.lower()
    env = re.sub(r'[^a-z0-9-]', '-', env)
    env = env.strip('-')

    if not env:
        raise ValidationError("environment results in empty string after sanitization")

    if not PATTERNS['environment'].match(env):
        raise ValidationError(f"environment '{env}' is invalid")

    return env


def validate_environments(envs: List[str]) -> List[str]:
    """
    Validate list of environments.

    Args:
        envs: List of environment names

    Returns:
        Validated list of environments

    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(envs, list):
        raise ValidationError("environments must be a list")

    if not envs:
        raise ValidationError("environments cannot be empty")

    if len(envs) > 10:
        raise ValidationError("Maximum 10 environments allowed")

    validated = []
    seen = set()
    for env in envs:
        env = validate_environment(env)
        if env in seen:
            raise ValidationError(f"Duplicate environment: {env}")
        seen.add(env)
        validated.append(env)

    return validated


def escape_yaml_string(value: str) -> str:
    """Escape a string for safe YAML embedding"""
    # If contains special chars, quote it
    if any(c in value for c in ':{}[]&*#?|-<>=!%@`'):
        return f'"{value}"'
    return value


def escape_shell_string(value: str) -> str:
    """Escape a string for safe shell embedding"""
    # Use single quotes and escape any single quotes in the string
    return "'" + value.replace("'", "'\\''") + "'"


# ============================================
# ENUMS & CONFIGURATION
# ============================================

class Platform(Enum):
    """Supported CI/CD platforms"""
    GITHUB_ACTIONS = "github"
    GITLAB_CI = "gitlab"
    CIRCLECI = "circleci"
    BITBUCKET = "bitbucket"
    AZURE_PIPELINES = "azure"

    @classmethod
    def from_string(cls, s: str) -> 'Platform':
        s = sanitize_string(s, "platform", max_length=20).lower()
        mapping = {
            'github': cls.GITHUB_ACTIONS,
            'github-actions': cls.GITHUB_ACTIONS,
            'gitlab': cls.GITLAB_CI,
            'gitlab-ci': cls.GITLAB_CI,
            'circleci': cls.CIRCLECI,
            'circle': cls.CIRCLECI,
            'bitbucket': cls.BITBUCKET,
            'azure': cls.AZURE_PIPELINES,
            'azure-pipelines': cls.AZURE_PIPELINES,
        }
        if s not in mapping:
            valid = ', '.join(sorted(set(mapping.keys())))
            raise ValidationError(f"Unknown platform '{s}'. Valid options: {valid}")
        return mapping[s]


class Language(Enum):
    """Supported programming languages"""
    NODEJS = "nodejs"
    PYTHON = "python"
    GO = "go"
    JAVA = "java"
    DOTNET = "dotnet"
    RUST = "rust"

    @classmethod
    def from_string(cls, s: str) -> 'Language':
        s = sanitize_string(s, "language", max_length=20).lower()
        mapping = {
            'nodejs': cls.NODEJS, 'node': cls.NODEJS, 'javascript': cls.NODEJS, 'js': cls.NODEJS,
            'python': cls.PYTHON, 'py': cls.PYTHON,
            'go': cls.GO, 'golang': cls.GO,
            'java': cls.JAVA, 'kotlin': cls.JAVA,
            'dotnet': cls.DOTNET, 'csharp': cls.DOTNET, '.net': cls.DOTNET, 'c#': cls.DOTNET,
            'rust': cls.RUST, 'rs': cls.RUST,
        }
        if s not in mapping:
            valid = ', '.join(sorted(set(mapping.keys())))
            raise ValidationError(f"Unknown language '{s}'. Valid options: {valid}")
        return mapping[s]


class Target(Enum):
    """Supported deployment targets"""
    ECS = "ecs"
    EKS = "eks"
    APP_RUNNER = "apprunner"
    LAMBDA = "lambda"
    EC2_SSH = "ssh"
    AKS = "aks"
    APP_SERVICE = "appservice"
    CLOUD_RUN = "cloudrun"
    GKE = "gke"
    KUBERNETES = "k8s"

    @classmethod
    def from_string(cls, s: str) -> 'Target':
        s = sanitize_string(s, "target", max_length=20).lower()
        mapping = {
            'ecs': cls.ECS, 'fargate': cls.ECS,
            'eks': cls.EKS,
            'apprunner': cls.APP_RUNNER, 'app-runner': cls.APP_RUNNER,
            'lambda': cls.LAMBDA, 'aws-lambda': cls.LAMBDA,
            'ssh': cls.EC2_SSH, 'ec2': cls.EC2_SSH, 'vm': cls.EC2_SSH,
            'aks': cls.AKS,
            'appservice': cls.APP_SERVICE, 'app-service': cls.APP_SERVICE,
            'cloudrun': cls.CLOUD_RUN, 'cloud-run': cls.CLOUD_RUN,
            'gke': cls.GKE,
            'k8s': cls.KUBERNETES, 'kubernetes': cls.KUBERNETES,
        }
        if s not in mapping:
            valid = ', '.join(sorted(set(mapping.keys())))
            raise ValidationError(f"Unknown target '{s}'. Valid options: {valid}")
        return mapping[s]


class Registry(Enum):
    """Supported container registries"""
    ECR = "ecr"
    DOCKERHUB = "dockerhub"
    GHCR = "ghcr"
    ACR = "acr"
    GAR = "gar"
    GITLAB = "gitlab"

    @classmethod
    def from_string(cls, s: str) -> 'Registry':
        s = sanitize_string(s, "registry", max_length=20).lower()
        mapping = {
            'ecr': cls.ECR, 'aws': cls.ECR,
            'dockerhub': cls.DOCKERHUB, 'docker': cls.DOCKERHUB,
            'ghcr': cls.GHCR, 'github': cls.GHCR,
            'acr': cls.ACR, 'azure': cls.ACR,
            'gar': cls.GAR, 'google': cls.GAR, 'gcr': cls.GAR,
            'gitlab': cls.GITLAB,
        }
        if s not in mapping:
            valid = ', '.join(sorted(set(mapping.keys())))
            raise ValidationError(f"Unknown registry '{s}'. Valid options: {valid}")
        return mapping[s]


# ============================================
# LANGUAGE CONFIGURATIONS
# ============================================

LANG_CONFIG = {
    Language.NODEJS: {
        "display": "Node.js",
        "image": "node:20-alpine",
        "install": "npm ci",
        "build": "npm run build",
        "test": "npm test",
        "lint": "npm run lint",
        "cache_path": "~/.npm",
        "cache_key": "package-lock.json",
        "audit": "npm audit --audit-level=high",
        "port": "3000",
    },
    Language.PYTHON: {
        "display": "Python",
        "image": "python:3.12-slim",
        "install": "pip install -r requirements.txt",
        "build": "python -m build",
        "test": "pytest --cov",
        "lint": "ruff check . && black --check .",
        "cache_path": "~/.cache/pip",
        "cache_key": "requirements.txt",
        "audit": "pip-audit",
        "port": "8000",
    },
    Language.GO: {
        "display": "Go",
        "image": "golang:1.22-alpine",
        "install": "go mod download",
        "build": "CGO_ENABLED=0 go build -o app ./cmd/server",
        "test": "go test -v -race -coverprofile=coverage.out ./...",
        "lint": "golangci-lint run",
        "cache_path": "~/go/pkg/mod",
        "cache_key": "go.sum",
        "audit": "govulncheck ./...",
        "port": "8080",
    },
    Language.JAVA: {
        "display": "Java",
        "image": "eclipse-temurin:21-jdk",
        "install": "./mvnw dependency:resolve",
        "build": "./mvnw package -DskipTests",
        "test": "./mvnw test",
        "lint": "./mvnw checkstyle:check",
        "cache_path": "~/.m2/repository",
        "cache_key": "pom.xml",
        "audit": "./mvnw dependency-check:check",
        "port": "8080",
    },
    Language.DOTNET: {
        "display": ".NET",
        "image": "mcr.microsoft.com/dotnet/sdk:8.0",
        "install": "dotnet restore",
        "build": "dotnet build --configuration Release",
        "test": "dotnet test",
        "lint": "dotnet format --verify-no-changes",
        "cache_path": "~/.nuget/packages",
        "cache_key": "*.csproj",
        "audit": "dotnet list package --vulnerable",
        "port": "5000",
    },
    Language.RUST: {
        "display": "Rust",
        "image": "rust:1.75-slim",
        "install": "cargo fetch",
        "build": "cargo build --release",
        "test": "cargo test",
        "lint": "cargo clippy -- -D warnings",
        "cache_path": "~/.cargo",
        "cache_key": "Cargo.lock",
        "audit": "cargo audit",
        "port": "8080",
    },
}


# ============================================
# PIPELINE CONFIG
# ============================================

@dataclass
class PipelineConfig:
    """
    Configuration for pipeline generation.
    All inputs are validated on initialization.
    """
    service_name: str = "my-app"
    platform: Platform = Platform.GITHUB_ACTIONS
    language: Language = Language.NODEJS
    target: Target = Target.ECS
    registry: Registry = Registry.ECR
    environments: List[str] = field(default_factory=lambda: ["dev", "staging", "prod"])
    aws_region: str = "us-east-1"
    node_version: str = "20"
    python_version: str = "3.12"
    go_version: str = "1.22"
    include_tests: bool = True
    include_security_scan: bool = True

    def __post_init__(self):
        """Validate all inputs after initialization"""
        self.service_name = validate_service_name(self.service_name)
        self.aws_region = validate_aws_region(self.aws_region)
        self.environments = validate_environments(self.environments)

        # Validate version strings
        for attr in ['node_version', 'python_version', 'go_version']:
            val = getattr(self, attr)
            if not re.match(r'^[\d.]+$', val):
                raise ValidationError(f"{attr} must contain only digits and dots")


# ============================================
# GITHUB ACTIONS GENERATOR
# ============================================

def generate_github_actions(config: PipelineConfig) -> Dict[str, str]:
    """Generate GitHub Actions workflow with security best practices"""
    lang = LANG_CONFIG[config.language]
    files = {}

    # Use validated/escaped values
    svc = config.service_name
    region = config.aws_region

    workflow = f'''name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

env:
  SERVICE_NAME: {svc}
  AWS_REGION: {region}

permissions:
  contents: read
  packages: write
  id-token: write
  security-events: write

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
'''

    # Language-specific setup
    if config.language == Language.NODEJS:
        workflow += f'''
      - uses: actions/setup-node@v4
        with:
          node-version: '{config.node_version}'
          cache: 'npm'

      - run: {lang["install"]}
      - run: {lang["lint"]}
'''
    elif config.language == Language.PYTHON:
        workflow += f'''
      - uses: actions/setup-python@v5
        with:
          python-version: '{config.python_version}'
          cache: 'pip'

      - run: pip install ruff black
      - run: {lang["lint"]}
'''
    elif config.language == Language.GO:
        workflow += f'''
      - uses: actions/setup-go@v5
        with:
          go-version: '{config.go_version}'

      - uses: golangci/golangci-lint-action@v4
'''

    # Test job
    if config.include_tests:
        workflow += f'''
  test:
    name: Test
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
'''
        if config.language == Language.NODEJS:
            workflow += f'''
      - uses: actions/setup-node@v4
        with:
          node-version: '{config.node_version}'
          cache: 'npm'

      - run: {lang["install"]}
      - run: {lang["test"]} -- --coverage

      - uses: codecov/codecov-action@v4
        with:
          token: ${{{{ secrets.CODECOV_TOKEN }}}}
        continue-on-error: true
'''
        elif config.language == Language.PYTHON:
            workflow += f'''
      - uses: actions/setup-python@v5
        with:
          python-version: '{config.python_version}'
          cache: 'pip'

      - run: {lang["install"]}
      - run: pip install pytest pytest-cov
      - run: {lang["test"]}
'''
        elif config.language == Language.GO:
            workflow += f'''
      - uses: actions/setup-go@v5
        with:
          go-version: '{config.go_version}'

      - run: {lang["test"]}
'''

    # Security scan
    if config.include_security_scan:
        workflow += '''
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'

      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
        continue-on-error: true
'''

    # Build job
    needs = ["test", "security"] if config.include_tests and config.include_security_scan else ["lint"]
    workflow += f'''
  build:
    name: Build & Push
    runs-on: ubuntu-latest
    needs: [{", ".join(needs)}]
    if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'
    outputs:
      image_tag: ${{{{ github.sha }}}}
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ secrets.AWS_ROLE_ARN }}}}
          aws-region: ${{{{ env.AWS_REGION }}}}

      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ${{{{ steps.login-ecr.outputs.registry }}}}/{svc}:${{{{ github.sha }}}}
            ${{{{ steps.login-ecr.outputs.registry }}}}/{svc}:latest
          cache-from: type=gha
          cache-to: type=gha,mode=max
'''

    # Deploy jobs
    for i, env in enumerate(config.environments):
        prev_job = "build" if i == 0 else f"deploy-{config.environments[i-1]}"
        condition = ""
        if env == "prod":
            condition = "\n    if: github.ref == 'refs/heads/main'"

        workflow += f'''
  deploy-{env}:
    name: Deploy to {env.upper()}
    runs-on: ubuntu-latest
    needs: {prev_job}
    environment: {env}{condition}
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{{{ secrets.AWS_ROLE_ARN_{env.upper()} }}}}
          aws-region: ${{{{ env.AWS_REGION }}}}
'''

        if config.target == Target.ECS:
            workflow += f'''
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2

      - name: Deploy to ECS
        uses: aws-actions/amazon-ecs-deploy-task-definition@v1
        with:
          task-definition: ecs-task-definition-{env}.json
          service: {svc}-{env}
          cluster: {svc}-{env}
          wait-for-service-stability: true
'''
        elif config.target == Target.EKS:
            workflow += f'''
      - name: Update kubeconfig
        run: aws eks update-kubeconfig --name {svc}-{env} --region ${{{{ env.AWS_REGION }}}}

      - name: Deploy to EKS
        run: |
          kubectl set image deployment/{svc} \\
            {svc}=${{{{ needs.build.outputs.image_tag }}}} \\
            -n {svc}-{env}
          kubectl rollout status deployment/{svc} -n {svc}-{env} --timeout=300s
'''
        elif config.target == Target.EC2_SSH:
            workflow += f'''
      - name: Deploy via SSH
        uses: appleboy/ssh-action@v1.0.0
        with:
          host: ${{{{ secrets.SSH_HOSTS_{env.upper()} }}}}
          username: deploy
          key: ${{{{ secrets.SSH_PRIVATE_KEY }}}}
          script: |
            set -euo pipefail
            docker pull ${{{{ secrets.ECR_REGISTRY }}}}/{svc}:${{{{ github.sha }}}}
            docker stop {svc} || true
            docker rm {svc} || true
            docker run -d --name {svc} --restart unless-stopped \\
              -p {lang["port"]}:{lang["port"]} -e NODE_ENV={env} \\
              ${{{{ secrets.ECR_REGISTRY }}}}/{svc}:${{{{ github.sha }}}}
'''

        workflow += f'''
      - name: Health check
        run: |
          sleep 30
          curl -sf --retry 5 --retry-delay 10 ${{{{ secrets.{env.upper()}_URL }}}}/health || exit 1
'''

    files[".github/workflows/ci-cd.yml"] = workflow
    return files


# ============================================
# GITLAB CI GENERATOR
# ============================================

def generate_gitlab_ci(config: PipelineConfig) -> Dict[str, str]:
    """Generate GitLab CI configuration"""
    lang = LANG_CONFIG[config.language]
    files = {}
    svc = config.service_name

    gitlab_ci = f'''# GitLab CI/CD for {svc}
# Generated by PipeForge v{__version__}

stages:
  - lint
  - test
  - security
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  SERVICE_NAME: {svc}

.cache_config: &cache_config
  cache:
    key: $CI_COMMIT_REF_SLUG
    paths:
      - node_modules/
      - .npm/

lint:
  stage: lint
  image: {lang["image"]}
  <<: *cache_config
  script:
    - {lang["install"]}
    - {lang["lint"]}
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_BRANCH == "develop"
'''

    if config.include_tests:
        gitlab_ci += f'''
test:
  stage: test
  image: {lang["image"]}
  <<: *cache_config
  script:
    - {lang["install"]}
    - {lang["test"]}
  coverage: '/Coverage: \\d+\\.\\d+%/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage/cobertura-coverage.xml
    expire_in: 1 week
'''

    if config.include_security_scan:
        gitlab_ci += '''
security:
  stage: security
  image:
    name: aquasec/trivy:latest
    entrypoint: [""]
  script:
    - trivy fs --severity HIGH,CRITICAL --exit-code 0 .
  allow_failure: true
'''

    gitlab_ci += f'''
build:
  stage: build
  image: docker:24-dind
  services:
    - docker:24-dind
  before_script:
    - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -t $CI_REGISTRY_IMAGE:latest .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    - docker push $CI_REGISTRY_IMAGE:latest
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
    - if: $CI_COMMIT_BRANCH == "develop"
'''

    for i, env in enumerate(config.environments):
        when = "on_success" if env == "dev" else "manual"
        gitlab_ci += f'''
deploy_{env}:
  stage: deploy
  image: bitnami/kubectl:latest
  environment:
    name: {env}
    url: https://{svc}.{env}.example.com
  script:
    - kubectl set image deployment/{svc} {svc}=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -n {svc}-{env}
    - kubectl rollout status deployment/{svc} -n {svc}-{env} --timeout=300s
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      when: {when}
'''

    files[".gitlab-ci.yml"] = gitlab_ci
    return files


# ============================================
# CIRCLECI GENERATOR
# ============================================

def generate_circleci(config: PipelineConfig) -> Dict[str, str]:
    """Generate CircleCI configuration"""
    lang = LANG_CONFIG[config.language]
    files = {}
    svc = config.service_name

    circleci = f'''version: 2.1

orbs:
  aws-cli: circleci/aws-cli@4.1
  slack: circleci/slack@4.12

executors:
  default:
    docker:
      - image: cimg/node:20.10
    resource_class: medium

commands:
  install-deps:
    steps:
      - restore_cache:
          keys:
            - deps-v1-{{{{ checksum "{lang["cache_key"]}" }}}}
      - run: {lang["install"]}
      - save_cache:
          key: deps-v1-{{{{ checksum "{lang["cache_key"]}" }}}}
          paths:
            - node_modules

jobs:
  lint:
    executor: default
    steps:
      - checkout
      - install-deps
      - run: {lang["lint"]}
'''

    if config.include_tests:
        circleci += f'''
  test:
    executor: default
    steps:
      - checkout
      - install-deps
      - run: {lang["test"]}
      - store_artifacts:
          path: coverage
'''

    if config.include_security_scan:
        circleci += '''
  security:
    executor: default
    steps:
      - checkout
      - run: |
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          trivy fs --severity HIGH,CRITICAL .
'''

    circleci += f'''
  build-push:
    executor: default
    steps:
      - checkout
      - setup_remote_docker:
          version: default
      - aws-cli/setup
      - run: |
          set -euo pipefail
          aws ecr get-login-password --region {config.aws_region} | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker build -t $ECR_REGISTRY/{svc}:$CIRCLE_SHA1 .
          docker push $ECR_REGISTRY/{svc}:$CIRCLE_SHA1
'''

    for env in config.environments:
        if config.target == Target.EC2_SSH:
            circleci += f'''
  deploy-{env}:
    executor: default
    steps:
      - add_ssh_keys:
          fingerprints:
            - "$SSH_KEY_FINGERPRINT"
      - run: |
          set -euo pipefail
          IFS=',' read -ra HOSTS <<< "$SSH_HOSTS_{env.upper()}"
          for HOST in "${{HOSTS[@]}}"; do
            ssh -o StrictHostKeyChecking=no deploy@"$HOST" << 'EOF'
              set -euo pipefail
              docker pull $ECR_REGISTRY/{svc}:$CIRCLE_SHA1
              docker stop {svc} || true && docker rm {svc} || true
              docker run -d --name {svc} --restart unless-stopped -p {lang["port"]}:{lang["port"]} $ECR_REGISTRY/{svc}:$CIRCLE_SHA1
EOF
          done
'''
        else:
            circleci += f'''
  deploy-{env}:
    executor: default
    steps:
      - aws-cli/setup
      - run: |
          set -euo pipefail
          aws ecs update-service --cluster {svc}-{env} --service {svc} --force-new-deployment
          aws ecs wait services-stable --cluster {svc}-{env} --services {svc}
'''

    # Workflows
    circleci += '''
workflows:
  build-test-deploy:
    jobs:
      - lint
'''
    if config.include_tests:
        circleci += '''      - test:
          requires: [lint]
'''
    if config.include_security_scan:
        circleci += '''      - security:
          requires: [lint]
'''

    deps = ["test"] if config.include_tests else ["lint"]
    if config.include_security_scan:
        deps.append("security")

    circleci += f'''      - build-push:
          requires: [{", ".join(deps)}]
          filters:
            branches:
              only: [main, develop]
'''

    for i, env in enumerate(config.environments):
        prev = "build-push" if i == 0 else f"deploy-{config.environments[i-1]}"
        if env == "prod":
            circleci += f'''      - hold-prod:
          type: approval
          requires: [{prev}]
      - deploy-prod:
          requires: [hold-prod]
          context: [aws-prod]
'''
        else:
            circleci += f'''      - deploy-{env}:
          requires: [{prev}]
          context: [aws-{env}]
'''

    files[".circleci/config.yml"] = circleci
    return files


# ============================================
# BITBUCKET PIPELINES GENERATOR
# ============================================

def generate_bitbucket(config: PipelineConfig) -> Dict[str, str]:
    """Generate Bitbucket Pipelines configuration"""
    lang = LANG_CONFIG[config.language]
    files = {}
    svc = config.service_name

    if config.target == Target.EC2_SSH:
        deploy_cmd = f'''            - pipe: atlassian/ssh-run:0.8.1
              variables:
                SSH_USER: 'deploy'
                SERVER: '$SSH_HOSTS'
                COMMAND: |
                  set -euo pipefail
                  docker pull $DOCKER_IMAGE
                  docker stop {svc} || true
                  docker rm {svc} || true
                  docker run -d --name {svc} --restart unless-stopped -p {lang["port"]}:{lang["port"]} $DOCKER_IMAGE'''
    else:
        deploy_cmd = f'''            - pipe: atlassian/aws-ecs-deploy:1.9.0
              variables:
                AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
                AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
                AWS_DEFAULT_REGION: '{config.aws_region}'
                CLUSTER_NAME: '{svc}-$ENVIRONMENT'
                SERVICE_NAME: '{svc}'
                TASK_DEFINITION: 'task-def.json' '''

    bitbucket = f'''# Bitbucket Pipelines for {svc}
# Generated by PipeForge v{__version__}

image: {lang["image"]}

definitions:
  steps:
    - step: &lint
        name: Lint
        script:
          - {lang["install"]}
          - {lang["lint"]}

    - step: &test
        name: Test
        script:
          - {lang["install"]}
          - {lang["test"]}

    - step: &build
        name: Build & Push
        services:
          - docker
        script:
          - pipe: atlassian/aws-ecr-push-image:2.4.0
            variables:
              AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
              AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
              AWS_DEFAULT_REGION: '{config.aws_region}'
              IMAGE_NAME: {svc}
              TAGS: '$BITBUCKET_COMMIT latest'

pipelines:
  default:
    - step: *lint
    - step: *test

  branches:
    develop:
      - step: *lint
      - step: *test
      - step: *build
      - step:
          name: Deploy to Dev
          deployment: dev
          script:
            - export ENVIRONMENT=dev
            - export DOCKER_IMAGE="$ECR_REGISTRY/{svc}:$BITBUCKET_COMMIT"
{deploy_cmd}

    main:
      - step: *lint
      - step: *test
      - step: *build
      - step:
          name: Deploy to Staging
          deployment: staging
          script:
            - export ENVIRONMENT=staging
            - export DOCKER_IMAGE="$ECR_REGISTRY/{svc}:$BITBUCKET_COMMIT"
{deploy_cmd}
      - step:
          name: Deploy to Prod
          deployment: production
          trigger: manual
          script:
            - export ENVIRONMENT=prod
            - export DOCKER_IMAGE="$ECR_REGISTRY/{svc}:$BITBUCKET_COMMIT"
{deploy_cmd}
'''

    files["bitbucket-pipelines.yml"] = bitbucket
    return files


# ============================================
# AZURE PIPELINES GENERATOR
# ============================================

def generate_azure_pipelines(config: PipelineConfig) -> Dict[str, str]:
    """Generate Azure Pipelines configuration"""
    lang = LANG_CONFIG[config.language]
    files = {}
    svc = config.service_name

    if config.target == Target.AKS:
        deploy_task = f'''                - task: Kubernetes@1
                  inputs:
                    connectionType: 'Azure Resource Manager'
                    azureSubscriptionEndpoint: '$(AZURE_SUBSCRIPTION)'
                    kubernetesCluster: '{svc}-$(ENV)'
                    command: 'set'
                    arguments: 'image deployment/{svc} {svc}=$(containerRegistry)/{svc}:$(Build.BuildId)' '''
    elif config.target == Target.EC2_SSH:
        deploy_task = f'''                - task: SSH@0
                  inputs:
                    sshEndpoint: 'ssh-$(ENV)'
                    commands: |
                      set -euo pipefail
                      docker pull $(containerRegistry)/{svc}:$(Build.BuildId)
                      docker stop {svc} || true && docker rm {svc} || true
                      docker run -d --name {svc} -p {lang["port"]}:{lang["port"]} $(containerRegistry)/{svc}:$(Build.BuildId)'''
    else:
        deploy_task = '''                - script: echo "Configure deployment"'''

    azure = f'''# Azure Pipelines for {svc}
# Generated by PipeForge v{__version__}

trigger:
  branches:
    include: [main, develop]

variables:
  - name: containerRegistry
    value: '$(ACR_NAME).azurecr.io'

stages:
  - stage: Build
    jobs:
      - job: BuildTest
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '20.x'
          - script: {lang["install"]}
          - script: {lang["lint"]}
          - script: {lang["test"]}

      - job: BuildImage
        dependsOn: BuildTest
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - task: Docker@2
            inputs:
              command: buildAndPush
              repository: {svc}
              containerRegistry: $(dockerConnection)
              tags: $(Build.BuildId)
'''

    for env in config.environments:
        azure += f'''
  - stage: Deploy{env.title()}
    variables:
      - name: ENV
        value: '{env}'
    jobs:
      - deployment: Deploy
        environment: '{svc}-{env}'
        pool:
          vmImage: 'ubuntu-latest'
        strategy:
          runOnce:
            deploy:
              steps:
{deploy_task}
'''

    files["azure-pipelines.yml"] = azure
    return files


# ============================================
# DOCKERFILE GENERATOR
# ============================================

def generate_dockerfile(config: PipelineConfig) -> str:
    """Generate optimized Dockerfile with security best practices"""
    lang = LANG_CONFIG[config.language]
    svc = config.service_name

    if config.language == Language.NODEJS:
        return f'''# Dockerfile for {svc}
# Generated by PipeForge v{__version__}
# Security: Multi-stage build, non-root user, health check

# Build stage
FROM node:{config.node_version}-alpine AS builder
WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy source and build
COPY . .
RUN npm run build

# Production stage
FROM node:{config.node_version}-alpine AS production
WORKDIR /app

# Security: Create non-root user
RUN addgroup -g 1001 -S appgroup && \\
    adduser -S appuser -u 1001 -G appgroup

# Copy only necessary files
COPY --from=builder --chown=appuser:appgroup /app/dist ./dist
COPY --from=builder --chown=appuser:appgroup /app/node_modules ./node_modules
COPY --from=builder --chown=appuser:appgroup /app/package*.json ./

# Security: Run as non-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:{lang["port"]}/health || exit 1

EXPOSE {lang["port"]}
CMD ["node", "dist/index.js"]
'''

    elif config.language == Language.PYTHON:
        return f'''# Dockerfile for {svc}
# Generated by PipeForge v{__version__}
# Security: Multi-stage build, non-root user, health check

# Build stage
FROM python:{config.python_version}-slim AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential && \\
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:{config.python_version}-slim AS production
WORKDIR /app

# Security: Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH

COPY --chown=appuser:appuser . .

# Security: Run as non-root
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:{lang["port"]}/health')" || exit 1

EXPOSE {lang["port"]}
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{lang["port"]}"]
'''

    elif config.language == Language.GO:
        return f'''# Dockerfile for {svc}
# Generated by PipeForge v{__version__}
# Security: Multi-stage build, distroless image, non-root user

# Build stage
FROM golang:{config.go_version}-alpine AS builder
WORKDIR /app

RUN apk --no-cache add ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \\
    -ldflags='-w -s -extldflags "-static"' \\
    -o /app/server ./cmd/server

# Production stage - distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12 AS production

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/server /server

# Security: Run as non-root
USER nonroot:nonroot

EXPOSE {lang["port"]}
ENTRYPOINT ["/server"]
'''

    return f'''# Dockerfile for {svc}
# Generated by PipeForge v{__version__}

FROM {lang["image"]}
WORKDIR /app
COPY . .
RUN {lang["install"]}
EXPOSE {lang["port"]}
CMD ["./app"]
'''


# ============================================
# DOCKER COMPOSE GENERATOR
# ============================================

def generate_docker_compose(config: PipelineConfig) -> str:
    """Generate docker-compose.yml for local development"""
    lang = LANG_CONFIG[config.language]
    svc = config.service_name

    return f'''# Docker Compose for {svc}
# Generated by PipeForge v{__version__}

version: '3.8'

services:
  {svc}:
    build:
      context: .
      target: production
    ports:
      - "{lang["port"]}:{lang["port"]}"
    environment:
      - NODE_ENV=development
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:{lang["port"]}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    restart: unless-stopped
'''


# ============================================
# SSH SCRIPTS GENERATOR
# ============================================

def generate_ssh_scripts(config: PipelineConfig) -> Dict[str, str]:
    """Generate SSH deployment scripts with security best practices"""
    lang = LANG_CONFIG[config.language]
    files = {}
    svc = config.service_name

    files["scripts/deploy-ssh.sh"] = f'''#!/bin/bash
# SSH Deployment Script for {svc}
# Generated by PipeForge v{__version__}
# Security: Strict mode, input validation, error handling

set -euo pipefail
IFS=$'\\n\\t'

# Configuration
readonly SERVICE_NAME="{svc}"
readonly DOCKER_IMAGE="${{DOCKER_IMAGE:-${{1:-}}}}"
readonly ENVIRONMENT="${{ENVIRONMENT:-${{2:-}}}}"
readonly HOSTS="${{HOSTS:-${{3:-}}}}"
readonly MAX_FAILURE_PERCENT=30
readonly DEPLOY_DELAY=10
readonly HEALTH_CHECK_RETRIES=30
readonly HEALTH_CHECK_DELAY=2

# Logging
log() {{ echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }}
error() {{ echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2; }}

# Validation
validate_inputs() {{
    if [[ -z "$DOCKER_IMAGE" ]]; then
        error "DOCKER_IMAGE is required"
        exit 1
    fi
    if [[ -z "$ENVIRONMENT" ]]; then
        error "ENVIRONMENT is required"
        exit 1
    fi
    if [[ -z "$HOSTS" ]]; then
        error "HOSTS is required"
        exit 1
    fi
    # Validate environment name
    if ! [[ "$ENVIRONMENT" =~ ^[a-z][a-z0-9-]{{0,30}}$ ]]; then
        error "Invalid ENVIRONMENT format"
        exit 1
    fi
}}

# Main deployment
main() {{
    validate_inputs

    IFS=',' read -ra HOST_ARRAY <<< "$HOSTS"
    local TOTAL=${{#HOST_ARRAY[@]}}
    local FAILED=0
    local SUCCESSFUL=0

    log "Deploying $SERVICE_NAME to $TOTAL servers"
    log "Image: $DOCKER_IMAGE"
    log "Environment: $ENVIRONMENT"

    for i in "${{!HOST_ARRAY[@]}}"; do
        local HOST="${{HOST_ARRAY[$i]}}"

        # Validate host format (basic IP/hostname check)
        if ! [[ "$HOST" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            error "Invalid host format: $HOST"
            ((FAILED++))
            continue
        fi

        log "[$((i+1))/$TOTAL] Deploying to $HOST..."

        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 -o BatchMode=yes deploy@"$HOST" << ENDSSH
            set -euo pipefail

            echo "Pulling image..."
            docker pull "$DOCKER_IMAGE"

            echo "Stopping old container..."
            docker stop "$SERVICE_NAME" 2>/dev/null || true
            docker rm "$SERVICE_NAME" 2>/dev/null || true

            echo "Starting new container..."
            docker run -d \\
                --name "$SERVICE_NAME" \\
                --restart unless-stopped \\
                -p {lang["port"]}:{lang["port"]} \\
                -e NODE_ENV="$ENVIRONMENT" \\
                --health-cmd="curl -f http://localhost:{lang["port"]}/health || exit 1" \\
                --health-interval=30s \\
                --health-timeout=10s \\
                --health-retries=3 \\
                "$DOCKER_IMAGE"

            echo "Waiting for health check..."
            for attempt in $(seq 1 $HEALTH_CHECK_RETRIES); do
                if docker inspect --format='{{{{.State.Health.Status}}}}' "$SERVICE_NAME" 2>/dev/null | grep -q healthy; then
                    echo "Container is healthy"
                    exit 0
                fi
                sleep $HEALTH_CHECK_DELAY
            done

            echo "Health check failed"
            docker logs "$SERVICE_NAME" --tail 50
            exit 1
ENDSSH
        then
            log "SUCCESS: $HOST"
            ((SUCCESSFUL++))
        else
            error "FAILED: $HOST"
            ((FAILED++))

            # Check failure threshold
            if (( FAILED * 100 / TOTAL > MAX_FAILURE_PERCENT )); then
                error "Failure threshold exceeded ($FAILED/$TOTAL). Stopping deployment."
                exit 1
            fi
        fi

        # Delay between deployments (rolling)
        if [[ $i -lt $((TOTAL-1)) ]]; then
            log "Waiting ${{DEPLOY_DELAY}}s before next deployment..."
            sleep $DEPLOY_DELAY
        fi
    done

    # Summary
    log "========================================"
    log "Deployment Summary"
    log "========================================"
    log "Total: $TOTAL | Successful: $SUCCESSFUL | Failed: $FAILED"

    if [[ $FAILED -gt 0 ]]; then
        error "Deployment completed with failures"
        exit 1
    fi

    log "All deployments successful!"
}}

main "$@"
'''

    files["scripts/discover-hosts.sh"] = f'''#!/bin/bash
# Discover EC2 hosts by tags
# Generated by PipeForge v{__version__}

set -euo pipefail

readonly SERVICE="{svc}"
readonly ENV="${{1:-dev}}"
readonly REGION="${{AWS_REGION:-{config.aws_region}}}"

# Validate environment
if ! [[ "$ENV" =~ ^[a-z][a-z0-9-]{{0,30}}$ ]]; then
    echo "Invalid environment format" >&2
    exit 1
fi

HOSTS=$(aws ec2 describe-instances \\
    --region "$REGION" \\
    --filters \\
        "Name=tag:Service,Values=$SERVICE" \\
        "Name=tag:Environment,Values=$ENV" \\
        "Name=instance-state-name,Values=running" \\
    --query 'Reservations[].Instances[].PrivateIpAddress' \\
    --output text | tr '\\n' ',' | sed 's/,$//')

if [[ -z "$HOSTS" ]]; then
    echo "No hosts found" >&2
    exit 1
fi

echo "$HOSTS"
'''

    files["scripts/setup-server.sh"] = f'''#!/bin/bash
# Setup server for {svc}
# Generated by PipeForge v{__version__}

set -euo pipefail

echo "Setting up server for {svc}..."

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Create deploy user if not exists
if ! id "deploy" &>/dev/null; then
    echo "Creating deploy user..."
    useradd -m -s /bin/bash deploy
    usermod -aG docker deploy
fi

# Setup directories
mkdir -p /opt/{svc}
mkdir -p /var/log/{svc}
chown -R deploy:deploy /opt/{svc}
chown -R deploy:deploy /var/log/{svc}

# Setup SSH directory
mkdir -p /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Add CI/CD SSH public key to /home/deploy/.ssh/authorized_keys"
echo "2. Tag this instance with Service={svc} and Environment=<env>"
'''

    return files


# ============================================
# SECRETS DOCUMENTATION GENERATOR
# ============================================

def generate_secrets_doc(config: PipelineConfig) -> str:
    """Generate secrets documentation"""
    svc = config.service_name
    secrets = []

    if config.registry == Registry.ECR:
        secrets.append(("AWS_ROLE_ARN", "IAM role ARN for OIDC authentication", "Required"))
        for env in config.environments:
            secrets.append((f"AWS_ROLE_ARN_{env.upper()}", f"IAM role for {env} deployments", "Required"))

    if config.target == Target.EC2_SSH:
        secrets.append(("SSH_PRIVATE_KEY", "SSH private key for deployment", "Required"))
        for env in config.environments:
            secrets.append((f"SSH_HOSTS_{env.upper()}", f"Comma-separated {env} server IPs", "Required"))

    for env in config.environments:
        secrets.append((f"{env.upper()}_URL", f"Base URL for {env} health checks", "Required"))

    secrets.append(("CODECOV_TOKEN", "Codecov token for coverage reports", "Optional"))
    secrets.append(("SLACK_WEBHOOK_URL", "Slack webhook for notifications", "Optional"))

    doc = f'''# Required Secrets for {svc}

Generated by PipeForge v{__version__}

## Configuration

Configure these secrets in your CI/CD platform settings.

| Secret | Description | Status |
|--------|-------------|--------|
'''
    for name, desc, status in secrets:
        doc += f"| `{name}` | {desc} | {status} |\n"

    doc += '''
## Security Best Practices

1. **Never commit secrets** to version control
2. **Use OIDC** instead of long-lived credentials where possible
3. **Rotate secrets** regularly
4. **Limit scope** - use least privilege principle
5. **Audit access** - monitor secret usage

## Platform-Specific Setup

### GitHub Actions
- Go to Settings > Secrets and variables > Actions
- Add each secret as a Repository secret
- For environments, create Environments and add environment-specific secrets

### GitLab CI
- Go to Settings > CI/CD > Variables
- Add variables with appropriate scope (project/group)
- Mark sensitive values as "Masked"

### CircleCI
- Go to Project Settings > Environment Variables
- Create contexts for environment-specific secrets
'''

    return doc


# ============================================
# MAIN GENERATOR
# ============================================

def generate_pipeline(config: PipelineConfig) -> Dict[str, str]:
    """
    Generate all pipeline files.

    Args:
        config: Validated PipelineConfig instance

    Returns:
        Dictionary of filename -> content
    """
    files = {}

    # CI/CD config based on platform
    generators = {
        Platform.GITHUB_ACTIONS: generate_github_actions,
        Platform.GITLAB_CI: generate_gitlab_ci,
        Platform.CIRCLECI: generate_circleci,
        Platform.BITBUCKET: generate_bitbucket,
        Platform.AZURE_PIPELINES: generate_azure_pipelines,
    }

    generator = generators.get(config.platform)
    if generator:
        files.update(generator(config))

    # Common files
    files["Dockerfile"] = generate_dockerfile(config)
    files["docker-compose.yml"] = generate_docker_compose(config)
    files[".dockerignore"] = '''# Generated by PipeForge
node_modules/
__pycache__/
*.pyc
.git/
.github/
.gitlab-ci.yml
.circleci/
*.md
.env*
coverage/
.pytest_cache/
*.log
.DS_Store
Thumbs.db
'''

    # SSH scripts if needed
    if config.target == Target.EC2_SSH:
        files.update(generate_ssh_scripts(config))

    # Documentation
    files["SECRETS.md"] = generate_secrets_doc(config)

    return files


def validate_output_path(path_str: str) -> Path:
    """
    Validate output directory path.
    Allows backslashes for Windows paths but blocks dangerous patterns.

    Args:
        path_str: Path string to validate

    Returns:
        Resolved Path object

    Raises:
        ValidationError: If validation fails
        SecurityError: If dangerous patterns detected
    """
    if not isinstance(path_str, str):
        raise ValidationError("output_dir must be a string")

    path_str = path_str.strip()
    if not path_str:
        raise ValidationError("output_dir cannot be empty")

    if len(path_str) > 500:
        raise ValidationError("output_dir exceeds maximum length")

    # Check for specific dangerous patterns (but allow backslashes for Windows)
    dangerous = [
        r'[;&|`$]',        # Command injection chars
        r'[\x00-\x1f]',    # Control characters
    ]
    for pattern in dangerous:
        if re.search(pattern, path_str):
            raise SecurityError("output_dir contains potentially dangerous characters")

    return Path(path_str).resolve()


def save_files(files: Dict[str, str], output_dir: str) -> None:
    """
    Save generated files to disk.

    Args:
        files: Dictionary of filename -> content
        output_dir: Output directory path
    """
    # Validate output directory (Windows-compatible)
    output_path = validate_output_path(output_dir)

    # Security: Ensure output is not in system directories
    dangerous_paths = ['/etc', '/usr', '/bin', '/sbin', '/var', '/root', 'C:\\Windows', 'C:\\Program Files']
    for dp in dangerous_paths:
        if str(output_path).startswith(dp):
            raise SecurityError(f"Cannot write to system directory: {output_path}")

    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print("  PipeForge - Generated Files")
    print('='*60)

    for filepath, content in files.items():
        full_path = output_path / filepath

        # Security: Validate path doesn't escape output directory
        try:
            full_path.resolve().relative_to(output_path.resolve())
        except ValueError:
            raise SecurityError(f"Path traversal detected: {filepath}")

        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        print(f"  [+] {filepath}")

        # Make scripts executable
        if filepath.endswith(".sh"):
            full_path.chmod(0o755)

    print(f"\n{'='*60}")
    print(f"  Output: {output_path}")
    print('='*60 + "\n")


# ============================================
# CLI
# ============================================

def prompt_choice(question: str, options: list, default: int = 0) -> int:
    """Prompt for choice with validation"""
    print(f"\n{question}")
    for i, opt in enumerate(options):
        marker = " *" if i == default else ""
        print(f"  {i + 1}. {opt}{marker}")

    while True:
        try:
            choice = input(f"  Select [1-{len(options)}] (default: {default + 1}): ").strip()
            if not choice:
                return default
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
            print("  Invalid choice. Please try again.")
        except ValueError:
            print("  Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n  Cancelled.")
            sys.exit(0)


def prompt_text(question: str, default: str) -> str:
    """Prompt for text with validation"""
    try:
        value = input(f"\n{question} [{default}]: ").strip()
        return value if value else default
    except KeyboardInterrupt:
        print("\n  Cancelled.")
        sys.exit(0)


def interactive_mode() -> PipelineConfig:
    """Interactive configuration with validation"""
    platforms = list(Platform)
    platform = platforms[prompt_choice("CI/CD Platform:", [p.value for p in platforms])]

    languages = list(Language)
    language = languages[prompt_choice("Language:", [LANG_CONFIG[l]["display"] for l in languages])]

    targets = list(Target)
    target = targets[prompt_choice("Deployment Target:", [t.value for t in targets])]

    registries = list(Registry)
    registry = registries[prompt_choice("Container Registry:", [r.value for r in registries])]

    env_opts = ["dev only", "dev + staging", "dev + staging + prod"]
    env_choice = prompt_choice("Environments:", env_opts, 2)
    environments = ["dev"] if env_choice == 0 else ["dev", "staging"] if env_choice == 1 else ["dev", "staging", "prod"]

    # Get and validate service name
    while True:
        service_name = prompt_text("Service name", "my-app")
        try:
            service_name = validate_service_name(service_name)
            break
        except (ValidationError, SecurityError) as e:
            print(f"  Error: {e}. Please try again.")

    # Get and validate AWS region
    while True:
        aws_region = prompt_text("AWS Region", "us-east-1")
        try:
            aws_region = validate_aws_region(aws_region)
            break
        except (ValidationError, SecurityError) as e:
            print(f"  Error: {e}. Please try again.")

    include_tests = input("\nInclude tests? [Y/n]: ").strip().lower() != 'n'
    include_security_scan = input("Include security scan? [Y/n]: ").strip().lower() != 'n'

    return PipelineConfig(
        service_name=service_name,
        platform=platform,
        language=language,
        target=target,
        registry=registry,
        environments=environments,
        aws_region=aws_region,
        include_tests=include_tests,
        include_security_scan=include_security_scan,
    )


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PipeForge - Production-Ready CI/CD Pipeline Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s                                    # Interactive mode
  %(prog)s -p github -l nodejs -t ecs -n api  # Command line mode
  %(prog)s --platform gitlab --language python --target ssh --name backend

Version: {__version__}
Author: {__author__}
Repository: https://github.com/Sheraz-k/pipeforge
"""
    )
    parser.add_argument("--platform", "-p", help="CI/CD platform")
    parser.add_argument("--language", "-l", help="Programming language")
    parser.add_argument("--target", "-t", help="Deployment target")
    parser.add_argument("--registry", "-r", help="Container registry")
    parser.add_argument("--name", "-n", help="Service name")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--version", "-v", action="version", version=f"PipeForge {__version__}")

    args = parser.parse_args()

    print("\n" + "="*60)
    print("  PipeForge - CI/CD Pipeline Generator")
    print(f"  Version {__version__} | No AI | No API | Secure")
    print("="*60)

    try:
        # Non-interactive mode if all required args provided
        if args.platform and args.language and args.target:
            config = PipelineConfig(
                platform=Platform.from_string(args.platform),
                language=Language.from_string(args.language),
                target=Target.from_string(args.target),
                registry=Registry.from_string(args.registry) if args.registry else Registry.ECR,
                service_name=args.name or "my-app",
                aws_region=args.region,
            )
        else:
            config = interactive_mode()

        # Summary
        print(f"\n{'-'*60}")
        print("  Configuration")
        print(f"{'-'*60}")
        print(f"  Platform:    {config.platform.value}")
        print(f"  Language:    {LANG_CONFIG[config.language]['display']}")
        print(f"  Target:      {config.target.value}")
        print(f"  Service:     {config.service_name}")
        print(f"  Region:      {config.aws_region}")
        print(f"  Environments: {', '.join(config.environments)}")
        print(f"{'-'*60}")

        if input("\nGenerate pipeline? [Y/n]: ").strip().lower() == 'n':
            print("Cancelled.")
            return

        # Generate
        files = generate_pipeline(config)

        # Save
        output_dir = args.output or prompt_text("Output directory", "./generated-pipeline")
        save_files(files, output_dir)

    except (ValidationError, SecurityError) as e:
        print(f"\nError: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)


if __name__ == "__main__":
    main()
