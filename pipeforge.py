#!/usr/bin/env python3
"""
PipeForge - Production-Ready CI/CD Pipeline Generator
======================================================

Generate enterprise-grade CI/CD pipelines in seconds.
No AI, no API keys, no external dependencies.

Author: Sheraz Khan (@Sheraz-k)
License: MIT
Repository: https://github.com/Sheraz-k/pipeforge
"""

__version__ = "1.0.0"
__author__ = "Sheraz Khan"

import os
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


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
        mapping = {
            'github': cls.GITHUB_ACTIONS,
            'gitlab': cls.GITLAB_CI,
            'circleci': cls.CIRCLECI,
            'bitbucket': cls.BITBUCKET,
            'azure': cls.AZURE_PIPELINES,
        }
        return mapping.get(s.lower(), cls.GITHUB_ACTIONS)


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
        mapping = {
            'nodejs': cls.NODEJS, 'node': cls.NODEJS, 'javascript': cls.NODEJS,
            'python': cls.PYTHON, 'py': cls.PYTHON,
            'go': cls.GO, 'golang': cls.GO,
            'java': cls.JAVA,
            'dotnet': cls.DOTNET, 'csharp': cls.DOTNET, '.net': cls.DOTNET,
            'rust': cls.RUST,
        }
        return mapping.get(s.lower(), cls.NODEJS)


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
        mapping = {
            'ecs': cls.ECS,
            'eks': cls.EKS,
            'apprunner': cls.APP_RUNNER, 'app-runner': cls.APP_RUNNER,
            'lambda': cls.LAMBDA,
            'ssh': cls.EC2_SSH, 'ec2': cls.EC2_SSH, 'vm': cls.EC2_SSH,
            'aks': cls.AKS,
            'appservice': cls.APP_SERVICE, 'app-service': cls.APP_SERVICE,
            'cloudrun': cls.CLOUD_RUN, 'cloud-run': cls.CLOUD_RUN,
            'gke': cls.GKE,
            'k8s': cls.KUBERNETES, 'kubernetes': cls.KUBERNETES,
        }
        return mapping.get(s.lower(), cls.ECS)


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
        mapping = {
            'ecr': cls.ECR,
            'dockerhub': cls.DOCKERHUB, 'docker': cls.DOCKERHUB,
            'ghcr': cls.GHCR, 'github': cls.GHCR,
            'acr': cls.ACR, 'azure': cls.ACR,
            'gar': cls.GAR, 'google': cls.GAR,
            'gitlab': cls.GITLAB,
        }
        return mapping.get(s.lower(), cls.ECR)


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
    """Configuration for pipeline generation"""
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


# ============================================
# GITHUB ACTIONS GENERATOR
# ============================================

def generate_github_actions(config: PipelineConfig) -> Dict[str, str]:
    """Generate GitHub Actions workflow"""
    lang = LANG_CONFIG[config.language]
    files = {}

    workflow = f'''name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
  workflow_dispatch:

env:
  SERVICE_NAME: {config.service_name}
  AWS_REGION: {config.aws_region}

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
            ${{{{ steps.login-ecr.outputs.registry }}}}/{config.service_name}:${{{{ github.sha }}}}
            ${{{{ steps.login-ecr.outputs.registry }}}}/{config.service_name}:latest
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
          service: {config.service_name}-{env}
          cluster: {config.service_name}-{env}
          wait-for-service-stability: true
'''
        elif config.target == Target.EKS:
            workflow += f'''
      - name: Update kubeconfig
        run: aws eks update-kubeconfig --name {config.service_name}-{env} --region ${{{{ env.AWS_REGION }}}}

      - name: Deploy to EKS
        run: |
          kubectl set image deployment/{config.service_name} \\
            {config.service_name}=${{{{ needs.build.outputs.image_tag }}}} \\
            -n {config.service_name}-{env}
          kubectl rollout status deployment/{config.service_name} -n {config.service_name}-{env} --timeout=300s
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
            docker pull ${{{{ secrets.ECR_REGISTRY }}}}/{config.service_name}:${{{{ github.sha }}}}
            docker stop {config.service_name} || true
            docker rm {config.service_name} || true
            docker run -d --name {config.service_name} --restart unless-stopped \\
              -p {lang["port"]}:{lang["port"]} -e NODE_ENV={env} \\
              ${{{{ secrets.ECR_REGISTRY }}}}/{config.service_name}:${{{{ github.sha }}}}
'''

        workflow += f'''
      - name: Health check
        run: |
          sleep 30
          curl -sf ${{{{ secrets.{env.upper()}_URL }}}}/health || exit 1
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

    gitlab_ci = f'''# GitLab CI/CD for {config.service_name}
# Generated by PipeForge

stages:
  - lint
  - test
  - security
  - build
  - deploy

variables:
  DOCKER_DRIVER: overlay2
  SERVICE_NAME: {config.service_name}

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
    url: https://{config.service_name}.{env}.example.com
  script:
    - kubectl set image deployment/{config.service_name} {config.service_name}=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -n {config.service_name}-{env}
    - kubectl rollout status deployment/{config.service_name} -n {config.service_name}-{env} --timeout=300s
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
          aws ecr get-login-password --region {config.aws_region} | docker login --username AWS --password-stdin $ECR_REGISTRY
          docker build -t $ECR_REGISTRY/{config.service_name}:$CIRCLE_SHA1 .
          docker push $ECR_REGISTRY/{config.service_name}:$CIRCLE_SHA1
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
          IFS=',' read -ra HOSTS <<< "$SSH_HOSTS_{env.upper()}"
          for HOST in "${{HOSTS[@]}}"; do
            ssh -o StrictHostKeyChecking=no deploy@$HOST << 'EOF'
              docker pull $ECR_REGISTRY/{config.service_name}:$CIRCLE_SHA1
              docker stop {config.service_name} || true && docker rm {config.service_name} || true
              docker run -d --name {config.service_name} --restart unless-stopped -p {lang["port"]}:{lang["port"]} $ECR_REGISTRY/{config.service_name}:$CIRCLE_SHA1
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
          aws ecs update-service --cluster {config.service_name}-{env} --service {config.service_name} --force-new-deployment
          aws ecs wait services-stable --cluster {config.service_name}-{env} --services {config.service_name}
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

    if config.target == Target.EC2_SSH:
        deploy_cmd = f'''            - pipe: atlassian/ssh-run:0.8.1
              variables:
                SSH_USER: 'deploy'
                SERVER: '$SSH_HOSTS'
                COMMAND: |
                  docker pull $DOCKER_IMAGE
                  docker stop {config.service_name} || true
                  docker rm {config.service_name} || true
                  docker run -d --name {config.service_name} --restart unless-stopped -p {lang["port"]}:{lang["port"]} $DOCKER_IMAGE'''
    else:
        deploy_cmd = f'''            - pipe: atlassian/aws-ecs-deploy:1.9.0
              variables:
                AWS_ACCESS_KEY_ID: $AWS_ACCESS_KEY_ID
                AWS_SECRET_ACCESS_KEY: $AWS_SECRET_ACCESS_KEY
                AWS_DEFAULT_REGION: '{config.aws_region}'
                CLUSTER_NAME: '{config.service_name}-$ENVIRONMENT'
                SERVICE_NAME: '{config.service_name}'
                TASK_DEFINITION: 'task-def.json' '''

    bitbucket = f'''# Bitbucket Pipelines for {config.service_name}
# Generated by PipeForge

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
              IMAGE_NAME: {config.service_name}
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
            - export DOCKER_IMAGE="$ECR_REGISTRY/{config.service_name}:$BITBUCKET_COMMIT"
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
            - export DOCKER_IMAGE="$ECR_REGISTRY/{config.service_name}:$BITBUCKET_COMMIT"
{deploy_cmd}
      - step:
          name: Deploy to Prod
          deployment: production
          trigger: manual
          script:
            - export ENVIRONMENT=prod
            - export DOCKER_IMAGE="$ECR_REGISTRY/{config.service_name}:$BITBUCKET_COMMIT"
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

    if config.target == Target.AKS:
        deploy_task = f'''                - task: Kubernetes@1
                  inputs:
                    connectionType: 'Azure Resource Manager'
                    azureSubscriptionEndpoint: '$(AZURE_SUBSCRIPTION)'
                    kubernetesCluster: '{config.service_name}-$(ENV)'
                    command: 'set'
                    arguments: 'image deployment/{config.service_name} {config.service_name}=$(containerRegistry)/{config.service_name}:$(Build.BuildId)' '''
    elif config.target == Target.EC2_SSH:
        deploy_task = f'''                - task: SSH@0
                  inputs:
                    sshEndpoint: 'ssh-$(ENV)'
                    commands: |
                      docker pull $(containerRegistry)/{config.service_name}:$(Build.BuildId)
                      docker stop {config.service_name} || true && docker rm {config.service_name} || true
                      docker run -d --name {config.service_name} -p {lang["port"]}:{lang["port"]} $(containerRegistry)/{config.service_name}:$(Build.BuildId)'''
    else:
        deploy_task = '''                - script: echo "Configure deployment"'''

    azure = f'''# Azure Pipelines for {config.service_name}
# Generated by PipeForge

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
              repository: {config.service_name}
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
        environment: '{config.service_name}-{env}'
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
    """Generate optimized Dockerfile"""
    lang = LANG_CONFIG[config.language]

    if config.language == Language.NODEJS:
        return f'''# Build stage
FROM node:{config.node_version}-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force
COPY . .
RUN npm run build

# Production stage
FROM node:{config.node_version}-alpine AS production
WORKDIR /app
RUN addgroup -g 1001 -S app && adduser -S app -u 1001 -G app
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --from=builder --chown=app:app /app/package*.json ./
USER app
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\
  CMD wget --spider http://localhost:{lang["port"]}/health || exit 1
EXPOSE {lang["port"]}
CMD ["node", "dist/index.js"]
'''

    elif config.language == Language.PYTHON:
        return f'''# Build stage
FROM python:{config.python_version}-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:{config.python_version}-slim AS production
WORKDIR /app
RUN useradd --create-home app
COPY --from=builder /root/.local /home/app/.local
ENV PATH=/home/app/.local/bin:$PATH
COPY --chown=app:app . .
USER app
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \\
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:{lang["port"]}/health')"
EXPOSE {lang["port"]}
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "{lang["port"]}"]
'''

    elif config.language == Language.GO:
        return f'''# Build stage
FROM golang:{config.go_version}-alpine AS builder
WORKDIR /app
RUN apk --no-cache add ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o /app/server ./cmd/server

# Production stage
FROM gcr.io/distroless/static-debian12 AS production
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/server /server
USER nonroot:nonroot
EXPOSE {lang["port"]}
ENTRYPOINT ["/server"]
'''

    return f'''FROM {lang["image"]}
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
    """Generate docker-compose.yml"""
    lang = LANG_CONFIG[config.language]

    return f'''version: '3.8'

services:
  {config.service_name}:
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
    """Generate SSH deployment scripts"""
    lang = LANG_CONFIG[config.language]
    files = {}

    files["scripts/deploy-ssh.sh"] = f'''#!/bin/bash
# SSH Deployment Script for {config.service_name}
# Generated by PipeForge
set -euo pipefail

SERVICE_NAME="{config.service_name}"
DOCKER_IMAGE="${{DOCKER_IMAGE:-$1}}"
ENVIRONMENT="${{ENVIRONMENT:-$2}}"
HOSTS="${{HOSTS:-$3}}"

log() {{ echo "[$(date +'%H:%M:%S')] $1"; }}

IFS=',' read -ra HOST_ARRAY <<< "$HOSTS"
TOTAL=${{#HOST_ARRAY[@]}}
FAILED=0

log "Deploying $SERVICE_NAME to $TOTAL servers"

for i in "${{!HOST_ARRAY[@]}}"; do
    HOST="${{HOST_ARRAY[$i]}}"
    log "[$((i+1))/$TOTAL] Deploying to $HOST..."

    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=30 deploy@"$HOST" << ENDSSH
        set -e
        docker pull $DOCKER_IMAGE
        docker stop $SERVICE_NAME 2>/dev/null || true
        docker rm $SERVICE_NAME 2>/dev/null || true
        docker run -d --name $SERVICE_NAME --restart unless-stopped \\
            -p {lang["port"]}:{lang["port"]} -e NODE_ENV=$ENVIRONMENT \\
            --health-cmd="curl -f http://localhost:{lang["port"]}/health || exit 1" \\
            --health-interval=30s --health-timeout=10s --health-retries=3 \\
            $DOCKER_IMAGE
        for attempt in {{1..30}}; do
            if docker inspect --format='{{{{.State.Health.Status}}}}' $SERVICE_NAME | grep -q healthy; then exit 0; fi
            sleep 2
        done
        exit 1
ENDSSH
    then
        log "SUCCESS: $HOST"
    else
        log "FAILED: $HOST"
        ((FAILED++))
        if (( FAILED * 100 / TOTAL > 30 )); then
            log "Too many failures. Stopping."
            exit 1
        fi
    fi
    [ $i -lt $((TOTAL-1)) ] && sleep 10
done

[ $FAILED -eq 0 ] && log "All deployments successful!" || exit 1
'''

    files["scripts/discover-hosts.sh"] = f'''#!/bin/bash
# Discover EC2 hosts by tags
set -euo pipefail

SERVICE="{config.service_name}"
ENV="${{1:-dev}}"
REGION="${{AWS_REGION:-{config.aws_region}}}"

HOSTS=$(aws ec2 describe-instances \\
    --region "$REGION" \\
    --filters "Name=tag:Service,Values=$SERVICE" "Name=tag:Environment,Values=$ENV" "Name=instance-state-name,Values=running" \\
    --query 'Reservations[].Instances[].PrivateIpAddress' \\
    --output text | tr '\\n' ',' | sed 's/,$//')

echo "$HOSTS"
'''

    files["scripts/setup-server.sh"] = f'''#!/bin/bash
# Setup server for {config.service_name}
set -euo pipefail

echo "Setting up server..."

if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker && systemctl start docker
fi

if ! id "deploy" &>/dev/null; then
    useradd -m -s /bin/bash deploy
    usermod -aG docker deploy
fi

mkdir -p /opt/{config.service_name}
chown -R deploy:deploy /opt/{config.service_name}

echo "Setup complete! Add SSH key to /home/deploy/.ssh/authorized_keys"
'''

    return files


# ============================================
# SECRETS DOCUMENTATION GENERATOR
# ============================================

def generate_secrets_doc(config: PipelineConfig) -> str:
    """Generate secrets documentation"""
    secrets = []

    if config.registry == Registry.ECR:
        secrets.append(("AWS_ROLE_ARN", "IAM role ARN for OIDC authentication"))
        for env in config.environments:
            secrets.append((f"AWS_ROLE_ARN_{env.upper()}", f"IAM role for {env} deployments"))

    if config.target == Target.EC2_SSH:
        secrets.append(("SSH_PRIVATE_KEY", "SSH private key for deployment"))
        for env in config.environments:
            secrets.append((f"SSH_HOSTS_{env.upper()}", f"Comma-separated {env} server IPs"))

    for env in config.environments:
        secrets.append((f"{env.upper()}_URL", f"Base URL for {env} health checks"))

    secrets.append(("CODECOV_TOKEN", "Codecov token (optional)"))
    secrets.append(("SLACK_WEBHOOK_URL", "Slack webhook (optional)"))

    doc = "# Required Secrets\n\nConfigure these in your CI/CD platform:\n\n"
    doc += "| Secret | Description |\n|--------|-------------|\n"
    for name, desc in secrets:
        doc += f"| `{name}` | {desc} |\n"

    return doc


# ============================================
# MAIN GENERATOR
# ============================================

def generate_pipeline(config: PipelineConfig) -> Dict[str, str]:
    """Generate all pipeline files"""
    files = {}

    # CI/CD config
    if config.platform == Platform.GITHUB_ACTIONS:
        files.update(generate_github_actions(config))
    elif config.platform == Platform.GITLAB_CI:
        files.update(generate_gitlab_ci(config))
    elif config.platform == Platform.CIRCLECI:
        files.update(generate_circleci(config))
    elif config.platform == Platform.BITBUCKET:
        files.update(generate_bitbucket(config))
    elif config.platform == Platform.AZURE_PIPELINES:
        files.update(generate_azure_pipelines(config))

    # Common files
    files["Dockerfile"] = generate_dockerfile(config)
    files["docker-compose.yml"] = generate_docker_compose(config)
    files[".dockerignore"] = '''node_modules/
__pycache__/
*.pyc
.git/
.github/
*.md
.env*
coverage/
'''

    # SSH scripts
    if config.target == Target.EC2_SSH:
        files.update(generate_ssh_scripts(config))

    # Documentation
    files["SECRETS.md"] = generate_secrets_doc(config)

    return files


def save_files(files: Dict[str, str], output_dir: str):
    """Save generated files to disk"""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print("  PipeForge - Generated Files")
    print('='*60)

    for filepath, content in files.items():
        full_path = output_path / filepath
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")
        print(f"  [+] {filepath}")

        if filepath.endswith(".sh"):
            full_path.chmod(0o755)

    print(f"\n{'='*60}")
    print(f"  Output: {output_path.absolute()}")
    print('='*60 + "\n")


# ============================================
# CLI
# ============================================

def prompt_choice(question: str, options: list, default: int = 0) -> int:
    """Prompt for choice"""
    print(f"\n{question}")
    for i, opt in enumerate(options):
        marker = " *" if i == default else ""
        print(f"  {i + 1}. {opt}{marker}")

    while True:
        choice = input(f"  Select [1-{len(options)}] (default: {default + 1}): ").strip()
        if not choice:
            return default
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return idx
        except ValueError:
            pass
        print("  Invalid choice.")


def prompt_text(question: str, default: str) -> str:
    """Prompt for text"""
    value = input(f"\n{question} [{default}]: ").strip()
    return value if value else default


def interactive_mode() -> PipelineConfig:
    """Interactive configuration"""
    config = PipelineConfig()

    platforms = list(Platform)
    config.platform = platforms[prompt_choice("CI/CD Platform:", [p.value for p in platforms])]

    languages = list(Language)
    config.language = languages[prompt_choice("Language:", [LANG_CONFIG[l]["display"] for l in languages])]

    targets = list(Target)
    config.target = targets[prompt_choice("Deployment Target:", [t.value for t in targets])]

    registries = list(Registry)
    config.registry = registries[prompt_choice("Container Registry:", [r.value for r in registries])]

    env_opts = ["dev only", "dev + staging", "dev + staging + prod"]
    env_choice = prompt_choice("Environments:", env_opts, 2)
    config.environments = ["dev"] if env_choice == 0 else ["dev", "staging"] if env_choice == 1 else ["dev", "staging", "prod"]

    config.service_name = prompt_text("Service name:", "my-app")
    config.aws_region = prompt_text("AWS Region:", "us-east-1")
    config.include_tests = input("\nInclude tests? [Y/n]: ").strip().lower() != 'n'
    config.include_security_scan = input("Include security scan? [Y/n]: ").strip().lower() != 'n'

    return config


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="PipeForge - Production-Ready CI/CD Pipeline Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--platform", "-p", help="CI/CD platform (github/gitlab/circleci/bitbucket/azure)")
    parser.add_argument("--language", "-l", help="Language (nodejs/python/go/java/dotnet/rust)")
    parser.add_argument("--target", "-t", help="Deploy target (ecs/eks/ssh/aks/cloudrun/k8s)")
    parser.add_argument("--registry", "-r", help="Container registry (ecr/dockerhub/ghcr/acr)")
    parser.add_argument("--name", "-n", help="Service name")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--version", "-v", action="version", version=f"PipeForge {__version__}")

    args = parser.parse_args()

    print("\n" + "="*60)
    print("  PipeForge - CI/CD Pipeline Generator")
    print("  No AI | No API | No Dependencies")
    print("="*60)

    # Non-interactive mode
    if args.platform and args.language and args.target:
        config = PipelineConfig(
            platform=Platform.from_string(args.platform),
            language=Language.from_string(args.language),
            target=Target.from_string(args.target),
            registry=Registry.from_string(args.registry) if args.registry else Registry.ECR,
            service_name=args.name or "my-app",
            aws_region=args.region
        )
    else:
        config = interactive_mode()

    # Summary
    print(f"\n{'-'*60}")
    print("  Configuration")
    print(f"{'-'*60}")
    print(f"  Platform: {config.platform.value}")
    print(f"  Language: {LANG_CONFIG[config.language]['display']}")
    print(f"  Target:   {config.target.value}")
    print(f"  Service:  {config.service_name}")
    print(f"{'-'*60}")

    if input("\nGenerate? [Y/n]: ").strip().lower() == 'n':
        print("Cancelled.")
        return

    # Generate
    files = generate_pipeline(config)

    # Save
    output_dir = args.output or prompt_text("Output directory:", "./generated-pipeline")
    save_files(files, output_dir)


if __name__ == "__main__":
    main()
