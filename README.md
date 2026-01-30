# PipeForge

<div align="center">

![PipeForge Logo](https://img.shields.io/badge/PipeForge-CI%2FCD%20Generator-blue?style=for-the-badge&logo=github-actions)

**Production-Ready CI/CD Pipeline Generator**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![No Dependencies](https://img.shields.io/badge/dependencies-zero-green.svg)](#)
[![Offline Ready](https://img.shields.io/badge/works-offline-brightgreen.svg)](#)

*Generate enterprise-grade CI/CD pipelines in seconds. No AI, no API keys, no external dependencies.*

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Documentation](#documentation) • [Contributing](#contributing)

</div>

---

## Why PipeForge?

Setting up CI/CD pipelines is repetitive and error-prone. PipeForge generates **production-ready, best-practice pipelines** instantly:

- **Zero Configuration** - Answer a few questions, get a complete pipeline
- **Zero Dependencies** - Pure Python 3.8+, works offline
- **Zero Cost** - No AI APIs, no subscriptions, completely free
- **Enterprise Ready** - Security scanning, multi-environment, rollback strategies

## Features

### Supported CI/CD Platforms

| Platform | Config File | Status |
|----------|-------------|--------|
| GitHub Actions | `.github/workflows/ci-cd.yml` | ✅ Full Support |
| GitLab CI | `.gitlab-ci.yml` | ✅ Full Support |
| CircleCI | `.circleci/config.yml` | ✅ Full Support |
| Bitbucket Pipelines | `bitbucket-pipelines.yml` | ✅ Full Support |
| Azure Pipelines | `azure-pipelines.yml` | ✅ Full Support |

### Supported Deployment Targets

| Target | Type | Multi-Region |
|--------|------|--------------|
| Amazon ECS | Container Orchestration | ✅ |
| Amazon EKS | Kubernetes | ✅ |
| AWS App Runner | Serverless Containers | ✅ |
| AWS Lambda | Serverless Functions | ✅ |
| EC2/VM (SSH) | Direct Deployment | ✅ |
| Azure AKS | Kubernetes | ✅ |
| Azure App Service | PaaS | ✅ |
| Google Cloud Run | Serverless Containers | ✅ |
| Google GKE | Kubernetes | ✅ |
| Kubernetes | Self-Managed | ✅ |

### Supported Languages

| Language | Package Managers | Versions |
|----------|-----------------|----------|
| Node.js | npm, yarn, pnpm | 18, 20, 22 |
| Python | pip, poetry, pipenv | 3.10, 3.11, 3.12 |
| Go | go modules | 1.21, 1.22 |
| Java | Maven, Gradle | 17, 21 |
| .NET | NuGet | 6.0, 8.0 |
| Rust | Cargo | stable |

### Built-in Best Practices

```
┌─────────────────────────────────────────────────────────────┐
│                    Every Pipeline Includes                   │
├─────────────────────────────────────────────────────────────┤
│  ✓ Dependency Caching        ✓ Security Scanning (Trivy)    │
│  ✓ Test Coverage Reports     ✓ Container Image Scanning     │
│  ✓ Multi-stage Dockerfiles   ✓ Non-root Containers          │
│  ✓ Health Checks             ✓ Automatic Rollback            │
│  ✓ Environment Promotion     ✓ Manual Prod Approval          │
│  ✓ Slack/Teams Notifications ✓ Secrets Management            │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Option 1: Clone Repository (Recommended)

```bash
git clone https://github.com/Sheraz-k/pipeforge.git
cd pipeforge
```

### Option 2: Download Single File

```bash
curl -O https://raw.githubusercontent.com/Sheraz-k/pipeforge/main/pipeforge.py
```

### Option 3: pip install (Coming Soon)

```bash
pip install pipeforge
```

## Quick Start

### Interactive Mode

```bash
python pipeforge.py
```

You'll be prompted to select:
1. CI/CD Platform
2. Programming Language
3. Deployment Target
4. Container Registry
5. Environments (dev/staging/prod)
6. Service Name

### Non-Interactive Mode

```bash
python pipeforge.py \
  --platform github \
  --language nodejs \
  --target ecs \
  --registry ecr \
  --name my-service \
  --output ./my-pipeline
```

### Programmatic Usage

```python
from pipeforge import PipeForge, Platform, Language, Target

# Create configuration
forge = PipeForge(
    service_name="payment-api",
    platform=Platform.GITHUB_ACTIONS,
    language=Language.NODEJS,
    target=Target.ECS,
    environments=["dev", "staging", "prod"]
)

# Generate and save
forge.generate("./output")
```

## Generated Output

```
my-pipeline/
├── .github/
│   └── workflows/
│       └── ci-cd.yml          # Complete CI/CD pipeline
├── Dockerfile                  # Multi-stage, optimized
├── docker-compose.yml          # Local development
├── .dockerignore               # Build optimization
├── scripts/
│   ├── deploy-ssh.sh          # Rolling SSH deployment
│   ├── discover-hosts.sh      # EC2 auto-discovery
│   └── setup-server.sh        # Server preparation
└── SECRETS.md                  # Required secrets documentation
```

## Pipeline Architecture

```
                           ┌─────────────────────┐
                           │    Pull Request     │
                           └──────────┬──────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
        ┌──────────┐           ┌──────────┐           ┌──────────┐
        │   Lint   │           │   Test   │           │ Security │
        └──────────┘           └──────────┘           │   Scan   │
              │                       │               └──────────┘
              └───────────────────────┼───────────────────────┘
                                      │
                           ┌──────────▼──────────┐
                           │   Build & Push      │
                           │   Container Image   │
                           └──────────┬──────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
  ┌───────────┐               ┌─────────────┐               ┌─────────────┐
  │    DEV    │──────────────▶│   STAGING   │──────────────▶│    PROD     │
  │  (auto)   │               │   (auto)    │               │  (manual)   │
  └───────────┘               └─────────────┘               └─────────────┘
```

## SSH Multi-Server Deployment

For EC2/VM deployments, PipeForge generates intelligent deployment scripts:

```bash
# Rolling deployment to multiple servers
./scripts/deploy-ssh.sh <image> <env> <host1,host2,host3>

# Features:
# - Rolling deployment (one server at a time)
# - Health checks before proceeding
# - Automatic rollback on >30% failure
# - 10-second delay between servers
```

### Dynamic Host Discovery

```bash
# Auto-discover EC2 instances by tags
./scripts/discover-hosts.sh prod

# Output: 10.0.1.10,10.0.1.11,10.0.1.12
```

Tag your EC2 instances with:
- `Service: your-service-name`
- `Environment: dev|staging|prod`

## Configuration Reference

### PipelineConfig Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `service_name` | str | "my-app" | Name of your service |
| `ci_platform` | CIPlatform | GITHUB_ACTIONS | CI/CD platform |
| `language` | Language | NODEJS | Programming language |
| `deploy_target` | DeployTarget | ECS | Deployment target |
| `container_registry` | ContainerRegistry | ECR | Container registry |
| `environments` | List[str] | ["dev", "staging", "prod"] | Deployment environments |
| `aws_region` | str | "us-east-1" | AWS region |
| `include_tests` | bool | True | Include test stage |
| `include_security_scan` | bool | True | Include security scanning |

### Environment Variables

Generated pipelines use these secrets (configure in your CI/CD platform):

| Secret | Description | Required For |
|--------|-------------|--------------|
| `AWS_ROLE_ARN` | IAM role for OIDC auth | AWS deployments |
| `SSH_PRIVATE_KEY` | SSH key for deployments | EC2/VM deployments |
| `SSH_HOSTS_*` | Comma-separated server IPs | EC2/VM deployments |
| `CODECOV_TOKEN` | Coverage reporting | All |
| `SLACK_WEBHOOK_URL` | Notifications | Optional |

## Examples

### Node.js + GitHub Actions + ECS

```python
from pipeforge import PipeForge, Platform, Language, Target

PipeForge(
    service_name="user-api",
    platform=Platform.GITHUB_ACTIONS,
    language=Language.NODEJS,
    target=Target.ECS
).generate("./user-api-pipeline")
```

### Python + GitLab + Kubernetes

```python
PipeForge(
    service_name="ml-service",
    platform=Platform.GITLAB_CI,
    language=Language.PYTHON,
    target=Target.KUBERNETES
).generate("./ml-pipeline")
```

### Go + CircleCI + SSH Deployment

```python
PipeForge(
    service_name="backend",
    platform=Platform.CIRCLECI,
    language=Language.GO,
    target=Target.EC2_SSH
).generate("./backend-pipeline")
```

## Dockerfile Features

Generated Dockerfiles include:

- **Multi-stage builds** - Smaller final images
- **Non-root user** - Security best practice
- **Health checks** - Container orchestration ready
- **Layer caching** - Faster builds
- **Security hardening** - Minimal attack surface

Example for Node.js:

```dockerfile
# Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build

# Production stage
FROM node:20-alpine AS production
RUN addgroup -g 1001 -S app && adduser -S app -u 1001
WORKDIR /app
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
USER app
HEALTHCHECK --interval=30s CMD wget --spider http://localhost:3000/health
EXPOSE 3000
CMD ["node", "dist/index.js"]
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
git clone https://github.com/Sheraz-k/pipeforge.git
cd pipeforge
python -m pytest tests/
```

### Adding a New Platform

1. Create generator function in `pipeforge.py`
2. Add to `CIPlatform` enum
3. Update `generate_pipeline()` function
4. Add tests
5. Update README

## Roadmap

- [ ] Jenkins pipeline support
- [ ] AWS CodePipeline support
- [ ] Tekton pipelines
- [ ] ArgoCD GitOps workflows
- [ ] Helm chart generation
- [ ] Terraform infrastructure
- [ ] pip installable package
- [ ] Web UI

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Sheraz Khan** - [@Sheraz-k](https://github.com/Sheraz-k)

---

<div align="center">

**If PipeForge saves you time, please give it a ⭐**

[Report Bug](https://github.com/Sheraz-k/pipeforge/issues) • [Request Feature](https://github.com/Sheraz-k/pipeforge/issues)

</div>
