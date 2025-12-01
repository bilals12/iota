# Docker Registry Configuration

iota uses **Docker Hub exclusively** for container image distribution.

The CI/CD workflows use Turo's open-source Docker actions (`open-turo/actions-docker`) for consistent, production-ready builds with native multi-architecture support.

## Quick Start

### Docker Hub Setup

**1. Set GitHub Secrets:**
- Go to your repository → Settings → Secrets and variables → Actions
- Add `DOCKERHUB_USERNAME` (your Docker Hub username)
- Add `DOCKERHUB_PASSWORD` (your Docker Hub password or Personal Access Token)

**Detailed setup instructions:** See `docs/DOCKERHUB_SETUP.md`

**2. Automatic Push on Release:**
When you create a version tag (e.g., `v1.0.0`), the `release.yml` workflow will automatically:
- Build AMD64 and ARM64 images separately on native runners
- Create a multi-arch manifest combining both platforms
- Push to Docker Hub

**3. Manual Push:**
```bash
# Build locally
make docker-build

# Push to Docker Hub
make docker-push-dockerhub DOCKERHUB_USERNAME=yourusername IMAGE_TAG=v1.0.0
```

## Workflows

### `release.yml` (Automatic)
- **Triggers**: Version tags (`v*.*.*`)
- **Uses**: Turo's `open-turo/actions-docker/build` and `open-turo/actions-docker/manifest` actions
- **Process**:
  1. Builds AMD64 and ARM64 images separately (parallel jobs)
  2. Creates multi-arch manifest from digests
  3. Pushes to Docker Hub
- **Requires**: `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` secrets
- **Tags**: `v1.0.0`, `1.0`, `1`, `latest`
- **Security**: Optional Trivy vulnerability scanning (free, open-source)

### `dockerhub.yml` (Docker Hub Only)
- **Triggers**: Version tags or manual `workflow_dispatch`
- **Uses**: Turo's `open-turo/actions-docker/build` and `open-turo/actions-docker/manifest` actions
- **Registry**: Docker Hub only
- **Requires**: `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` secrets
- **Use case**: Separate workflow for Docker Hub if you want more control

## Required Secrets

### Docker Hub

To push to Docker Hub, set these GitHub secrets:
- `DOCKERHUB_USERNAME` - Your Docker Hub username
- `DOCKERHUB_PASSWORD` - Your Docker Hub password or Personal Access Token (recommended)

**Setup Instructions:**
See `docs/DOCKERHUB_SETUP.md` for detailed step-by-step instructions.

**Manual push to Docker Hub:**
```bash
# Login to Docker Hub
docker login

# Build and push
make docker-build
make docker-push-dockerhub DOCKERHUB_USERNAME=yourusername IMAGE_TAG=v1.0.0
```

## Makefile Targets

| Target | Description | Example |
|--------|-------------|---------|
| `docker-build` | Build Docker image locally | `make docker-build` |
| `docker-push-dockerhub` | Push to Docker Hub | `make docker-push-dockerhub DOCKERHUB_USERNAME=user` |
| `docker-push-ecr` | Push to ECR | `make docker-push-ecr IMAGE_REPO=...` |
| `docker-push` | Generic push (requires IMAGE_REPO) | `make docker-push IMAGE_REPO=registry/image` |

## Image Names

- **Docker Hub**: `username/iota:tag` (e.g., `bilals12/iota:v1.0.0`)

## Using Images in Kubernetes

Update your Kubernetes deployment to use the image:

```yaml
spec:
  template:
    spec:
      containers:
        - name: iota
          image: yourusername/iota:v1.0.0
```

## Troubleshooting

### Docker Hub Push Fails

1. **Check secrets are set**: Repository → Settings → Secrets
2. **Verify credentials**: Test login manually with `docker login`
3. **Check rate limits**: Docker Hub has rate limits for free accounts
4. **Use access token**: Consider using a Docker Hub Personal Access Token instead of password

## About Trivy

Trivy is a **free, open-source** vulnerability scanner. The workflow includes an optional Trivy scan step that:
- Scans your Docker image for vulnerabilities
- Reports CRITICAL and HIGH severity issues
- Won't fail the workflow if there are issues (uses `continue-on-error: true`)

You don't need to install or configure anything - the GitHub Action handles it automatically.
