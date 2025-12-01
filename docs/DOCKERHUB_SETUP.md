# Docker Hub Setup Guide

This guide explains how to configure GitHub Actions to build and push Docker images to Docker Hub.

## Required GitHub Secrets

You need to add two secrets to your GitHub repository:

1. **`DOCKERHUB_USERNAME`** - Your Docker Hub username
2. **`DOCKERHUB_PASSWORD`** - Your Docker Hub password or Personal Access Token (PAT)

### Step-by-Step Setup

#### 1. Create a Docker Hub Personal Access Token (Recommended)

Using a Personal Access Token is more secure than using your password:

1. Log in to [Docker Hub](https://hub.docker.com/)
2. Go to **Account Settings** → **Security**
3. Click **New Access Token**
4. Give it a name (e.g., `GitHubActionsToken`)
5. Set permissions to **Read & Write**
6. Click **Generate**
7. **Copy the token immediately** - you won't be able to see it again!

#### 2. Add Secrets to GitHub Repository

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Create two secrets:

   **Secret 1:**
   - Name: `DOCKERHUB_USERNAME`
   - Value: Your Docker Hub username (e.g., `bilals12`)

   **Secret 2:**
   - Name: `DOCKERHUB_PASSWORD`
   - Value: Your Docker Hub password OR the Personal Access Token you created

#### 3. Verify Setup

Once the secrets are added, your workflows will automatically:
- Build AMD64 and ARM64 images when you create a version tag (e.g., `v1.0.0`)
- Create a multi-arch manifest
- Push to Docker Hub

### Testing

To test the setup:

```bash
# Create a test tag
git tag v0.1.0-test
git push origin v0.1.0-test

# Check GitHub Actions tab to see the workflow run
# Check Docker Hub to verify the image was pushed
```

### Image Location

Your images will be available at:
- `docker.io/<DOCKERHUB_USERNAME>/iota:latest`
- `docker.io/<DOCKERHUB_USERNAME>/iota:v1.0.0`
- etc.

### Troubleshooting

**Workflow fails with authentication error:**
- Verify `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` secrets are set correctly
- Ensure the token has Read & Write permissions
- Check that your Docker Hub account is active

**Image not appearing on Docker Hub:**
- Check the GitHub Actions logs for errors
- Verify the image name in `.docker-config.json` matches your Docker Hub username
- Ensure you have permission to push to the repository

## About Trivy

Trivy is a **free, open-source** vulnerability scanner. The workflow includes an optional Trivy scan step that:
- Scans your Docker image for vulnerabilities
- Reports CRITICAL and HIGH severity issues
- Won't fail the workflow if there are issues (uses `continue-on-error: true`)

You don't need to install or configure anything - the GitHub Action handles it automatically.
