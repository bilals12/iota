# Kubernetes manifests

Canonical Kustomize **base** and cluster overlays live in the **[iota-deployments](https://github.com/iota-corp/iota-deployments)** repository:

- **`base/`** — Deployment, Service, ServiceAccount, PVC, Namespace
- **`clusters/<environment>/`** — production GitOps overlays
- **`examples/`** — starter overlays (e.g. ECR + IRSA, EKS lab sample)

Do **not** add workload YAML in this directory; change **`iota-deployments`** and commit there.

See **`docs/manifest-migration-checklist.md`** for the consolidation rationale.
