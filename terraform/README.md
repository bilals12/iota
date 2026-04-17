# Terraform modules (moved)

The **EKS + Helm** module and the **IAM-only** submodule used to live under **`terraform/`** in this repo. They now live in **[iota-infra](https://github.com/iota-corp/iota-infra)**:

| Old path | New location |
|----------|----------------|
| **`terraform/`** (root module) | **`iota-infra/modules/iota-eks-helm/`** |
| **`terraform/system-modules/iota-system/`** | **`iota-infra/modules/iota-system-iam/`** |

See **`docs/manifest-migration-checklist.md`** (Phase 2) and each module’s **`README.md`** in **iota-infra**.

Do **not** add new `.tf` files here.
