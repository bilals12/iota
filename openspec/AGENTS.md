# OpenSpec Instructions (Turo Workflow)

Instructions for AI coding assistants using OpenSpec with iota.

## TL;DR Quick Checklist

- Search existing work: `openspec list --specs`, `openspec list`
- Decide scope: new capability vs modify existing capability
- Pick a unique `change-id`: kebab-case, verb-led (`add-`, `update-`, `remove-`, `refactor-`)
- Scaffold: `proposal.md`, `tasks.md`, `design.md` (only if needed) under `changes/<id>/`
- **Edit specs directly** in `openspec/specs/` (not in `changes/<id>/specs/`)
- Generate spec-diff: Run `/openspec-spec-diff` to create annotated diff for review
- Request approval: Do not start implementation until proposal is approved

## Key Difference: Turo vs Standard OpenSpec

| Aspect              | Standard OpenSpec                  | Turo Workflow                         |
| ------------------- | ---------------------------------- | ------------------------------------- |
| Spec changes        | `changes/<id>/specs/<cap>/spec.md` | Direct edit in `openspec/specs/`      |
| Change tracking     | Delta files with ADDED/MODIFIED    | Git branch diff                       |
| Multi-repo support  | Single repo only                   | Frontmatter declares multiple repos   |
| Archival            | Merge deltas into specs            | `--skip-specs` (specs already merged) |
| Reviewable artifact | Delta files                        | `spec-diff/index.md`                  |

## Three-Stage Workflow

### Stage 1: Creating Changes

Create proposal when you need to:

- Add features or functionality
- Make breaking changes (API, schema)
- Change architecture or patterns
- Optimize performance (changes behavior)
- Update security patterns
- Add new detection rules (bulk additions)

Skip proposal for:

- Bug fixes (restore intended behavior)
- Typos, formatting, comments
- Dependency updates (non-breaking)
- Configuration changes
- Tests for existing behavior
- Individual rule additions

**Workflow**

1. Review `openspec/project.md`, `openspec list`, and `openspec list --specs` to understand current context.
2. Choose a unique verb-led `change-id` and scaffold `proposal.md`, `tasks.md`, optional `design.md` under `openspec/changes/<id>/`.
3. **Edit specs directly** in `openspec/specs/<capability>/spec.md` (create new capability folder if needed).
4. Run `/openspec-spec-diff` to generate annotated diff in `changes/<id>/spec-diff/`.
5. Request approval before implementation.

### Stage 2: Implementing Changes

1. **Read proposal.md** - Understand what's being built
2. **Read design.md** (if exists) - Review technical decisions
3. **Read tasks.md** - Get implementation checklist
4. **Implement tasks sequentially** - Complete in order
5. **Update checklist** - After all work is done, set every task to `- [x]`
6. **Approval gate** - Do not start implementation until the proposal is reviewed and approved

### Stage 3: Archiving Changes

After deployment:

1. Verify `spec-diff/` is current (regenerate with `/openspec-spec-diff` if needed)
2. Run `openspec archive <change-id> --skip-specs --yes`
3. Change moves to `changes/archive/YYYY-MM-DD-<change-id>/`

## Directory Structure

```
openspec/
├── project.md              # Project conventions
├── specs/                  # Current truth - edit directly on branches
│   ├── detection-engine/   # Core detection pipeline
│   ├── log-processing/     # Adaptive classifier, parsers
│   ├── alerting/           # Deduplication, forwarding
│   ├── deployment/         # SQS/EventBridge modes, Terraform
│   └── transforms/         # Substation-inspired pipeline
├── changes/                # Proposals
│   ├── [change-name]/
│   │   ├── proposal.md     # Why, what, impact
│   │   ├── tasks.md        # Implementation checklist
│   │   ├── design.md       # Technical decisions (optional)
│   │   └── spec-diff/      # Annotated spec changes
│   │       └── index.md
│   └── archive/            # Completed changes
```

## CLI Commands

```bash
openspec list                  # List active changes
openspec list --specs          # List specifications
openspec show [item]           # Display change or spec
openspec validate [item]       # Validate changes or specs
openspec archive [change] --skip-specs --yes  # Archive (Turo workflow)
```

## Quick Reference

### File Purposes

- `proposal.md` - Why and what
- `tasks.md` - Implementation steps
- `design.md` - Technical decisions
- `spec.md` - Requirements and behavior
- `spec-diff/` - Annotated changes for review

Remember: Specs are truth. Edit them directly on branches. Use `spec-diff/` for reviewable artifacts.
