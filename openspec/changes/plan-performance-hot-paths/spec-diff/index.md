# Spec diff: plan-performance-hot-paths

Manual summary for review (regenerate with `/openspec-spec-diff` if the project uses automated annotation).

## New: `openspec/specs/performance/spec.md`

- New capability covering roadmap performance targets: Python engine amortization, bounded memory for large S3 objects, line scanner limits, data lake flush latency, SQLite contention, `--process-workers`, OTel sampling.
- Requirements use **SHOULD** / **MAY**; baseline notes reference bloom filter and project performance figures.

## `openspec/project.md`

- Under **Performance Characteristics**, added pointers to `docs/PERFORMANCE-ROADMAP.md` and OpenSpec change `plan-performance-hot-paths`.

## `docs/DEVELOPMENT.md`

- Capabilities list includes **`performance`**; added link to `PERFORMANCE-ROADMAP.md` and `plan-performance-hot-paths`.
