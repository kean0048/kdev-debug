# dmesg-agent weekly scorecard

Scoring starts with 2026-W48. Each week a maintainer records one card with `dmesg-agent score --record [--live] --note "..."`; the machine-readable basis lives in `dmesg_agent/scorecards/<week>.json`. Users installing any release inherit this history — the score starts from the first recorded week, not from their install date.

| Week | Version | Overall | Architecture | Accuracy | Improvement | Grade |
|---|---|---|---|---|---|---|
| 2026-W48 | 0.4.0 | 7.0 | 10.0 | 5.0 | 6.5 | C |

## 2026-W48 — 7.0/10 (C)

Recorded 2026-11-27 · version 0.4.0 · head 1275023 · eval mode stub
Note: baseline: case library (shadow) and weekly scorecard introduced; architecture and offline-harness accuracy measured; live-model accuracy is the next weekly run (--live)

### Architecture — 10.0/10

- modularity (module count): 1.5/1.5 — 22 modules, 3258 lines
- largest module stays reviewable: 1.0/1.0 — dmesg_agent/scorecard.py = 487 lines (cap 1200)
- test-file density: 1.0/1.0 — 15 test files / 22 modules
- test functions: 1.5/1.5 — 105 test functions (full credit at 60)
- docs: 1.0/1.0 — README=True, invariant docs (CLAUDE.md Architecture)=True
- module docstrings: 0.5/0.5 — 95% of modules documented
- CI runs tests: 1.5/1.5 — CI-with-pytest=True
- dependency hygiene: 1.0/1.0 — 1 runtime dependencies
- future annotations: 1.0/1.0 — 86% of modules

### Accuracy — 5.0/10

- eval category coverage: 3.0/3.0 — 5 categories: gpu, locking, memory, service, storage
- eval case count: 1.0/2.0 — 5 known-answer cases (full credit at 10)
- harness integrity: 1.0/1.0 — offline harness produced parseable metrics
- live-model accuracy: 0.0/4.0 — live eval not run this week — accuracy above the offline harness is unmeasured (rerun with --live to record it)

### Improvement — 6.5/10

- commits since baseline: 3.0/3.0 — 20 commit(s) since repository start be99392 (baseline week)
- code growth: 2.0/2.0 — 6089 insertions across 56 file(s)
- test growth: 0.0/2.0 — baseline week (deltas start with the next scorecard)
- eval-case growth: 0.0/1.5 — baseline week (deltas start with the next scorecard)
- tests pass: 1.5/1.5 — pytest passed

Improvement evidence (commits since baseline):

- `1275023 feat: per-host case library (shadow) + weekly software scorecard`
- `e5a294f feat: harden the last two product pillars — enforced severity + actionable fix`
- `00e76d2 fix(collectors,executors): sudo elevation for log collection`
- `c4c8bda feat(cli): dmesg-agent check pre-flight subcommand`
- `fcd8b6f docs(readme): versioning and release process`
- `8d33384 ci: version control + CI/CD pipelines`
- `90ff8b3 docs(readme): full option reference — every flag, subcommand and env var`
- `64ae50e feat(cli): dmesg-agent eval subcommand (sashiko-benchmark-style entry)`
- `ba4d605 eval: sashiko-benchmark three-state scoring + noise rate (batch C)`
- `222bb83 feat: zero-token cross-run recurrence tracking (sashiko batch B)`
- `3a8db77 feat: sashiko-parity batch A — drift tolerance, both-sides inconclusive, in-block trimming`
- `4f86747 feat: stream model output live to stderr (sashiko-style progress)`

