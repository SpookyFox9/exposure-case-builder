# Engineering rules audit (2026-11-02)

The user's written rules (`common/` and `python/`, copied into `.claude/rules/`) were checked against everything built so far, with tools where a tool exists and by reading where it does not. This page records what was found, what was done, and what remains. Deviations from a rule are recorded here with their reason (see `CLAUDE.md`).

## Method

Measured with the project's own tools (ruff, black, mypy, bandit, coverage, `scripts/check_standards.py`), a scan of all 16 commits with gitleaks, a run of the suite on Python 3.10, and three independent reviews: a whole-repository `security-reviewer`, a whole-repository `code-reviewer` (also acting as consistency and redundancy reviewer), and prior-art research. Refactors were proved behavior-neutral by hashing every export and tool answer on the full real tenant (1,015 items) and on the committed sample (93 items) before and after.

## Rule by rule

| Rule | At audit | Resolution |
|---|---|---|
| Immutability (critical) | `service.py` edited dictionaries it had just been handed; all dataclasses already frozen | Responses are now built as new dictionaries. Checker enforces `frozen=True`. **Exception, documented:** `Workspace`'s memoization caches (derived and rebuildable, never exposed) |
| Small files (800 max, 200-400 typical) | Largest 324 lines | Still true; `service.py` is now 431 (a warning). The Markdown renderers were split into `report_md.py` and the neutralizers into `text_safety.py` |
| Functions under 50 lines | **4 violations** (`package_markdown` 87, `case_markdown` 93, `parse_record` 65, `service.export` 54) plus `build_server` and `record_disposition`; black had expanded them, and ad-hoc checks missed it | All split. `scripts/check_standards.py` now enforces it on every commit |
| No deep nesting (over 4) | None | Enforced by the checker |
| Error handling; input validation | Sound; hardened further by two reviews | See the reviews below |
| No hardcoded secrets; secret management | gitleaks clean over all history; keys only from environment variables | Unchanged. `python-dotenv` (suggested by `python/security.md`) is not used: keys come from an encrypted vault outside the repo, so a `.env` file is unnecessary |
| `python/security`: bandit | Never run | Run: 0 issues. Now a gate |
| Security response protocol: use the `security-reviewer` agent and review the whole codebase after a finding | **Not followed**: earlier security findings went to `python-reviewer` and only the changed files were reviewed | Whole-repo `security-reviewer` run; see below |
| 80% coverage; unit, integration **and E2E** tests | Coverage 96%; **no E2E test**; no markers | E2E test added; unit/integration/e2e markers assigned in `tests/conftest.py`; coverage is a gate |
| TDD: write the test, see it **fail**, then implement | Followed for most code; for clustering, scoring, fix packages and links the tests and code were written together and the failing run was not observed | Followed since the audit (every new test file was run RED first); stated in `CLAUDE.md`. Cannot be fixed retroactively |
| `python/coding-style`: **black**, isort, ruff, type annotations on all signatures | **black never run** (31 of 42 files unformatted); ruff run only with ad-hoc settings; no annotation gate | black applied in its own commit; ruff, black and `mypy --disallow-untyped-defs` configured in `pyproject.toml` and gated |
| `python/hooks`: no `print()` | 6 calls | Replaced with `logging` (stderr); `T201` and the checker enforce it |
| Development workflow, **step 0: research and reuse** | **Skipped.** The pivot moved into a domain with real prior art without a search | `PRIOR_ART.md`: about 35 listings read; positioning corrected; pyTenable evaluated and declined with reasons |
| Planning docs (architecture, design, tasks) | Only `PLAN.md` | `docs/architecture.md` added; `PLAN.md` rewritten to match reality |
| Agent rules (`planner`, `architect`, `tdd-guide`, `code-reviewer`, `security-reviewer`) | **Not used.** Planning was done inline; reviews used `python-reviewer` (four times) and `web-fetch` only | `code-reviewer` and `security-reviewer` run on the whole repo; the requirement is written into `CLAUDE.md`. `planner`, `architect` and `tdd-guide` were still not launched in this audit (see Remaining) |
| Conventional commits; no attribution line | Followed | Unchanged |
| API response shape (status, data, error, pagination metadata) | MCP carries status and errors in its own `is_error` channel; `findings` lacked `limit` | `findings` now returns `total`, `offset` and `limit` |
| Python >= 3.10 | **Claimed but untested** (only 3.14 had run) | Suite run on 3.10: 481 passed. CI runs 3.10 and 3.12 |

## Reviews run in this audit and what was done

**Security review (whole repository): 0 critical, 0 high, 3 medium, 7 low.** All acted on except where noted.

- Redirects would have forwarded the API keys: now refused; proved against a local server. Response and chunk-count caps; export id validated; symlinked output directory refused; temp-file writes.
- Stored analyst notes and untrusted text reach the model: notes omitted from bulk rows and labelled in detail views; the number of hidden items is reported; instructions say the text is data. **Not adopted:** MCP elicitation (client support unverified); `confirm` remains a convention backed by the client prompt, stated honestly in the README, skill, playbook and tool docs.
- Bare URLs auto-link in Markdown: now inert code spans. `plugins.json` overflow could crash start-up: fixed. Total-size and file-count limits added. Output paths no longer default to the working directory.
- The committed sample held plugin output, one record of which contained a person's email address: plugin output removed from the sample and from the sample builder.
- Not done: rewriting git history (two early commits contain a Windows username in a path, and the history holds the retired synthetic insider data); the supply-chain note to prefer `uv sync --frozen` is now in `CLAUDE.md`.

**Code review (whole repository): 0 critical, 0 high, 8 medium, 7 low.**

- Stale or wrong docs (PLAN tools table, scoring table, status): `PLAN.md` rewritten. Dead `Finding` class: removed. Mismatched input limits: one source. Duplicated helpers (worst severity x3, plural x2, invisible-character stripper x2): consolidated. README overstated what was verified: figures from the private full export are now labelled as such.
- Formatting and function size: see the table. Test files named after review events: renamed by topic.
- Not done: moving shared test helpers out of test modules into one helper module (the cross-test imports remain; low risk, recorded as follow-up).

Earlier, narrower reviews (`python-reviewer`) covered the fetch script and ingest, the fix view, the exporters, and the MCP server; their findings were fixed in commits `9bd18e1`, `486f8e5` and `71942b7`.

## Remaining deviations and follow-ups

- **`planner`, `architect` and `tdd-guide` agents** were not launched during this audit; the plan and design were produced inline and reviewed by the user. Going forward `CLAUDE.md` requires them for complex features and architectural decisions.
- **`PostToolUse` formatting and type-check hooks** (`python/hooks.md`) are not configured. They belong in the user's `~/.claude/settings.json` (a global change), not in the public repo, where a hook would run commands for anyone who opens it. Left for the user to decide.
- **`service.py` is 431 lines** (warning, limit 800). Splitting the queue/row builders into their own module is a reasonable next step.
- **Cross-test imports** between test modules remain.
- **The live Claude Code session** has not been run, so narrative quality is untested beyond the contract tests.
