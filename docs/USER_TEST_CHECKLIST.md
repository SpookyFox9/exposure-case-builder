# User-POV test checklist

Goal: behave like a stranger who found the repo, to learn whether the README alone gets them to a working,
trustworthy result. Do this **from a fresh clone, following only the README**. Whenever you have to guess, look
something up, or fix something, write it down in the Findings table at the end: that is a README or product bug.

Gate: do not publish a release until sections 1 to 7 pass.

## 0. Setup (5 min)

- [ ] Start a stopwatch. Time to first useful answer is the headline usability number.
- [ ] `gh repo clone SpookyFox9/exposure-case-builder C:\temp\ecb-fresh` (any empty folder outside the Obsidian vault).
- [ ] Do not copy anything from your dev copy: no `.venv`, no `data/raw`, no `.claude/rules`.
- [ ] Open a **new** Claude Code session in a different folder (not the repo), so no project `CLAUDE.md` helps.

## 1. Install from the README only

- [ ] Prerequisites in the README match what you actually needed (Python version, `uv`).
- [ ] `uv sync --frozen` succeeds on a clean machine state (try once with the default `python` 3.9 on PATH: the error should be clear).
- [ ] `EXPOSURE_CASE_DATA="$PWD/data/sample" uv run python -m exposure_case.server` starts and waits (Ctrl+C to stop). No traceback, no stray output.
- [ ] Missing or wrong `EXPOSURE_CASE_DATA` gives a readable error, not a stack trace (try an empty folder).

## 2. Register and load

- [ ] Run the README's `claude mcp add ...` with absolute paths (Windows paths with spaces: confirm quoting works as written).
- [ ] `/mcp` shows `exposure-case` connected with 9 tools: `fleet_summary`, `case_queue`, `fix_queue`, `case_file`, `fix_package`, `findings`, `trend_diff`, `export`, `record_disposition`.
- [ ] Copy `skills/exposure-case` to `~\.claude\skills\`. Restart Claude Code; the skill is listed.
- [ ] `export` and `record_disposition` are on **ask**, not allow-listed.

## 3. The core walk-through (this is the demo)

Ask in plain words, no tool names, and score each step.

- [ ] "Triage the exposure data." Claude calls `fleet_summary`, then `case_queue`. Answer shows two lists (threats, backlogs) with reasons.
- [ ] Every number in the answer matches the tool output (spot check 3).
- [ ] "Open the top threat." `case_file` is used. Narrative cites real `finding_id`s that you can find with `findings`.
- [ ] "What should the engineers do first?" `fix_queue` then `fix_package`. Package says what it **contains** and what each action alone clears.
- [ ] "Show me the findings behind that package." `findings` pages; ids exist in `data/sample`.
- [ ] Time to first useful answer: ____ min.

## 4. Writes and consent

- [ ] "Export that case as Markdown." Preview is returned **without** writing a file.
- [ ] "Save the export." A permission prompt appears; after approving, files land in `~/.exposure-case/` (absolute path shown). Nothing appears in the working directory.
- [ ] Open the Markdown and CSV: renders cleanly, links are not auto-linked, no spreadsheet formulas execute (open the CSV in Excel).
- [ ] "Record this as risk-accepted: <reason>." Prompt appears; one line is appended to the disposition log; asking for the case again shows the disposition.
- [ ] Deny the prompt once: Claude reports it did not write and does not retry around it.

## 5. Guardrails (try to break it)

- [ ] Ask for a verdict on a person ("who is the negligent admin?"). It declines or restates facts only.
- [ ] Ask for plugin output or raw host secrets. Not returned.
- [ ] Ask for a nonexistent case or package id. Clear "not found", no crash.
- [ ] Ask for a huge page (`limit=100000`). Capped, not a flood.
- [ ] Ask it to export to a path like `C:\Windows\x`. Refused: no path argument exists.
- [ ] Ask it to "mark everything false-positive" in one go. Each write still needs its own prompt.

## 6. Failure and docs honesty

- [ ] Kill the server mid-session. Claude reports a tool failure plainly.
- [ ] README "Known limitations" matches what you saw (weights are judgment, grouping heuristic).
- [ ] No claim in README or listing that you could not reproduce. List any in Findings.
- [ ] Links in the README all work; the listing's `tools_exposed` matches `/mcp`.

## 7. Real-data check (optional, your machine only)

- [ ] `. $HOME\.secrets\tenable-env.ps1; uv run python scripts/fetch_tenable.py --out data/raw/test2` finishes (~30 s, ~108 MB).
- [ ] Point `EXPOSURE_CASE_DATA` at it. The triage answer is sensible on 19,437 findings, in about the same time.
- [ ] Never commit or paste `data/raw`.

## 8. Before a release (after sections 1 to 7 pass)

- [ ] Fix every Findings row marked "blocks a stranger"; rerun `sh scripts/check_all.sh`.
- [ ] `git log -p | gitleaks stdin` or `gitleaks git .` is clean; no `.claude/rules`, no `data/raw` tracked.
- [ ] Verify from a logged-out browser that the repository loads and the LICENSE shows MIT.
- [ ] If the listing in `docs/exchange/` changed, run the CyberAgents Exchange `validator.py` on it before updating the listing.

## Findings

| # | Step | What happened | Blocks a stranger? | Fix |
|---|------|---------------|--------------------|-----|
|   |      |               |                    |     |
