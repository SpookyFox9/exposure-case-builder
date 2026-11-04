# Exposure case playbook

For the analyst running the tool. The `/exposure-case` skill tells Claude how to use the tools; this page
tells you how to set it up, run a triage session and share the results.

## 1. One-time setup

1. `uv sync` in the repo. Python 3.10 or newer (via `uv`).
2. Store your Tenable API keys outside the repo (read-only keys). On Windows the repo's helper scripts keep them
   DPAPI-encrypted under `~/.secrets/`; load them per session with `. ~/.secrets/tenable-env.ps1`. The keys live
   in `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` and are never written to the repo.
3. Optional but recommended: set `TENABLE_UA_VENDOR` to your company or team name. Tenable asks integrations to identify themselves with `User-Agent: Integration/1.0 (VENDOR; PRODUCT; Build/VERSION)`; the script sends it on every call, and the vendor otherwise defaults to the project name.
4. Fetch an export (the one outbound network call in the project):
   `uv run python scripts/fetch_tenable.py --out data/raw/<name>`. About 30 seconds and 100 MB for 160 hosts.
   `data/raw/` is gitignored.
5. Register the MCP server with Claude Code (this edits your Claude config, so you run it):
   ```
   claude mcp add exposure-case --env EXPOSURE_CASE_DATA=<absolute path to data/raw/<name>> -- uv run --directory <absolute path to this repo> python -m exposure_case.server
   ```
   Check `claude mcp add --help` if your version orders the flags differently. To try it without a Tenable
   account, point `EXPOSURE_CASE_DATA` at `data/sample` (a trimmed, fake, masked sample).
6. Copy `skills/exposure-case` to `~/.claude/skills/` (or your project's `.claude/skills/`).

Optional settings: `EXPOSURE_CASE_EXPORTS` (default `~/.exposure-case/exports`) and `EXPOSURE_CASE_DISPOSITIONS`
(default `~/.exposure-case/dispositions.jsonl`). Both must be absolute paths if you set them, so output never lands in
whatever directory the server was started from.

## 2. A triage session

1. Ask: *"Triage the exposure data."* Claude reads `fleet_summary` and shows two lists:
   **threats** (one vulnerability each) and **backlogs** (a whole patch family), each with why it ranks there.
2. Pick one. Claude pulls the case file and real finding IDs and writes a short cited narrative: what it is,
   why it ranks here, the evidence, what limits it, how Tenable says to fix it, what else to check.
3. Ask: *"What should engineers do first?"* Claude shows the **fix queue**. A package groups findings by how they
   are fixed, such as "apply updates to OpenSSH".
4. Optional: ask *"In what order do we get hosts free of urgent findings?"* Claude shows the fix queue in
   **coverage order**. It is a heuristic, and a step can mean many actions, so read the actions count next to the
   hosts cleared. Ask *"What changed since the last pull?"* only if the operator configured a baseline; Claude
   shows the trend counts with the host overlap, and never calls a missing finding fixed.
5. Ask for a handoff: Claude renders the package as Markdown for a ticket. Saving files (`exports/`) needs your
   explicit yes.
6. Tell Claude your decision (`assigned`, `risk-accepted`, `false-positive` or `needs-info`), your name and a
   note. Claude reads it back and records it only after you confirm. The next queue can hide decided items.

## 3. Reading the numbers

- **Score (0-100).** A fixed weighted sum, shown component by component in every case: severity 30, exploit 25
  (CISA KEV, malware, high VPR, public exploit), breadth 15, volume 10, age 5, unsupported 5, recurrence 5,
  patch 5. Nothing is learned or hidden; change the weights in `scoring.py` and every number follows.
- **Threats and backlogs are ranked separately** on purpose. A large OS backlog scores high because of its size
  and breadth; a single exploited vulnerability on one host would otherwise vanish beneath it.
- **A package's impact is what it contains.** It spans several distinct actions. Only each action's own row says
  what that action alone clears. Tenable's data does not say one update replaces another, so the tool never
  claims it.
- **Dates.** Ages are measured from the newest observation in the export, not today. Fixed and reopened dates
  are Tenable's own where it supplies them.

## 4. Sharing safely

- Markdown is the supported format for tickets and chat. Fix text, hostnames and advisory URLs come from
  Tenable and are escaped; URLs appear as text, not links. For another system, use the JSON export.
- CSVs open safely in Excel: anything that looks like a formula is prefixed with an apostrophe.
- Hostnames and IPs in the committed sample are masked. Treat identifiers as opaque and do not research them.

## 5. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Server exits at start with "set EXPOSURE_CASE_DATA" | The env var is missing in the `claude mcp add` command. |
| "data directory not found" | The path is wrong or relative; use an absolute path to the folder that contains `chunks/`. |
| "cannot load the export: ..." | A chunk is malformed or unusually large; the message names the file and record. Fetch again. |
| `record_disposition` or `export` says confirm is required | Working as intended: say yes to Claude's read-back first. |
| Queue looks empty with `hide_dispositioned` | Everything shown has a recorded decision; turn the filter off. |
| Tool says "unknown case_id" | Ids change with the data. Re-run `case_queue` and use an id from it. |

## 6. What protects the writes

`confirm=true` is something Claude passes, not proof that you agreed: the server cannot tell the difference. The
real gate is your client's tool-permission prompt. In Claude Code, leave `export` and `record_disposition` on
"ask" (do not allow-list them) so you see every write before it happens. Tenable text (plugin names, solution
text, hostnames) is untrusted and could contain instructions aimed at the model; the server and the skill tell
Claude to treat it as data, but the permission prompt is what stops a mistake.

## 7. Data flows

The server reads the saved export and makes no network calls. The only outbound call is `scripts/fetch_tenable.py`
(reads from Tenable; creates an export job on Tenable's side). The only local writes are export files (fixed
directory) and the disposition log (append-only), each only after `confirm=true`. Nothing changes Tenable or any
other system.
