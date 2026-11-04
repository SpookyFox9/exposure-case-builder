# Demo script (about 15 minutes, one live case)

Everything below runs on the committed sample (`data/sample`: 154 hosts, 1,125 findings, 50 plugins; fake, masked tenant data). Figures were read from the sample on 2026-11-03. Rehearse once with the real client before the pitch; the contract tests do not prove the narrative reads well.

## Setup (before the room)

```bash
uv sync --frozen
uv run python scripts/make_baseline.py data/sample <new-dir>    # SYNTHETIC earlier pull, for the trend step only
claude mcp add exposure-case \
  --env EXPOSURE_CASE_DATA=<abs path to data/sample> \
  --env EXPOSURE_CASE_BASELINE=<abs path to the new-dir> \
  -- uv run --directory <abs path to this repo> python -m exposure_case.server
```

Then copy the skill so the client loads the current one (an older copy in `~/.claude/skills` silently wins), and move any earlier disposition log aside so the demo starts at zero:

```bash
cp -r skills/exposure-case ~/.claude/skills/
mv ~/.exposure-case/dispositions.jsonl ~/.exposure-case/dispositions.before-demo.jsonl   # if it exists
```

Start a new Claude Code session afterwards (tools and skills load at startup), and rehearse on the model you will pitch with: wording varies between models. Keep `export` and `record_disposition` on "ask" in the client's tool permissions. If a real second pull exists by then (`scripts/fetch_tenable.py` again), use it as the baseline instead and drop the synthetic caveat.

## 0. Open with the outcome, then position it honestly (1 min)

Lead with the result on the sample: 1,087 active findings become 43 cases and 33 fix packages, and the top package hands an engineer 10 named OpenSSH upgrades for 21 hosts, each with what it alone affects. Black Hat SWARM judges "scored impact above everything else" (Tenable's recap), so the number comes first.

Then position it. Per Tenable's documentation (read 2026-11-03, not tested on a live tenant), the **Solutions view**, **Exposure Response** and **Hexa AI** cover related ground on Tenable One or Lumin licensing; this project needs only a saved Vulnerability Management export, never changes Tenable, and its handoff needs no Tenable login. The judges may also have seen **Vuln Prioritizer** (PR #225, same tenant): it ranks each finding and assigns an SLA tier from CVSS, VPR, EPSS, KEV and CMDB context. Say the difference in one line: *it ranks findings and sets deadlines; this groups findings into cases and fix packages and hands each package to the engineer who applies it.* Concede what it has and this does not: SLAs, asset context, external exploit feeds.

## 1. The size of the problem (1 min) - `fleet_summary`

154 hosts, 1,087 active findings (32 critical, 125 high), 24 on the CISA KEV list, 43 cases and 33 fix packages. Mention the data-quality notes, and explain the "25 of 50" before anyone reads it as half the data being wrong: it compares **plugins**, not findings, against Tenable's own per-plugin counts, and on this sample every gap has the export *below* Tenable's number (checked 2026-11-03; cause unverified; the answer's direction counts show it for any data). The sample keeps the most widespread plugins, which include 25 of the 41 plugins that differ on the full export, where 4,636 of 4,677 plugins (99.1%) match.

## 2. Two lists, on purpose (2 min) - `case_queue`

Threats (one vulnerability each) and backlogs (a whole patch family) come back separately so a large backlog cannot bury an exploited vulnerability. Top threat: **Bash Remote Code Execution (Shellshock)**, 5 hosts, score 70.8. Top backlog: **Windows : Microsoft Bulletins**, 14 hosts, score 80.9. Open the Shellshock case: `case_file`, then `findings` for real finding ids, and let Claude write the short cited narrative. Point at the score breakdown: a fixed weighted sum, no model.

## 3. The engineer's view (3 min) - `fix_queue`, `fix_package`

Show the top package, **OpenSSH (patch)**: 21 hosts and **10 distinct Tenable actions** ("Upgrade to OpenSSH version 10.4 or later", "... 10.5 ...", and so on). Each action has its own row with what it alone clears. A human can see these are cumulative; the tool does not claim it, because Tenable's data does not say one update replaces another. This is the part to dwell on. Then `export` the package as Markdown: Claude shows the returned ticket body, which an engineer can use without a Tenable login. Its "Source records" section counts the finding ids and points to the JSON export, which lists them all. Saving the files is a separate, approved write.

## 4. What first, if hosts are the goal (2 min) - `fix_queue` with `order="coverage"`

Step 1 is the OpenSSH patch package: it brings 8 of the 67 hosts with an urgent finding to zero, but it means 10 actions. Step 2, **OpenSSH (configuration)**, is one action and brings 19 more hosts to zero (27 of 67 in total). Say plainly that this is a heuristic, not the shortest plan, that "cleared" means no urgent finding in the export (urgent = critical, KEV, exploited by malware or a public exploit), and that a step is not an effort estimate: read the actions column. On the full competition export (private) the first step is 93 distinct updates for 8 hosts, which is why that column is there. Do not reorder steps or add up a few of them (for example, "do steps 5-7 first and clear 11 hosts", which a rehearsal produced): each step's figures assume every earlier step is done, so a different order needs the engine to recompute it. To contrast with risk, point at the score rank.

## 5. What changed since last time (2 min) - `trend_diff`

State first that this baseline is **synthetic** (the answer says so too). Show the counts: new since baseline 13, newly visible 51, fixed as recorded 9, reopened 17, not seen (host rescanned) 62, severity raised 2 and lowered 6, with host overlap (145 of 154) beside them. Then the rule: a finding missing from the later export is never reported as fixed, because Tenable recorded no fix. Say that finding-id stability across real pulls is undocumented and untested here, and that `id_reuse` and `possible_rekeys` are the counters that would show it. Then ask "Which findings were reopened since the last pull?": the same tool pages through the actual finding ids by category.

## 6. The decision (1 min) - `record_disposition`

Tell Claude a decision and a note; it reads the entry back and records it only after you confirm. One appended line in a local log; nothing else changes.

## Likely questions

- **"Why a weighted sum? SSVC and BOD 26-04 use decision tables."** True, and neither endorses a weighted sum. The score here only orders work and shows its breakdown; it is not a risk measure. The two-list queue does the gate-like part (an exploited single vulnerability is never buried under a patch backlog), and EPSS is shown but not multiplied in, per FIRST's guidance. A decision-table tier is a reasonable next step.
- **"Are Tenable's finding ids stable between pulls?"** Tenable documents `finding_id` as the finding's unique identifier but never states it is stable; its own integration guide names asset, plugin, port and protocol as the unique key. `trend_diff` requires both to agree, and its `id_reuse` and `possible_rekeys` counters show any disagreement. A new asset UUID (a rebuilt or re-created host) would mean new findings.

## Do not claim

- That Tenable lacks fix grouping, tickets or an MCP server.
- That the coverage order is optimal, or that a step is a measure of effort.
- That anything missing from a later pull was fixed.
- That the trend diff has been proven on two real pulls (unless it has been by then).
- Anything about who owns a host: the tenant has no owner or tag data.

## If something fails

The server, the skill and the data are all local. If the client misbehaves, `uv run pytest tests/test_server.py` shows the same tools answering over the real protocol, and `exposure_case.service.Workspace` can be called from a Python shell with the same arguments. If the synthetic baseline is missing, skip step 5 rather than improvise numbers.
