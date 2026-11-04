# Pitch outline (Thu 2026-11-05, 12:45 PM ET, Zoom)

Format, from the organizers: 15 minutes on Zoom. About **8 minutes to pitch and demo**, **5 minutes of judges' questions**, 2 minutes spare. Start with the problem, then show it working; a live demo is best. Test microphone, video and screen share before joining.

Scoring: **mission impact 40%**, technical execution 20%, innovation and creativity 20%, pitch execution 20%.

This is an outline to follow, not a script. `docs/DEMO.md` is the longer 15-minute walk-through. Its figures, "Likely questions" and "Do not claim" list still apply. Steps 4 and 5 from DEMO.md (coverage order, trend diff) are held back for questions.

## Morning checklist (before 12:30 PM ET)

1. In `C:/Users/maupi/Documents/GitHub/exposure-case-builder-demo`, run `git pull` (docs only since `1637819`). The installed skill in `~/.claude/skills/exposure-case` is current; re-copy only if `skills/` changed.
2. Move every earlier disposition log aside: `~/.exposure-case/dispositions.jsonl` must not exist, so the decision step starts at zero.
3. Check that the demo clone has `.claude/settings.local.json`, with the seven read tools under `allow` and `export` and `record_disposition` under `ask`. Without it, every read tool prompts, and the deny test on 2026-11-04 showed this stalls the demo. Move the `2026-11-03-*.txt` rehearsal transcripts out of the clone root: one has a guardrail-test title naming an "admin", and Claude offers these files when tools fail. Start `claude` there, then check `/mcp` (connected) and `/permissions`.
4. Prepare the screen: a large terminal font (readable on a shared Zoom screen), notifications off (Windows Focus, Discord, mail), and only the terminal and one browser window open. No vault, `.secrets` or e-mail on screen.
5. Open the fallbacks in browser tabs: the README's "What you get" section on GitHub, and the saved rehearsal transcript. Have `uv run pytest tests/test_server.py` typed and ready in a second terminal.
6. Join Zoom early. Test the microphone, camera, and **sharing the terminal window** (not the whole desktop).
7. Keep this outline on a second screen or a printout, not in the shared window.

## The 8 minutes

### 1. Problem (about 1 min, no screen share yet) [impact]
- A Tenable export is thousands of findings. An analyst has to answer two questions: *what is risky* and *what does the engineer actually do*.
- The two answers come in different units: risk is per vulnerability, work is per patch. A big patch backlog hides one exploited vulnerability, and a ranked list of findings doesn't tell the engineer what to do.
- Who it helps: the analyst triaging, and the engineer on another team who has to apply the fix without a Tenable login.

### 2. The result in one line (about 30 s) [impact]
- On the competition sample: **1,087 active findings become 43 cases and 33 fix packages.** The top package gives an engineer 10 named OpenSSH upgrades for 21 hosts, with what each one alone affects.
- How it works: code clusters, scores and collects evidence; Claude writes the narrative; the human decides.

### 3. Live demo (about 5 min, share the terminal) [technical, innovation]
Ask for one beat at a time. While Claude works, talk over it.

- **a. "What should I look at first?"** (`fleet_summary`, `case_queue`, about 1.5 min)
  - Point: there are **two lists on purpose**, threats and backlogs, so a backlog never buries an exploited vulnerability.
  - Top threat: Shellshock, 5 hosts. Top backlog: Windows bulletins, 14 hosts.
  - Point at the score breakdown: a fixed weighted sum shown component by component, no ML.
- **b. "Open the Shellshock case"** (`case_file`, `findings`, about 1 min)
  - Claude's narrative cites real finding ids. Everything traces back to `finding_id` and `scan.uuid`.
- **c. "What does the engineer do?"** (`fix_package` OpenSSH, then `export` Markdown, about 2 min) **This is the centerpiece. Spend the most time here.**
  - 10 distinct Tenable actions, each with what *it alone* clears.
  - The tool does not claim one update replaces another, because Tenable's data doesn't say so.
  - Show the ticket body: an engineer can act on it without a Tenable login.
- **d. "Record the Shellshock case as assigned, analyst Colter, note: patch window Friday."** (`record_disposition`, about 30 s). Give the exact value (`assigned`) and an analyst name, or Claude stops to ask: "accepted" is ambiguous between `assigned` and `risk-accepted`.
  - The approval prompt appears. Approve it and show it's one appended local line.
  - Point: the human makes the decision, and nothing outside the machine changed.

### 4. Why this, not the others (about 1 min) [innovation]
- Use the one-line difference from the competitor research (fill in after it arrives). The default line: *Vuln Prioritizer ranks findings and sets deadlines; this groups them into cases and fix packages and hands each package to the engineer who applies it.*
- Admit what the others have (SLAs, asset context, exploit feeds, act-and-verify).

### 5. Trust and close (about 30 s) [technical]
- Read-only. Tenable text is treated as untrusted data. Writes need approval. The engine never touches the network.
- 758 tests and CI are green, and a full-history secret scan is clean. Listed on the Exchange as PR #227.
- Close with one sentence about the impact: what to fix first, and a handoff the engineer can use.

## Timing guardrails
- If the demo is past 6:30, skip 3d and just describe it.
- If Claude stalls for more than 20 s, say so, switch to the rehearsal transcript tab, and keep talking.
- Don't type long prompts live. Have the four beat prompts ready to paste.

## Questions (5 min). Keep answers short.
- **Weighted sum versus SSVC or BOD 26-04 decision tables:** see DEMO.md.
- **Are finding ids stable between pulls?** See DEMO.md, then show `trend_diff` if they ask about change over time. Say first that the baseline is synthetic.
- **"Which hosts first?"**: `fix_queue(order="coverage")`. It's a heuristic, not the shortest plan.
- **"How is this different from Tenable's Solutions view or Exposure Response?"**: this needs only a saved VM export, doesn't need Tenable One, and the handoff needs no login. Don't claim Tenable lacks fix grouping.
- **"What's next?"**: per-case trend deltas, a decision-table tier, and per-action plugin ids.
