# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the repository's **Security** tab and choose
**Report a vulnerability** (GitHub private vulnerability reporting). Do not open a public issue for a
vulnerability. This is a one-person project, so replies are best effort; expect an acknowledgement within a few
days.

Please include what you found, how to reproduce it, and what an attacker could do with it. Test only against your
own data or the committed sample (`data/sample`, fake and masked).

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release branches.

## Scope

In scope: the MCP server and engine (`src/exposure_case/`), the fetch script (`scripts/fetch_tenable.py`), the
Claude Code skill and playbook, and the export files the tool writes.

Out of scope: Tenable's own services and APIs, the MCP Python SDK and Claude Code themselves (report those to
their maintainers), and the sample data's source tenant.

## Threat model in brief

The server runs locally over stdio, reads a saved Tenable export from disk, and makes no network calls. The fetch
script is the only network code. How each class of risk applies:

| Risk | Applies? | How it is handled |
|---|---|---|
| Prompt injection through Tenable text (plugin names, solution text, hostnames, advisory links) — MCP security best practices; OWASP LLM01 | Yes | The text reaches the model only as values inside JSON fields. The server instructions and the skill say it is data, never instructions, and never a reason to call a write tool. Exports neutralize it for Markdown, CSV (formula prefixes) and invisible or bidirectional characters. Plugin output is never returned. |
| A model calling a write tool on its own — excessive agency, OWASP LLM06 | Low | Only two tools write, both locally: `export` (files in a fixed directory) and `record_disposition` (an append-only log). Both need `confirm=true`, but **the model sets that flag, so it is not human approval on its own**. The real gate is the client's permission prompt: keep both tools on "ask" (see the README). No tool accepts a file path. |
| Tool annotations | — | `readOnlyHint` and `destructiveHint` are set on every tool, but clients must treat annotations as hints, not controls. |
| Oversized or hostile input | Yes | Each export file is capped at 128 MB, a whole export at 1 GB, the number of chunk files at 1,000, and each text field at 4,096 characters; JSON errors and deep nesting become a clear error. Tool answers are capped so one call cannot flood the model's context; exports stay complete. |
| Confused deputy, token passthrough | No | The server has no OAuth, holds no tokens and calls no API. |
| SSRF | Fetch script only | It talks to `https://cloud.tenable.com` and nothing else, never follows redirects (they would forward the API keys), and caps each response at 128 MB. |
| Secrets | Fetch script only | API keys come from environment variables, are never written to disk, logs or tool output, and are hidden from `repr`. The pre-commit hook (`.githooks/pre-commit`, enabled per clone with `git config core.hooksPath .githooks`) scans each staged diff with gitleaks, the full history across all refs was scanned before release, and GitHub secret scanning with push protection is enabled on the repository. |
| Local compromise of the server process | Reduced | Stdio only (no listening socket), pinned dependencies installed from `uv.lock` with hashes, actions in CI pinned to commit hashes with read-only permissions. |
| Data sent to the model provider | Yes | Tool answers (hostnames, IPs, plugin names) go to whichever model your client uses. The committed sample is fake and masked; treat real tenant data accordingly. |
| Unknown tool arguments | Low | The MCP SDK ignores arguments a tool does not declare. A misspelled flag can therefore never turn a write on: writes require `confirm=true` exactly (strict booleans). |
