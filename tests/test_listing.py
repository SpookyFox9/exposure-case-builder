"""The drafted Exchange listing must match the real server and the vocabularies reported on 2026-11-02.

The vocabularies below come from tenable/cyberagents-exchange validator.py as read on that date. Before opening
the PR, also run the Exchange's own `uv run ./validator.py` in your fork: that file is the source of truth.
"""

import asyncio
import json
import re
from pathlib import Path

import pytest

from exposure_case.server import build_server
from exposure_case.service import Workspace

ROOT = Path(__file__).resolve().parent.parent
LISTING = ROOT / "docs" / "exchange" / "mcp-server-listing.md"
PLACEHOLDER = "REPLACE_WITH_YOUR_ACCEPTANCE_TIMESTAMP"

DOMAINS = {
    "ai-security",
    "application-security",
    "cloud-security",
    "cryptography-pki",
    "data-security",
    "email-collaboration-security",
    "governance-risk-compliance",
    "identity-access",
    "network-security",
    "ot-iot-security",
    "platform-operations",
    "security-awareness",
    "security-operations",
    "threat-intelligence",
    "vulnerability-management",
}
INTEGRATIONS = {
    "Anthropic",
    "AWS",
    "Azure",
    "Check Point",
    "Cisco",
    "CrowdStrike",
    "Firebase",
    "Fortinet",
    "GCP",
    "IPGeolocation.io",
    "KnowBe4",
    "Microsoft Sentinel",
    "Mimecast",
    "Netskope",
    "NVD",
    "PagerDuty",
    "Palo Alto",
    "Qualys",
    "Rapid7",
    "Recorded Future",
    "SentinelOne",
    "ServiceNow",
    "Snyk",
    "Splunk",
    "Supabase",
    "Tenable",
    "Tenable Hexa AI MCP",
    "URLScan.io",
    "VirusTotal",
    "Wiz",
    "Checkmarx One",
    "SecurityScorecard",
}
CLIENTS = {
    "Antigravity",
    "ChatGPT",
    "Claude Code",
    "Claude Desktop",
    "Cline",
    "Codex",
    "Continue",
    "Cursor",
    "Gemini CLI",
    "VS Code Copilot",
    "Windsurf",
}
TRANSPORTS = {"stdio", "http", "both"}
RUNTIMES = {"binary", "bun", "go", "node", "python", "rust"}
AUTH = {"api-key", "none", "oauth2", "token"}


def parse(text: str) -> tuple[dict, list[dict], str]:
    match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.DOTALL)
    assert match, "listing must start with YAML frontmatter"
    head, body = match.groups()
    meta: dict = {}
    tools: list[dict] = []
    in_tools = False
    for line in head.splitlines():
        if line.startswith("tools_exposed:"):
            in_tools = True
            continue
        if in_tools and line.startswith("  - name:"):
            tools.append({"name": json.loads(line.split(":", 1)[1].strip())})
            continue
        if in_tools and line.startswith("    description:"):
            tools[-1]["description"] = json.loads(line.split(":", 1)[1].strip())
            continue
        in_tools = False
        key, _, value = line.partition(": ")
        value = value.strip()
        meta[key] = json.loads(value) if value[:1] in '["' or value in ("true", "false") else value
    return meta, tools, body


@pytest.fixture(scope="module")
def listing():
    return parse(LISTING.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def real_tools(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("listing")
    ws = Workspace.load(ROOT / "data" / "sample", exports_dir=tmp / "e", dispositions_path=tmp / "d.jsonl")
    return {t.name for t in asyncio.run(build_server(ws).list_tools())}


def test_required_fields_present(listing):
    meta, _, _ = listing
    required = [
        "name",
        "author",
        "github_url",
        "description",
        "license",
        "tier",
        "tags",
        "domains",
        "integrations",
        "date_added",
        "contribution_agreement_date",
        "transport",
        "runtime",
        "auth_method",
        "compatible_clients",
        "tools_exposed",
        "resources_exposed",
        "prompts_exposed",
    ]
    assert not [f for f in required if f not in meta and f != "tools_exposed"]


def test_controlled_vocabularies(listing):
    meta, _, _ = listing
    assert meta["tier"] == "contributed" and 1 <= len(meta["domains"]) <= 2
    assert set(meta["domains"]) <= DOMAINS and set(meta["integrations"]) <= INTEGRATIONS
    assert set(meta["compatible_clients"]) <= CLIENTS
    assert meta["transport"] in TRANSPORTS and meta["runtime"] in RUNTIMES and meta["auth_method"] in AUTH


def test_listing_tools_match_the_real_server(listing, real_tools):
    _, tools, _ = listing
    assert {t["name"] for t in tools} == real_tools
    assert all(t["description"].strip() for t in tools)


def test_license_matches_the_license_file(listing):
    meta, _, _ = listing
    assert meta["license"] == "MIT" and (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")


def test_author_matches_the_license_holder(listing):
    meta, _, _ = listing
    assert f"Copyright (c) 2026 {meta['author']}" in (ROOT / "LICENSE").read_text(encoding="utf-8")


def test_it_does_not_claim_the_hexa_mcp(listing):
    meta, _, _ = listing
    assert meta["works_with_tenable_hexa_mcp"] is False and "Tenable Hexa AI MCP" not in meta["integrations"]


def test_the_agreement_date_is_the_submitters_recorded_acceptance(listing):
    """Set only after the submitter said they accept (2026-11-03T22:24:56Z); never a placeholder or a guess."""
    meta, _, _ = listing
    stamp = str(meta["contribution_agreement_date"])
    assert stamp != PLACEHOLDER
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp)


def test_body_has_the_required_sections_and_discloses_outbound_calls(listing):
    _, _, body = listing
    assert "## What it does" in body and "## How it works" in body
    assert "https://cloud.tenable.com" in body and "POST /vulns/export" in body and "User-Agent" in body


def test_no_template_leftovers(listing):
    meta, _, _ = listing
    text = json.dumps(meta)
    assert "your-github-username" not in text and "Your MCP Server Name" not in text
    assert meta["date_added"] != "2026-01-01"


def test_listing_describes_the_coverage_order_without_overclaiming(listing):
    _, tools, _ = listing
    fix_queue = next(t for t in tools if t["name"] == "fix_queue")["description"].lower()
    assert "coverage" in fix_queue and "heuristic" in fix_queue
