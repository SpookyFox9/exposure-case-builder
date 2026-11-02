# Fix: v:p (patch)

Package `fix:v-p:patch` · priority #1 (score 81.1/100) · data as of 2026-11-02

**Why it ranks here:** worst active severity: critical (30 of 30 points for severity); on the CISA KEV list (25 of 25 points for exploit); 2 of 2 hosts affected (15 of 15 points for breadth).

## What to do

Fix text is Tenable-provided. Tenable's data does not state that one update supersedes another, so each action is listed separately, and the totals are contained in the package, not cleared by a single action.

| Action (Tenable solution) | Vulnerabilities | Hosts | Worst severity | Fleet criticals this action alone clears |
| --- | ---: | ---: | --- | ---: |
| Upgrade to widget 2.0 or later. | 1 | 2 | critical | 100.0% |
| Upgrade to widget 2.1. | 1 | 1 | medium | – |

## Impact (contained in this package)

- 2 distinct actions, 2 vulnerabilities, 3 findings on 2 hosts
- Findings by severity: critical 2, medium 1
- Exploitation: 2 with a public exploit, 0 exploited by malware, 1 on the CISA KEV list
- Contains 100.0% of the fleet's critical findings

## Affected hosts

| Host | IP | OS | Findings | Worst severity | First seen |
| --- | --- | --- | ---: | --- | --- |
| HOST1 | 172.26.0.62 | Ubuntu Linux 14.04 | 2 | critical | 2026-05-24 |
| HOST1 | 172.26.0.62 | Ubuntu Linux 14.04 | 1 | critical | 2026-05-24 |

## References

CVEs:
- CVE-2023-1

Advisories (shown as text, not links):
- `https://example.test/adv1`

## Cases this relieves

- `plugin:1` Plugin 1: 2 findings (66.6% of this package)
- `plugin:2` Plugin 2: 1 finding (33.3% of this package)

## Source records

3 Tenable finding IDs support this package; they are listed in the JSON export (`evidence_ids`).

Hostnames, IP addresses and similar identifiers in this dataset are masked.
