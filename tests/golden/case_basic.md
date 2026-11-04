# Case: Plugin 1

Case `plugin:1` · plugin · rank #1 (score 70.5/100) · data as of 2026-11-02

## Summary

- 2 hosts, 2 findings across 1 vulnerability.
- Worst severity: critical.
- 2 findings with a public exploit available.
- The oldest finding was first seen 161 days before the data snapshot (2026-11-02).

## Score breakdown

| Component | Points | Max | Why |
| --- | ---: | ---: | --- |
| severity | 30.0 | 30 | worst active severity: critical |
| exploit | 15.0 | 25 | public exploit available |
| breadth | 15.0 | 15 | 2 of 2 hosts affected |
| volume | 1.0 | 10 | 1 distinct vulnerability, 2 findings |
| age | 4.5 | 5 | oldest active finding first seen 161 days ago |
| unsupported | 0.0 | 5 | 0 findings on vendor-unsupported software |
| recurrence | 0.0 | 5 | 0 findings reopened after a fix |
| patch | 5.0 | 5 | 2 findings with a vendor patch available |

## Fix packages that address this case

| Package | Findings | Share of this case addressed |
| --- | ---: | ---: |
| v:p (patch) (fix:v-p:patch) | 2 | 100.0% |

## Top vulnerabilities

| Vulnerability | CVEs | Severity | Hosts | KEV | VPR | EPSS % | Tenable fix text |
| --- | --- | --- | ---: | --- | --- | --- | --- |
| Plugin 1 | CVE-2023-1 | critical | 2 |  |  |  | Upgrade to widget 2.0 or later. |

## Affected hosts

| Host | IP | OS | Findings | Worst severity | First seen |
| --- | --- | --- | ---: | --- | --- |
| HOST1 | 172.26.0.62 | Ubuntu Linux 14.04 | 1 | critical | 2026-05-24 |
| HOST1 | 172.26.0.62 | Ubuntu Linux 14.04 | 1 | critical | 2026-05-24 |

## Timeline

| Date | Event | Findings | Hosts |
| --- | --- | ---: | ---: |
| 2026-05-24 | First seen | 2 | 2 |

## Limitations

- Hostnames, IP addresses and similar identifiers in this tenant are masked and are treated as opaque identifiers.
- Scores and counts are computed from Tenable export records, and every finding ID is listed. This is evidence for prioritization and is not a verdict on any person or team.
- Timeline dates come from Tenable's first-found and last-found dates and, where present, its fixed and resurfaced dates.
- Fix actions are Tenable's own solution text; Tenable's data does not state that one update replaces another.

## Source records

2 Tenable finding IDs support this case; they are listed in the JSON export (`evidence_ids`).

## Disposition

Not yet recorded. The analyst records a disposition separately; nothing in this file is a verdict.
