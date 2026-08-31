# The DFIR Report scenario corpus status

The canonical catalog is [REPORT_CATALOG.json](REPORT_CATALOG.json). It records all 97 public entries exposed by the 17-page report index on August 31, 2026, at six entries per page (the final page contains one). One entry—WordPress post 310, `default-post`—is a published lorem-ipsum template rather than a DFIR report, leaving 96 actual reports in scope.

## Current coverage

| State | Count |
|---|---:|
| Public index entries in catalog | 97 |
| Verified DFIR reports in scope | 96 |
| Excluded non-report placeholders | 1 |
| Dedicated scenario folders | 96 |
| Fully validated against current lab-safety rules | 96 |
| Existing scenarios requiring safety remediation | 0 |
| Reports without a dedicated scenario | 0 |

`001-APT29` is an external Carbon Black APT29 exercise rather than a scenario sourced from this report catalog, so it is not counted as report coverage.

The current lab-safety baseline requires a lab confirmation gate, domain-controller refusal, no live malware, no real IOC/C2 connections, no credential or LSASS access, no remote propagation, no GPO/SYSVOL changes, no security-control impairment, no log clearing, no shadow-copy deletion, no user-data encryption, a runtime artifact manifest, artifacts left in place for investigation, and separate deterministic cleanup.

All 96 in-scope reports now have a dedicated scenario validated against this baseline.
