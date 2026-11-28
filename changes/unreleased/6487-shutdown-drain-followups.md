---
section: Fixed
issues: [#6487]
---
- **Shutdown now gives running scheduler jobs a bounded window to stop before their leases are left to expire** (#6487). The job-wait deadline used to be the drain deadline, which had already passed when the wait started; it is now set when the stop is requested and includes five seconds after the drain. The drain documentation also spells out which Helm values the chart can use to derive `terminationGracePeriodSeconds`.
