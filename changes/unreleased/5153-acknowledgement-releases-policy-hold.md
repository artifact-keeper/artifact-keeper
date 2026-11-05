---
section: Fixed
issues: [#5153]
---
- **Acknowledging the last open finding releases a scan-policy hold** (#5153). The scanner now records `quarantine_source = scan_policy` on the hold it writes, and an acknowledgement that clears the policy releases that hold and audits the release, instead of the download answering 409 until an administrator released it by hand. An administrator's hold, an upload-period hold, a rejection, and a hold written before this version (which records no source) are not released.
