---
section: Fixed
issues: [#6043]
---
- **A proxy-cache quarantine release that answers 200 is no longer followed by a 409** (#6043). When an admin released a held proxied path while its background fetch was still running, the next download could still be refused with `409 "Artifact is quarantined and pending security review"`, intermittently. The fetch's commit wrote the cached entry with its hold first and only dropped the hold once it saw the release, so a download in between read the hold. A download that came in before the commit fetched the package again and put a new hold on it. Now the commit checks for a release before it writes the entry and is serialized with the release on the same server. A download that arrives during the fetch also honours a release already made, so every download after the release is served.
