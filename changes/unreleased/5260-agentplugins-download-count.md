---
section: Fixed
issues: [#5260]
---
- **Agent Plugins versions report the downloads they serve on the Packages page** (#5260). Their archive downloads already recorded `download_statistics` rows, but the package endpoints returned the never-incremented catalog counters, so every version showed 0. The catalog count now reads the recorded download history the artifact download stats use; a regression test publishes, downloads and lists an Agent Plugins plugin through the real routes to keep the count wired to that history.
