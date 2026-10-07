---
section: Security
issues: [#4555]
---
- **A virtual conda channel no longer lets a remote member shadow a package name a hosted member owns** (#4555). The virtual merge took records from remote members first and kept the first writer per filename, so an upstream that published `acme-core 99.0` sat next to the internal `acme-core 1.0` in the merged `repodata.json` and won the solve: the textbook dependency-confusion attack, and the gap the name-shadowing guard already closes for npm, PyPI, Cargo, RubyGems and Hex. Once any local or staging member of the virtual has published a name, remote members now contribute no records under that name in any subdir, `channeldata.json` drops their entry for it, and a download of such a file through the virtual is not proxied upstream. Ownership is read from every member regardless of the caller's access, and a database error fails the request instead of merging unguarded.
