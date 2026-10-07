---
section: Changed
issues: [#3658]
---
- **GitHub API release-by-tag lookups are cached for seven days on github, mise and aqua remotes** (#3658). mise's aqua backend calls `api.github.com/repos/<owner>/<repo>/releases/tags/<tag>` even for exactly pinned versions. Through a `github`-format API mirror those responses took the five-minute default, so a cold CI runner could only resolve pinned tools for about the first hour of a GitHub outage. That exact path shape now gets the same seven-day finite lifetime as release assets and is still revalidated when it expires. The paginated release list, `releases/latest` and every other API path keep the short default. A repository TTL override still takes precedence, as it does for every mutable path. Ordinary `generic` remotes are unchanged.
