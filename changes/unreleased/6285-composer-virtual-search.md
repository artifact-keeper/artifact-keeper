---
section: Fixed
issues: [#6285]
---
- **Composer `search.json` on a Virtual finds the packages of its hosted members** (#6285). A Virtual searched only its own artifact rows, which are always empty, so it answered `{"results":[],"total":0}` for packages it installs. It now searches the Local and Staging members the caller may read, with one hit per package name from the highest-priority member, and each hit's `url` points at the Virtual. A direct search also returns one hit per name, `per_page` is clamped to 1–100, and the `next` link percent-encodes `q` and `type`. Remote repositories, and Remote members of a Virtual, still contribute nothing; forwarding the search upstream is left for a later release.
