---
section: Fixed
issues: [#6285]
---
- **Composer `search.json` on a Virtual finds its members' packages, and a Remote answers its upstream's search** (#6285). A Virtual searched only its own artifact rows, which are always empty, so it answered `{"results":[],"total":0}` for packages it installs. It now searches the Local and Staging members the caller may read, one hit per package name from the highest-priority member, and forwards the search to its Remote members' upstreams (Packagist serves `search.json`) under the member metadata deadline, at most 8 Remotes. A Remote queried directly forwards the search the same way. Every hit's `url` points at the repository that was asked. An upstream without a search adds nothing; a Virtual that found nothing while a member was unavailable answers 503 instead of an empty result. `per_page` below 1 is now treated as 1.
