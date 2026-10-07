---
section: Fixed
issues: [#4432]
---
- **The age gate keeps an npm package's own `latest` tag instead of re-pointing it to the newest allowed version** (#4432). Every gated packument had `latest` set to the newest version that passed the gate, prereleases included, so `npm install typescript` resolved to a nightly build and `next` to a canary. A `latest` the gate allows is now kept. When the gate blocks it, `latest` moves to the newest allowed release at or below it, then the newest allowed release, then the newest allowed version of any kind.
