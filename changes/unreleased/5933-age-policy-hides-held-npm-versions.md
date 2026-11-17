---
section: Fixed
issues: [#5933]
---
- **An npm packument leaves out the versions the Package Age Policy holds** (#5933). On a Remote with the policy on, and in a Virtual over one, a version whose `time` entry is inside the window drops out of `versions` and `time`, and a dist-tag naming it is moved or dropped the way the Age Gate does (`latest` goes back to the newest version left), so `npm install pkg@^1.21.0` picks 1.21.0 instead of stopping at the young 1.21.1's 409. The version comes back when its window ends. A version without a `time` entry stays listed and its tarball keeps its own hold. Such packuments skip the computed-packument cache.
