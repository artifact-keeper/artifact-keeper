---
section: Fixed
issues: [#5724]
---
- **The derived npm `latest` tag follows SemVer precedence among pre-releases** (#5724). When a package has no recorded `latest` dist-tag and every candidate version is a pre-release, the server picked the most recently listed one among versions with the same `major.minor.patch`, so `1.0.0-alpha` published after `1.0.0-rc.1` became `latest`. It now picks the highest by SemVer precedence, as the npm client would. Packages with a stable release, or with a recorded `latest`, are unaffected.
