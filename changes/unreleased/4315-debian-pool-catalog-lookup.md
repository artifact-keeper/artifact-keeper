---
section: Fixed
issues: [#4315]
---
- **Remote Debian pool downloads no longer list the whole proxy cache on every request** (#4315). The Tier B checksum lookup found cached `Packages` indexes by listing storage, so every `.deb` got slower as the cache grew; it now reads the index paths from the proxy cache catalog.
