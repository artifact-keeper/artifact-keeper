---
section: Fixed
issues: [#5644]
---
- **The Incus rootfs scanner now applies only to Incus and LXC repositories** (#5644). Applicability was decided by path shape alone, so a PyPI sdist stored as `pyyaml/5.3.1/PyYAML-5.3.1.tar.gz` looked like an Incus image and was extracted and rootfs-scanned, wasting scanner time and producing a misleading scan row. The scanner now requires the artifact's repository format to be `incus` or `lxc` before its path is classified.
