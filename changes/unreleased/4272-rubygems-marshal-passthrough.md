---
section: Fixed
issues: [#4272]
---
- **RubyGems remote and virtual indexes no longer come back empty when upstream serves gzip Marshal** (#4272). `gem` compact/Marshal indexes are binary; parsing them as JSON produced a ~24-byte empty index. Specs indexes are now passed through as-is, and PyPI age-gate publish evidence prefers the PEP 691 simple index over Warehouse JSON.
