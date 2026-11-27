---
section: Changed
issues: [#5977]
---
- **RubyGems Virtual specs-index member fetches now reserve from the RubyGems metadata share with a bounded wait** (#5977). Sequential member fetches release each reservation before the next, so a merge over many Remote members no longer starves other formats' metadata or sheds against itself.
