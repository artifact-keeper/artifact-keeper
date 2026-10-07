---
section: Fixed
issues: [#3939]
---
- **`artifact.uploaded` webhooks now fire for CRAN, Hex, Ansible, Puppet and RubyGems publishes, promotions, approved promotions, Git LFS uploads and chunked uploads** (#3939). These paths wrote their `artifacts` row directly and never produced the event, so a webhook or email subscription on `artifact.uploaded` heard nothing for them. Each now emits exactly one event, carrying the new artifact's id, its repository and the uploader, the same shape the generic upload API sends; a promotion's event belongs to the target repository. CRAN, Hex, Ansible, Puppet and RubyGems publishes also now appear on the Packages page, like the other native formats. A test now fails the build when a handler writes `artifacts` without producing the event.
