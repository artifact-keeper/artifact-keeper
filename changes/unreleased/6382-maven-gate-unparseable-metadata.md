---
section: Security
issues: [#6382]
---
- **A gated Maven listing now refuses metadata it cannot filter instead of serving an unfiltered version list** (#6382). A `maven-metadata.xml` that is not UTF-8, does not parse as GA-level Maven metadata, or cannot be rewritten after the gate withheld versions now answers the gate's retryable 503; its checksum sidecar and headers refuse with it, so a lenient resolver cannot select a version whose download the gate blocks.
