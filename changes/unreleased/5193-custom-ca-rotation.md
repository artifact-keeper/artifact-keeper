---
section: Fixed
issues: [#5193]
---
- **Custom CA rotation refreshes retained outbound HTTP clients and connection pools without a backend restart** (#5193). A background poller validates and activates complete bundle revisions, preserves client-specific routing/security settings, and reports revision digests and reload failures. Invalid updates retain the previous trust set; requests already in progress may finish on their original pool.
