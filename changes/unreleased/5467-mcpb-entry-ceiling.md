---
section: Security
issues: [#5467]
---
- **MCPB bundle uploads now enforce the shared ingest archive entry ceiling before reading the manifest** (#5467). A bundle whose ZIP holds more than `MAX_INGEST_ARCHIVE_ENTRIES` entries (default 10,000) is refused with `400 mcp_bundle_invalid` before its manifest is looked up, so no bundle or version is persisted; exactly 10,000 entries is still accepted. Previously the MCPB inspection path opened the archive and looked up `manifest.json` without the entry-count limit every other ingestion metadata reader applies.
