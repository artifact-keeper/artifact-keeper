---
section: Security
issues: [#5526]
---
- **ZIP ingests are refused from their declared entry count before the central directory is parsed** (#5526). MCPB, agent plugins, VS Code extensions, wheels, Swift packages and the other ZIP readers that share `MAX_INGEST_ARCHIVE_ENTRIES` previously learned that an archive was over the ceiling only after `ZipArchive::new` had parsed every central-directory record. An upload near the body cap carrying millions of tiny entries therefore paid for that temporary parse and its allocations before the 400. The end-of-central-directory record (or ZIP64 EOCD) is now read from the file tail first, so an over-ceiling count is refused immediately; the parsed `archive.len()` check remains the authoritative second line for the central directory that was actually read.
