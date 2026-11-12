---
section: Fixed
issues: [#5862]
---
- **`S3_PREFIX` set to the empty string is no longer read as a prefix** (#5862). `S3_PREFIX=""` came through as `Some("")`, so every key started with a slash. Reads and writes normalize that away through `ObjectPath`, but the `x-amz-copy-source` header is built as a raw string, so a server-side copy asked for `bucket//ab/cd/ef` and got `NoSuchKey`. An empty or slash-only prefix is now treated as unset, and the copy-source header drops empty segments
