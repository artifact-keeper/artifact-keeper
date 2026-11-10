---
section: Fixed
issues: [#5648, #5197, #5202]
---
- **A protobuf `Download` naming a module with no commit or label no longer returns a 500 for a module with one commit** (#5648, backport of #5197, #5202). The latest-commit query could pick the module's `_labels` index, which is written right after the first commit under the same name, and the handler then failed reading that JSON document as a gzipped commit bundle. The query now skips the index, so the request returns the module's latest commit.
