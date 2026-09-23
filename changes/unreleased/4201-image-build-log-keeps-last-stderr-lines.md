---
section: Fixed
issues: [#4201]
---
- **An image build's log no longer loses the builder's last stderr lines** (#4201). The image builder closed its output channel as soon as `buildctl` exited, so a reader task that had not yet forwarded what was still in the stderr pipe had its sends rejected and those lines were dropped. That is where BuildKit reports progress and the reason a build failed, and it made the image-builds integration test fail about one run in four. The builder now keeps reading until both stdout and stderr reach EOF (bounded by the build timeout) before it writes the last log chunk and marks the build finished.
