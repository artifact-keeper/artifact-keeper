---
section: Security
issues: [#5541]
---
- **An MCPB bundle whose entry point has a case-variant twin is refused** (#5541). A bundle holding both `server/index.js` and `SERVER/INDEX.JS` was accepted, although the two unpack to one file on macOS and Windows (case-insensitive by default), so which one a desktop MCP client ran depended on the unpacker. Upload now answers `400 mcp_bundle_invalid` (`duplicate entry <entry point>`) when the manifest's `server.entry_point` matches more than one entry case-insensitively (Unicode upper case, as `manifest.json` already is). Case variants elsewhere in the bundle, such as a Linux-built `node_modules`, are still accepted.
