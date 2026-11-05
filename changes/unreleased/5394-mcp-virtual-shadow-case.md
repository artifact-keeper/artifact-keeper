---
section: Security
issues: [#5394]
---
- **A Virtual MCP registry's hosted member now shadows a Remote member's server of the same name in any letter case** (#5394). The hosted-shadows-remote rule, which keeps an upstream server from taking over an internal name, compared names case-sensitively, so a Remote's `io.Acme/tool` was listed and served through the Virtual beside the hosted `io.acme/tool`. Ownership is now decided case-insensitively, as the deny lists and namespace allowlists already were.
