---
section: Security
issues: [#5536]
---
- **An MCP package pinned through a Virtual is held when a reader of the Virtual cannot read the pinned member** ([#5536]). A Virtual's download route skips the members a caller cannot read, so a reader of the Virtual without access to the member a package was pinned from was served a lower member's copy of the same coordinate (another hosted member's bytes, or a NuGet Remote's upstream), while the server version kept being served as approved. When the pinned member is not readable by every principal that can read the Virtual, any later member that holds or proxies the coordinate now counts as shadowing it: the publish is refused with `422 mcp_package_shadowed`, and an already pinned version is held with `gate: shadowed` until every reader of the Virtual can read the pinned member. PyPI pins were already covered.
