-- MCP Registry repositories (server.json catalog, registry API v0.1, #5253).
-- Hosted (Local/Staging) in this release; Remote/Virtual follow.
ALTER TYPE repository_format ADD VALUE IF NOT EXISTS 'mcp';
