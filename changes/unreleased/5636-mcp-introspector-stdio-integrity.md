---
section: Security
issues: [#5636]
---
- **MCP introspection over stdio applies the response-integrity checks of #5450** (#5636). The stdio transport the sandbox guests speak skipped every line whose JSON-RPC `id` was not the pending request's, so a guest answering with a wrong id held the worker for the full 120-second message timeout (and was then retried), and a guest sending each response twice was recorded `ok`. Every response, response batch included, is now handed to the client's correlation check: a wrong id, a duplicate response or a batch ends the probe `refused` at once with `details.protocolViolation` (`response_id_mismatch`, `duplicate_response`, `unexpected_batch`), as on streamable HTTP and SSE.
