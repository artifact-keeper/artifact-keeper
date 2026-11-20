---
section: Fixed
issues: [#6063]
---
- **Creating or updating a repository with `versioning_enabled: true` on a format that does not version uploads now says so** (#6063). Only Generic and Mlmodel uploads honour the flag, but the API accepted and echoed it for every format, so a REST or Terraform client had no sign that a re-upload would still be refused with 409. The create and update API responses now carry `Warning: 299 - "versioning_enabled has no effect for format <format>"` and the server logs one line; config-as-code import calls these handlers in-process and is unaffected (no header, no log line). The request still succeeds and the value is still stored and read back unchanged, so existing clients and IaC plans see no difference; refusing the flag on those formats is planned for 1.13.
