---
section: Fixed
issues: [#5810]
---
- **Virtual artifact downloads no longer wait the full upstream read timeout behind an unresponsive member** ([#5810]). A Remote member that has not started answering within `AK_VIRTUAL_MEMBER_DOWNLOAD_DEADLINE_SECS` (default `20`, capped at `PROXY_UPSTREAM_READ_TIMEOUT_SECS`) is treated as unavailable for that request, and the next member in priority order serves. Before, a hung higher-priority member held every download for 60 s. Members that answer in time keep their priority. Each miss is logged and counted in `ak_virtual_member_download_timeouts_total{member}`. Set the variable to `0` to keep the old wait. See `docs/virtual-downloads.md`.
