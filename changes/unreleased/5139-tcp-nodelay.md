---
section: Fixed
issues: [#5139]
---
- **Small downloads no longer take about 44 ms on a keep-alive connection** (#5139). Accepted connections left Nagle's algorithm on, so when a response head and a body smaller than one TCP segment went out as two writes, the body waited for the client's delayed ACK of the head. This capped a connection at about 22 requests per second for small files such as Maven `.sha1` and `.md5` sidecars, with or without a reverse proxy. The HTTP accept loop now sets `TCP_NODELAY` on every accepted connection, on the API and metrics listeners alike.
