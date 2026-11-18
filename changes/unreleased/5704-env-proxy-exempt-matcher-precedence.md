---
section: Security
issues: [#5704]
---
- **The SSRF resolver exempts only the egress-proxy host the environment actually uses** (#5704). An upper-case proxy variable shadows its lower-case twin even when empty, and a CGI process (`REQUEST_METHOD` set) uses no environment proxy at all; a host named only by a variable that loses that precedence no longer stays outside the connect-time address filter, so a direct connection to that name cannot bypass the SSRF policy.
