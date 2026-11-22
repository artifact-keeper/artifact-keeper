---
section: Security
issues: [#6359]
---
- **The SSRF guard exempts only the egress proxies the environment matcher actually routes through** (#6359). The connect-time SSRF resolver lets the configured proxy's own (often private) address through. It took that host from `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` separately, so an `ALL_PROXY` host was exempt even when `HTTP_PROXY` and `HTTPS_PROXY` were both set and it was never used, and so was the host of a value the matcher drops (an `ftp://` scheme, no host). A direct connection to that name, such as a `NO_PROXY` destination named in an upstream index, then skipped the private-address check. The exempt set is now read from the matcher's own choice of proxy for `http://` and `https://` destinations. No configuration change: a deployment whose `ALL_PROXY` is the proxy in use keeps it exempt.
