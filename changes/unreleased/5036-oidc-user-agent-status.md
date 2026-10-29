---
section: Fixed
issues: [#5036]
---
- **SSO and CI OIDC requests send a User-Agent and report identity-provider HTTP errors** (#5036). Requests to identity providers (OIDC discovery, token, JWKS and userinfo, for SSO and CI OIDC) now carry `User-Agent: artifact-keeper/<version>`, so a web application firewall that refuses requests without one (such as the AWS WAF core rule set) no longer blocks them. A non-2xx answer from discovery or JWKS is now reported as `... returned HTTP <status>` instead of an invalid JSON error, and so is a token endpoint answer that is non-2xx and not JSON (OAuth JSON error responses are handled as before). The start of the response body is written to the server log only.
