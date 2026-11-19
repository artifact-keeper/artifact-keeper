---
section: Fixed
issues: [#6160]
---
- **Maven uploads with a directory username and password now work with the shipped compose stack** (#6160). Two gaps kept the opt-in LDAP Basic-auth passthrough from covering package uploads: `docker-compose.yml` listed the backend environment explicitly and never forwarded `LDAP_BASIC_AUTH_PASSTHROUGH`, so setting it in `.env` never reached the container, and requests naming a repository that does not exist yet skipped the passthrough and answered the anonymous 401 before a directory credential could be resolved. The compose file now forwards the switch (still off by default), and the format middleware resolves LDAP Basic credentials on the no-repository path as well, so a valid directory user gets the existence-hiding 404 a valid credential receives for any other unknown repository key. The passthrough is available from 1.12.0 (it is not in 1.11.x) and is enabled with `LDAP_BASIC_AUTH_PASSTHROUGH=true` in `.env`.
