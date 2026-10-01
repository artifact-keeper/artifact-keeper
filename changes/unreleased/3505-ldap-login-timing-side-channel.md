---
section: Security
issues: [#3505]
---
- **LDAP login no longer reveals through its response time whether a username exists in the directory** (#3505). #3371 made an absent username and a wrong password return the same response body, but on the search-then-bind path an absent username still returned right after the directory search, while an existing one paid a second connection and a bind. With a remote directory, STARTTLS, or an Active Directory that delays rejected binds, that extra round-trip could rebuild the enumeration oracle. A search miss now binds against a random DN that cannot exist, using the submitted password, so both cases perform the same directory operations in the same order and fail with the same error. The miss still always fails, whatever the directory answers to the decoy bind. A sweep of absent usernames now costs the directory one bind per attempt, the same as a sweep of existing usernames or wrong passwords already did.
