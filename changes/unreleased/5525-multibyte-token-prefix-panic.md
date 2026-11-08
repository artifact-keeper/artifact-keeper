---
section: Fixed
issues: [#5525]
---
- **A Basic credential with a multibyte character across byte 8 of the password no longer drops the connection** (#5525). The API-token lookup sliced the first 8 bytes of the credential as a `token_prefix` after checking only its byte length, so a Basic credential of `x:1234567é` on a format route such as `GET /pypi/x/simple/` panicked with "byte index 8 is not a char boundary" and the client saw a closed connection instead of a response; a user whose password had such a character could never use Basic auth on the format routes. `AuthService::validate_api_token`, `TokenService::validate_token` and `TokenService::has_scope` now treat a credential whose first 8 bytes are not a character boundary like any other malformed token: a 401, still burning the dummy bcrypt so the shape of the credential is not leaked by timing.
