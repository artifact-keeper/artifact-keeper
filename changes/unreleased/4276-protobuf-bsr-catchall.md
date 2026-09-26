---
section: Added
issues: [#4276]
---
- **Remote Protobuf repositories reverse-proxy unknown BSR Connect methods** (#4276). `buf` talks binary Connect at service/method paths the hosted REST layout does not name; `POST /protobuf/{repo}/*` forwards those upstream without copying the caller's Artifact Keeper token.
