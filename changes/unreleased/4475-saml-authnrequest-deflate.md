---
section: Fixed
issues: [#4475]
---
- **SAML login now DEFLATE-encodes the AuthnRequest on the HTTP-Redirect binding** (#4475). The `SAMLRequest` parameter carried base64 of the bare XML, which SAML 2.0 Bindings §3.4.4.1 does not allow; IdPs that enforce the binding, such as Microsoft Entra ID (`AADSTS750055`) and Shibboleth/CAS, rejected every SP-initiated login. The request is now raw-DEFLATE compressed before base64 encoding.
