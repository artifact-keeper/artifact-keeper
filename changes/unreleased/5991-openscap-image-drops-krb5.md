---
section: Security
issues: [#5991]
---
- **The OpenSCAP image no longer ships krb5-libs, libssh, openldap or cyrus-sasl** ([#5991]). These four packages were present only because the distribution's libcurl links them. Kerberos alone carried 14 HIGH CVEs that UBI 9 has no fixed package for. The image now uses its own libcurl 8.23.0, built without GSSAPI, SSH or LDAP support, and the four packages are gone. The CentOS Stream repository now supplies only scap-security-guide, so openscap and every library come from UBI 9 (oscap reports 1.3.14 instead of 1.3.16). Scan results are unchanged: the wrapper's `/scan` returns the same findings, and a full RHEL 9 STIG evaluation gives the same per-rule results. oscap can still fetch remote content over HTTPS, but no longer over Kerberos/Negotiate, SCP/SFTP or LDAP; the scanner's built-in wrapper never fetches anything.
