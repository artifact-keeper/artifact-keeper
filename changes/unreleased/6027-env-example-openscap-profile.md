---
section: Changed
issues: [#6027]
---
- **`.env.example` shows the current default OpenSCAP profile, `xccdf_org.ssgproject.content_profile_cis_server_l1`** (#6027). It still showed `content_profile_standard`, the pre-#6005 value, so a setup copied from it would not get the new default.
