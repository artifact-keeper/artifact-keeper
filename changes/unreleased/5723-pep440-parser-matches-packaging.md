---
section: Fixed
issues: [#5723]
---
- **PyPI versions are parsed exactly as pypa `packaging` parses them** (#5723). The hand-written PEP 440 parser behind version equality, ordering and pre-release detection disagreed with `packaging` in three ways. A number too large for 64 bits was read as zero, so a version such as `99999999999999999999` was treated as the same version as `0`. Some valid spellings were not recognised and fell back to exact string matching: a pre-release followed by the implicit post-release form (`1.0a2-1`, which is `1.0a2.post1`) and `post` directly followed by `dev` (`1.0b2.postdev1`). And nine strings that are not versions were accepted and given a meaning, for example `1..0` was read as `1.post0`. The parser now follows `packaging`'s own grammar and is checked against its answers for 2,368 version strings on every build. A number too large for 64 bits is now unparseable, never zero.
