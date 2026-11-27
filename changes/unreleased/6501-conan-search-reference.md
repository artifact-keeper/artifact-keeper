---
section: Fixed
issues: [#6501]
---
- **Conan search on a hosted repository matches the reference, not only the name** (#6501). `conan list "t17lib/*"` and `conan list t17lib/0.1.0` sent a pattern that was compared with the bare recipe name, so they found nothing while `conan list "t17lib*"` worked. The pattern now matches the name, `name/version` or the full `name/version@user/channel`, as it does on a remote repository and on conan_server. Virtual repositories search their hosted members the same way
