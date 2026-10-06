---
section: Security
issues: [#4346, #3323, #3813, #4360, #4381]
---
- **RPM virtual repositories' repodata now lists only the members the caller may read** (#4346, #3323). `repomd.xml`, `primary.xml.gz`, `filelists.xml.gz` and `other.xml.gz` of a virtual RPM repository were built from every member, so any caller who could read the virtual, including an anonymous caller of a public virtual, could read the names, versions, SHA-256 digests and file lists of packages in private and internal members (package bytes were already protected). The member walk is now caller-authorized like every other format's; the render cache is keyed by the virtual, the metadata root and the caller's authorized member set, so callers with different visibility never share a document, each set renders byte-identically and `repomd.xml.asc` signs exactly the document that caller is served. Each virtual root keeps at most four member-set renders.

  Attaching an `internal` repository to a virtual now needs a read grant on it (or instance admin), as for a `private` one (#3813): a delegated admin of a virtual could otherwise re-export any internal repository through it, anonymously if the virtual was public. The refusal is a 403.

  A router built without the auth middleware now reads the missing caller as anonymous (a virtual then lists only its public members) instead of answering 500 (#4360, #4381). Production always mounts the middleware, so only an embedding or test router was affected.
