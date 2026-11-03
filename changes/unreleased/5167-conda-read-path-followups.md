---
section: Fixed
issues: [#5167, #4978, #5005]
---
- **A hosted conda subdir no row has ever named answers `repodata.json.bz2` without a regeneration permit, and two renders of one revision no longer step the JLAP tail back** (#5167, #4978, #5005). The `.bz2` of such a subdir was the one encoding that waited for a permit to compress an empty document, so it could answer 503 while real renders held every permit; it is now filled with the other encodings. Two renders of the same revision that decided visibility at different instants took turns appending each other's document to the stored JLAP; a render of the revision already recorded now carries the stored JLAP instead. Until the revision next moves, a client holding the second render's `repodata.json` finds no patch from it and downloads the index.
