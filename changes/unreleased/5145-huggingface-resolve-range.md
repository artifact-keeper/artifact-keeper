---
section: Fixed
issues: [#5145]
---
- **Hugging Face `resolve` downloads honour HTTP `Range`, so an interrupted `hf download` can resume** (#5145). The route ignored the header and answered `200` with the whole file, which `huggingface_hub` appended to its partial copy before failing its size check. It now answers `206` with `Content-Range`, or `416` for a range past the end of the file, and advertises `Accept-Ranges: bytes`, on the hosted, Remote (cached or not) and Virtual paths. Hosted files are also streamed from storage instead of being read into memory.
