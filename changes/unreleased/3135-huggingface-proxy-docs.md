---
section: Added
issues: [#3135]
---
- **New guide for using a Hugging Face repository as a proxy of huggingface.co: `docs/huggingface.md`** (#3135). It covers creating a Remote repository with upstream `https://huggingface.co` (no routing rules needed), pointing `huggingface_hub` at it with `HF_ENDPOINT=https://<host>/huggingface/<repo_key>`, and using an Artifact Keeper API token as `HF_TOKEN`. It also explains how to give the Remote its own Hub token for gated models, the upload route for Local repositories, and what is not supported (datasets and Spaces, Hub search, the commit API, model info through Virtual repositories).
