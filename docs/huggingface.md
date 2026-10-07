# Hugging Face repositories

Artifact Keeper speaks enough of the Hugging Face Hub HTTP API for
`huggingface_hub` (the Python library, the `hf` / `huggingface-cli` CLI, and
the libraries built on it such as `transformers` and `sentence-transformers`)
to download models through it. Three repository types are supported:

- **Remote** (proxy / pull-through cache) of `https://huggingface.co`, the
  usual setup: clients download through Artifact Keeper, which fetches from
  the Hub on a miss and serves later requests from its cache.
- **Local** (hosted): models you upload yourself.
- **Virtual**: a group of Local and Remote members (see the limitations
  below).

## Setting up a proxy of huggingface.co

Create a repository with `format: huggingface`, `repo_type: remote` and the
Hub as its upstream. Use the bare origin, with no path: the handler appends
the Hub's own paths (`api/models/...`, `{model}/resolve/...`) itself.

```bash
curl -X POST https://registry.example.com/api/v1/repositories \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "key": "hf-remote",
        "name": "Hugging Face proxy",
        "format": "huggingface",
        "repo_type": "remote",
        "upstream_url": "https://huggingface.co"
      }'
```

The same can be done in the web UI (New repository, format Hugging Face, type
Remote, URL `https://huggingface.co`).

**No routing rules are needed.** Routing rules rewrite request paths for
upstreams whose URL layout differs from what the client asks for (a GitHub
Releases mirror, for example). The Hub's layout is the one `huggingface_hub`
already uses, so leave them empty.

### Gated and private models on the Hub

The token a client sends to Artifact Keeper is never forwarded to
huggingface.co. To proxy gated models (Llama, Gemma, ...) or private ones,
give the Remote repository its own Hub credential, a Hugging Face access
token with read access to those models:

```bash
curl -X PUT https://registry.example.com/api/v1/repositories/hf-remote/upstream-auth \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"auth_type": "bearer", "password": "hf_xxxxxxxxxxxxxxxxxxxx"}'
```

(`upstream_auth_type: "bearer"` with `upstream_password` does the same at
creation time.) Everyone who can read `hf-remote` in Artifact Keeper can then
download what that Hub token can see, so restrict the repository accordingly.

## Pointing `huggingface_hub` at it

`huggingface_hub` takes its server from `HF_ENDPOINT` and its credential from
`HF_TOKEN`. Point the endpoint at the repository, **including the
`/huggingface/<repo_key>` prefix and with no trailing slash**:

```bash
export HF_ENDPOINT=https://registry.example.com/huggingface/hf-remote
export HF_TOKEN=<an Artifact Keeper API token>
```

`HF_TOKEN` is an **Artifact Keeper** API token, not a Hugging Face one:
`huggingface_hub` sends it as `Authorization: Bearer <token>`, which Artifact
Keeper accepts for API tokens. A token with the `read:artifacts` scope is
enough to download. Create one in the web UI (profile, API tokens) or with:

```bash
curl -X POST https://registry.example.com/api/v1/auth/tokens \
  -H "Authorization: Bearer $AK_SESSION_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "hf-download", "scopes": ["read:artifacts"]}'
```

If the repository is public, anonymous reads are allowed and `HF_TOKEN` can be
left unset. Do not leave a real Hugging Face token in `HF_TOKEN` (or in
`~/.cache/huggingface/token` from an earlier `hf auth login`) while
`HF_ENDPOINT` points at Artifact Keeper: it is sent to Artifact Keeper, which
does not recognise it and refuses the request with 401.

Then use the library as usual:

```bash
hf download sentence-transformers/all-MiniLM-L6-v2
```

```python
from huggingface_hub import hf_hub_download, snapshot_download

path = hf_hub_download("gpt2", "config.json")
local_dir = snapshot_download("sentence-transformers/all-MiniLM-L6-v2", revision="main")
```

`transformers` and `sentence-transformers` read the same variables, so
`AutoModel.from_pretrained("bert-base-uncased")` downloads through the proxy
too. Files land in the normal `~/.cache/huggingface/hub` layout.

## Endpoints

All routes live under `/huggingface/{repo_key}`. Model IDs may be bare
(`gpt2`) or namespaced (`org/name`).

| Method | Path | Purpose |
|--------|------|---------|
| `GET`, `HEAD` | `/{model_id}/resolve/{revision}/{filename}` | Download a file (`hf_hub_download`). Remote: pull-through from the Hub, then served from cache. |
| `GET` | `/api/models/{model_id}` | Model info (`model_info`, with `siblings`). Remote: proxied from the Hub on a miss. |
| `GET` | `/api/models/{model_id}/revision/{revision}` | Model info at a revision; what `snapshot_download` and `hf download` call first. |
| `GET` | `/api/models/{model_id}/tree/{revision}` | File listing. Remote: proxied from the Hub when nothing is held locally. |
| `GET` | `/api/models` | Models held in the repository (see limitations). |
| `POST` | `/api/models/{model_id}/upload/{revision}` | Upload one file to a Local repository (Artifact Keeper's own route, see below). |

Revisions may be branch names, tags, 40-character commit shas or refs such as
`refs/pr/1`. Responses carry the `X-Repo-Commit` and `ETag` headers
`huggingface_hub` needs to place files in its cache. For a Local repository,
which has no git history, the commit is a stable value derived from the model
ID and revision.

## Publishing to a Local repository

`huggingface_hub`'s `upload_file` / `upload_folder` / `create_commit` use the
Hub's commit API, which Artifact Keeper does not implement. Upload files one
at a time with Artifact Keeper's own route instead, naming the file in
`X-Filename` (a path such as `onnx/model.onnx` is allowed):

```bash
curl -X POST \
  -H "Authorization: Bearer $AK_TOKEN" \
  -H "X-Filename: config.json" \
  --data-binary @config.json \
  https://registry.example.com/huggingface/hf-local/api/models/my-org/my-model/upload/main
```

The token needs `write:artifacts` and write permission on the repository.
Uploads to Remote (405) and Virtual (400) repositories are refused.

## Limitations

The supported surface above is derived from the handler
(`backend/src/api/handlers/huggingface.rs`) and its routes, not from an
exhaustive run of every `huggingface_hub` call against a live instance.
Anything not listed under Endpoints answers 404. In particular:

- **Models only.** Datasets and Spaces (`repo_type="dataset"` /
  `"space"`, the `api/datasets/...` and `api/spaces/...` routes) are not
  proxied, so `load_dataset(...)` and `snapshot_download(..., repo_type="dataset")`
  do not work through `HF_ENDPOINT`.
- **No Hub search or account calls.** `list_models()` returns the models the
  repository holds, ignoring search and filter parameters; a Remote
  repository keeps no model rows for proxied files, so it returns `[]` rather
  than searching the Hub. `whoami`, `paths-info`, repository creation and the
  commit/upload API are not implemented.
- **Tree listings for Remote repositories are a single page.** Very large
  repositories are listed short by `list_repo_tree` / `list_repo_files`.
  Downloads are unaffected: `snapshot_download` takes its file list from the
  model-info `siblings`.
- **Xet storage is hidden from clients.** Xet fields are stripped from
  proxied metadata so clients download through the ordinary `/resolve/` path
  (and through the cache) rather than fetching Xet chunks directly from the
  Hub's CAS servers. If a client still tries Xet (an `xet-read-token` 404 in
  its log), set `HF_HUB_DISABLE_XET=1`.
- **Virtual repositories route downloads only.** `/resolve/` requests are
  served from the first member that has the file, but model info and tree
  listings are answered only by Local and Remote repositories, so
  `snapshot_download` and `hf download` (which call model info first) fail
  against a Virtual repository. Point those at the Remote or Local
  repository directly; `hf_hub_download` of a named file works through a
  Virtual one.
