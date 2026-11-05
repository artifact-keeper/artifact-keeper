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

**Set the cache TTL when you create the Remote** if its cache is meant to
outlive the upstream, for example on an instance that will be disconnected.
Model info at a branch (`main`) and other mutable paths are revalidated after
the TTL (5 minutes by default), and a raised TTL only applies to an entry
from its next revalidation, so raising it after seeding leaves the entries
already cached on the old lifetime. Paths at a 40-character commit sha
(`<model>/resolve/<sha>/...`, which is how `snapshot_download` fetches its
files, and model info and tree listings at a sha) are immutable cache entries
and are never revalidated, whatever the TTL (#5283):

```bash
curl -X PUT https://registry.example.com/api/v1/repositories/hf-remote/cache-ttl \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"cache_ttl_seconds": 315360000}'
```

See [Proxy cache freshness](proxy-cache-freshness.md) for the TTL,
`on-upstream-not-found` and stale-if-error settings.

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
download what that Hub token can see, so restrict who can read the repository:
make it private and grant read to a group. A user outside that group gets
**404**, not 403, from every route of the repository, so `huggingface_hub`
raises `RepositoryNotFoundError` for them, as the Hub itself does for a
private repository the caller cannot see.

### Restricting which models a Remote can fetch

A Remote's [upstream filter](upstream-filter.md) decides which paths it may
request from the Hub. A Hugging Face Remote requests two shapes of path for
the same model, and **a pattern has to match both**:

| Request | Path sent upstream |
|---------|--------------------|
| Model info (`model_info`, the first call of `snapshot_download` and `hf download`) | `api/models/<org>/<name>`, `api/models/<org>/<name>/revision/<rev>` |
| File listing (`list_repo_tree`, and `snapshot_download` in `huggingface_hub` 2.x) | `api/models/<org>/<name>/tree/<rev>`, followed by its query in one canonical spelling: `recursive=true`, `expand=true` and `cursor=...` in that order, a `false` flag left out (`?recursive=true`, `?recursive=true&cursor=...`) |
| File download (`hf_hub_download`) | `<org>/<name>/resolve/<rev>/<file>` |

A filter written as `^acme/` admits the files but refuses model info, so
`snapshot_download` and `hf download` fail on their first call; one written as
`^api/models/acme/` does the opposite. Make the `api/models/` prefix optional
instead. To allow two organisations:

```bash
curl -X PUT https://registry.example.com/api/v1/repositories/hf-remote/upstream-filter \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"include_patterns": ["^(api/models/)?(sentence-transformers|Qwen)/[^/]+(/|$)"]}'
```

- **Anchor with `^`.** Patterns match anywhere in the path unless anchored, so
  an unanchored `Qwen/` also admits `evil-org/Qwen/...` paths.
- **Do not anchor the end with `$` after the model name.** Tree listings carry a query string (`?recursive=true`), which is part of the subject.
- **Keep the `/` after the organisation.** It stops look-alikes: the pattern
  above refuses `sentence-transformer/...` and `sentence-transformers-x/...`.
- **One model rather than a whole organisation:**
  `^(api/models/)?Qwen/Qwen2\.5-1\.5B-Instruct(/|$)`. Escape the dots.
- **Models without an organisation** (`gpt2`, `bert-base-uncased`) have no
  `<org>/` segment: `^(api/models/)?gpt2(/|$)`.
- **Matching is case-sensitive.** A client that spells the organisation in
  another case (`qwen/...`) is refused. Prefix a pattern with `(?i)` to accept
  any spelling, and always do so in `exclude_patterns`, where a case-sensitive
  pattern would let another spelling through.

A refused path answers 404 without contacting the Hub, so a refused model
looks to the client like one that does not exist. Already-cached files of a
refused model are served only while their cache entry is fresh; see
[already-cached content](upstream-filter.md#already-cached-content). Only the
request to the Remote's `upstream_url` is matched: the Hub's redirect of a
large file to its CDN is followed without being filtered again.

Check an allowed and a refused model (the second answers 404):

```bash
export HF_ENDPOINT=https://registry.example.com/huggingface/hf-remote
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $HF_TOKEN" \
  "$HF_ENDPOINT/api/models/sentence-transformers/all-MiniLM-L6-v2/revision/main"   # 200
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $HF_TOKEN" \
  "$HF_ENDPOINT/api/models/sentence-transformer/all-MiniLM-L6-v2/revision/main"    # 404
```

What a client sees for a gated model:

- **No upstream credential on the Remote.** The Hub refuses the Remote with
  `401` and `X-Error-Code: GatedRepo`, and the client gets the same: `401`,
  `X-Error-Code: GatedRepo`, and an `X-Error-Message` naming the Remote and
  `PUT /api/v1/repositories/{key}/upstream-auth`. `huggingface_hub` raises
  `GatedRepoError` straight away, without retrying. A Hub token that has not
  been granted the model gives `403` with `GatedRepo`, which raises the same
  error. Neither the Hub's message nor the Remote's token is passed on.
- **An upstream credential with access.** The model downloads like any other
  and is cached as usual. A refusal is never cached, so setting the credential
  takes effect on the next request.
- **An Artifact Keeper user who cannot read the Remote** (for example, outside
  the group the repository is restricted to) gets `404`, as for a repository
  that does not exist, whether or not the model is gated. `huggingface_hub`
  raises `RepositoryNotFoundError`. Artifact Keeper does not reveal that the
  repository exists, and the Hub is never asked.

Other refusals follow the Hub's lead. A `401` for a model that does not
exist, or for a private one the Remote's credential cannot see, reaches the
client as `401` with `X-Error-Code: RepoNotFound` (`RepositoryNotFoundError`).
A `403` without a code stays a `403`. Only a real upstream failure is a `5xx`.

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
| `GET` | `/api/models/{model_id}/tree/{revision}` | File listing (`list_repo_tree`; `snapshot_download` calls it with `recursive=true`). Honours `recursive`: without it, subdirectories are listed as `directory` entries. Remote: proxied from the Hub when nothing is held locally, forwarding `recursive`, `expand` and `cursor` (each distinct query is cached on its own), with the Hub's pages followed and returned as one list. |
| `GET` | `/api/models` | Models held in the repository (see limitations). |
| `POST` | `/api/models/{model_id}/upload/{revision}` | Upload one file to a Local repository (Artifact Keeper's own route, see below). |

Revisions may be branch names, tags, 40-character commit shas or refs such as
`refs/pr/1`. Responses carry the `X-Repo-Commit` and `ETag` headers
`huggingface_hub` needs to place files in its cache. For a Local repository,
which has no git history, the commit is a stable value derived from the model
ID and revision. Model info reports it as `sha`, and the model-info, tree and
resolve routes all accept it in place of the revision it stands for, which is
how `snapshot_download` requests the files it lists. Model info without a
revision describes `main` (or, for a model never published to `main`, its
newest revision), and an unknown revision answers 404 with
`X-Error-Code: RevisionNotFound`, as the Hub does.

On a Remote, the `HEAD` that `hf_hub_download` sends before its `GET` is
answered from the cache when the file is cached, and otherwise from a `HEAD`
to the Hub, so a new file is downloaded from the Hub once, by the `GET` that
follows. If the Hub refuses the `HEAD`, the request is served as a `GET`
would be. The same applies to a Remote member of a Virtual repository.

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

The body is streamed to storage while its SHA-256 is computed, so a
multi-gigabyte GGUF or safetensors file does not have to fit in the server's
memory. It is staged first (local upload scratch, or the repository's own
object store when that backend streams natively) and written to its final
key once it is complete. A file larger than `MAX_UPLOAD_SIZE` (default
10 GiB) is refused with `413`, up front when `Content-Length` declares it and
otherwise as soon as the limit is crossed, and leaves nothing behind. A
published file is immutable: uploading to a path that already holds a file
answers `409`, whatever the bytes. An empty body answers `400`. The response
carries the stored file's `path`, `sha256` and `size`.

Each revision is its own set of files: upload every file of a revision to
that revision. The model can then be downloaded with the usual calls, with
`HF_ENDPOINT` pointed at the Local repository:

```python
from huggingface_hub import HfApi, hf_hub_download, snapshot_download

HfApi().model_info("my-org/my-model", revision="main").siblings
snapshot_download("my-org/my-model")                 # main
snapshot_download("my-org/my-model", revision="v1")  # a revision uploaded as upload/v1
hf_hub_download("my-org/my-model", "config.json")
```

## Model-file scanning

Files uploaded to a Local repository are judged by the model-file scanner
(scan type `model`): pickle-bearing files (`pytorch_model.bin`, `.pt`,
`.ckpt`, `.pkl`, ...) are walked for imports that would run code on
`torch.load`, and safetensors and GGUF headers are checked for malformed or
inconsistent structure. A pickle importing a primitive such as `os.system` is
a critical `malicious` finding. Files proxied by a Remote repository are not
judged yet (Hugging Face has no scan-on-proxy). See [Model-file scanning](security/model-file-scanning.md) for
what is checked, the limits, and what it does not catch.

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
