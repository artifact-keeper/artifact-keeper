# PyPI Remote repositories

A PyPI Remote repository proxies an upstream package index. Clients use it
like any index, for example `pip install --index-url
https://registry.example.com/pypi/pypi-remote/simple/ requests`.

## The upstream index path (`pypi_upstream_index_path`)

The backend builds the upstream URL of a project page from the Remote's
`upstream_url`, an index path and the project name:
`<upstream_url>/<index path>/<project>/`. The index path is the repository
setting `pypi_upstream_index_path`:

| Value | Upstream URL of project `torch` | Use it for |
|---|---|---|
| unset or `"simple"` (default) | `<upstream_url>/simple/torch/` | pypi.org, devpi, Nexus, Artifactory and other PEP 503 indexes |
| `""` (empty) | `<upstream_url>/torch/` | indexes whose project pages sit directly under the URL you give, such as `https://download.pytorch.org/whl/cpu` |
| any other string, e.g. `"pypi/simple"` | `<upstream_url>/pypi/simple/torch/` | an index under a custom prefix |

When `upstream_url` already ends in `/simple` and the setting is the default,
the backend does not add a second `simple/`: `https://pypi.org/simple` and
`https://pypi.org` behave the same.

Set it when you create the Remote or later:

```bash
# A Remote for the PyTorch CPU wheel index
curl -X POST https://registry.example.com/api/v1/repositories \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"key": "pytorch-cpu", "name": "pytorch-cpu", "format": "pypi",
       "repo_type": "remote", "upstream_url": "https://download.pytorch.org/whl/cpu",
       "pypi_upstream_index_path": ""}'

# Change it on an existing Remote ("simple" restores the default)
curl -X PATCH https://registry.example.com/api/v1/repositories/pytorch-cpu \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"pypi_upstream_index_path": ""}'
```

The setting also applies to Poetry, Jupyter and Conda Remote repositories that
use the PyPI index layout.

### Diagnosing a wrong index path

With the wrong index path, the upstream usually answers `403` or `404` for
every project page. A `404` reaches the client as `404`. Any other upstream
`4xx` is answered `502 Failed to fetch from upstream`, and the response
carries an `X-AK-Upstream-Status` header with the status the upstream gave:

```console
$ curl -sI https://registry.example.com/pypi/pytorch-cpu/simple/torch/
HTTP/1.1 502 Bad Gateway
x-ak-upstream-status: 403
```

An `X-AK-Upstream-Status: 403` from an index that serves the same project to a
browser usually means the index path is wrong. The header is set on the
generic proxy `502` for every format, never names the upstream URL, and is
absent when the upstream gave no HTTP answer (a timeout or a refused
connection).

## JSON or HTML (PEP 691)

The `/simple/` pages are served as PEP 691 JSON
(`application/vnd.pypi.simple.v1+json`) or as PEP 503 HTML, chosen from the
request's `Accept` header:

- `application/vnd.pypi.simple.v1+json` and its alias
  `application/vnd.pypi.simple.latest+json` ask for JSON;
  `text/html`, `application/vnd.pypi.simple.v1+html` and
  `application/vnd.pypi.simple.latest+html` ask for HTML.
- Each type's `q` value counts. JSON is served when its best `q` is above
  zero and at least the best HTML `q`; otherwise HTML. A tie goes to JSON.
- `*/*`, `text/*` and a missing `Accept` get HTML.

pip and uv send JSON first with HTML at a lower `q`, so they get JSON. The
HTML page is served as `text/html` whichever HTML type was asked for.
