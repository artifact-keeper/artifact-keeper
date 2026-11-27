# Homebrew bottle repositories

Artifact Keeper hosts Homebrew bottles (#5985): the pre-built binary archives
`brew` pours into the Cellar. Create a repository with `format: homebrew` and
`repo_type: local`, upload bottles built by `brew bottle`, and serve them to
macOS and Linuxbrew hosts, for internal tools or an air-gapped mirror.

The formula JSON is rendered on demand from the uploaded bottles, so there is
no index step and nothing to keep in sync.

**Scope of this first slice.** Hosted repositories only: Remote (a proxy for
`formulae.brew.sh` and the bottle CDN) and virtual Homebrew repositories answer
`501 Not Implemented`. Casks and taps served as git repositories are not
supported. The formula JSON is served unsigned: current `brew` reads a
JWS-signed `formula.jws.json` from `HOMEBREW_API_DOMAIN`, which this repository
does not produce. The bottle endpoints and the JSON shape follow Homebrew's
public API, but end-to-end use with a stock `brew` has not been verified yet;
treat the API endpoints as experimental.

## Endpoints

All routes live under `/homebrew/{repo_key}`:

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/bottles/{filename}[?cellar=...]` | Upload a bottle |
| `GET` | `/bottles/{filename}` | Download a bottle |
| `DELETE` | `/bottles/{filename}` | Delete a bottle |
| `GET` | `/api/formula.json` | Every formula, newest version |
| `GET` | `/api/formula/{name}.json` | One formula |

`{filename}` is `{name}--{version}.{tag}.bottle[.{rebuild}].tar.gz`, the name
`brew bottle` writes, or the same with a single dash, the name a bottle host
serves. Both resolve to the one stored bottle. A formula name that contains a
dash followed by a digit (`lib-2to3`) is ambiguous in the single-dash spelling;
upload it with `--`.

## Publishing

```sh
brew install --build-bottle --bottle-arch=... ./mytool.rb
brew bottle --json mytool
curl -X PUT -H "Authorization: Bearer $TOKEN" --data-binary @mytool--1.2.0.arm64_sonoma.bottle.tar.gz \
  "https://ak.example.com/homebrew/tools/bottles/mytool--1.2.0.arm64_sonoma.bottle.tar.gz?cellar=:any"
```

- The archive must contain `{name}/{version}/INSTALL_RECEIPT.json` for the name
  and version in the filename, or the upload is refused with 400.
- `cellar` is the bottle's relocation mode: `:any` (default),
  `:any_skip_relocation`, or an absolute path such as `/opt/homebrew/Cellar`.
  `brew bottle --json` prints the right value.
- Re-uploading an existing filename is refused (409): publish a new `rebuild`
  (`...bottle.1.tar.gz`) instead. Each platform tag is served by its highest
  rebuild.
- Uploads need a token with the `write:artifacts` scope and write access to the
  repository; deletes need `delete:artifacts`.
- Uploaded bottles are scanned on upload like any other artifact.
