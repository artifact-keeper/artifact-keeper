# Presigned download redirects and the public storage endpoint

With `PRESIGNED_DOWNLOADS_ENABLED=true` and a storage backend that can sign
URLs (S3 with `S3_REDIRECT_DOWNLOADS=true`, GCS, Azure with Shared Key auth,
CloudFront), artifact downloads answer `302` (OCI blob pulls `307`) with a
signed URL on the object store, and the client fetches the bytes from there
instead of through Artifact Keeper.

That URL is only useful if the **client** can reach the host in it.

## The problem: an internal storage endpoint

By default the signed URL uses the same address the backend uses for its own
storage calls: `S3_ENDPOINT` or `AZURE_STORAGE_ENDPOINT`. In a cluster that is
often an in-cluster service name such as `http://storage-minio:9000`, which a
`docker pull` or `mvn` running outside the cluster cannot resolve, so every
redirected download fails (#4417).

**Do not enable presigned downloads while the storage endpoint is
unreachable from clients and no public endpoint is configured.** AWS S3
without a custom `S3_ENDPOINT`, GCS (always signed for
`storage.googleapis.com`) and CloudFront already hand out public URLs and need
nothing below.

## S3: `S3_PUBLIC_ENDPOINT`

```bash
S3_ENDPOINT=http://storage-minio:9000          # backend -> object store
S3_PUBLIC_ENDPOINT=https://s3.example.com      # client  -> object store
S3_REDIRECT_DOWNLOADS=true
PRESIGNED_DOWNLOADS_ENABLED=true
```

- Used **only** to build and sign presigned GET URLs. Every request the
  backend makes itself (reads, writes, listing, deletes, copies, the startup
  probe) still goes to `S3_ENDPOINT`.
- SigV4 signs the `Host` header and the request path, so the URL is signed for
  the public host rather than rewritten after signing. Whatever answers at the
  public endpoint (ingress, load balancer, reverse proxy) must forward to the
  object store **with the `Host` header unchanged and the path untouched**.
  For an nginx ingress in front of MinIO that means no `rewrite-target` and
  `proxy_set_header Host $http_host` (the ingress-nginx default).
- The value must be `scheme://host[:port]`: `http` or `https`, no path, no
  query string or fragment, no `user:password@`. A trailing slash is
  accepted. Anything else stops the backend at startup with an error naming
  the variable, rather than producing broken redirects later.
- URLs keep path-style addressing (`https://s3.example.com/<bucket>/<key>`),
  the same as the backend's own requests.
- Works with dedicated signing credentials (`S3_PRESIGN_ACCESS_KEY_ID` /
  `S3_PRESIGN_SECRET_ACCESS_KEY`); without them the normal credential chain
  signs.
- CloudFront, when configured, takes precedence and is unaffected.

## Azure: `AZURE_STORAGE_PUBLIC_ENDPOINT`

```bash
AZURE_STORAGE_ENDPOINT=http://azurite:10000/myaccount
AZURE_STORAGE_PUBLIC_ENDPOINT=https://blobs.example.com/myaccount
AZURE_REDIRECT_DOWNLOADS=true
PRESIGNED_DOWNLOADS_ENABLED=true
```

The SAS token signs the account, container and blob names, not the host, so
only the base of the redirect URL changes. The value may carry a path
(path-style endpoints such as Azurite put the account name in it); query
strings, fragments and userinfo are rejected at startup. SAS tokens are issued
with `spr=https`, so real Azure Storage requires an `https` public endpoint.

The proxy rule is the **opposite of S3's**: Azure Storage identifies the
storage account from the `Host` header, so a reverse proxy in front of
`<account>.blob.core.windows.net` must rewrite `Host` to the account host.
Alternatively, the public host must be registered as the account's custom
domain. (Azurite and other path-style endpoints take the account from the
path instead.)

## Checking it

With the backend running, send a GET that does not follow the redirect and
look at the `Location` header. Do not use `curl -I`: `HEAD` is never
redirected, so it shows no `Location`.

```bash
curl -s -o /dev/null -D - -u user:token \
  https://ak.example.com/v2/<name>/blobs/<digest> | grep -i '^location'
```

The host must be the public endpoint, and fetching that URL from outside the
cluster must return the object.
