# Reverse proxy timeouts for OCI and Docker pushes

When a client pushes a layer, the final `PUT /v2/<name>/blobs/uploads/<id>?digest=`
does not finish when its body has arrived. The backend still has to verify the
digest, move the blob to its content-addressed key and record it in the
database, and it sends no response bytes until that is done. How long that
takes depends on how the client uploaded the layer and on the storage backend:

| Upload | After the last body byte | Grows with layer size? |
|---|---|---|
| `POST`, then one `PUT` carrying the whole layer (containerd) | No read-back: the digest was computed while streaming. The stored size is checked from metadata. Filesystem renames; object stores copy server-side | Filesystem: only by the final `fsync` of the streamed body, which still runs before the response; the rename itself does not, unless rename is unavailable (for example staging and blobs on different mounts) and it falls back to a copy. Object stores: yes, by the copy |
| `POST ?digest=` carrying the whole layer | As above, without the stored-size check | Same |
| `POST`, one `PATCH`, empty `PUT` | Copy of the session part. Filesystem copies unless the volume supports reflinks | Yes, by the copy |
| `POST`, several `PATCH`es, `PUT` | Re-reads every part to verify the digest, writes one object, then moves it | Yes, by the read, hash and write |

The copy and re-read cases can take tens of seconds for a layer of several
hundred MB on S3, NFS or a networked block volume, sometimes minutes.

A reverse proxy whose response timeout is shorter than that answers the
client with 504 and resets the request to the backend. containerd 2.x (Docker
Engine with the containerd image store, BuildKit, nerdctl) pushes each layer
as one `PUT` carrying the whole layer and re-sends the identical `PUT` once
after a 504, so a short proxy timeout turns every large layer push into a
retry (#4902).

## Recommended settings

Give the `/v2/` routes a response timeout longer than the slowest layer
completion you expect. `3600s` is a safe value for multi-GB layers; disabling
the timeout for `/v2/` is also fine.

### Envoy Gateway (Gateway API `HTTPRoute`)

Envoy's route timeout defaults to **15 s** and is measured from the end of
the request body to the end of the response, so upload time does not count
but the completion work does. Envoy Gateway keeps that default unless the
route sets one:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: artifact-keeper
spec:
  rules:
    - matches:
        - path: { type: PathPrefix, value: /v2/ }
      timeouts:
        request: 3600s          # "0s" disables the timeout
        # backendRequest, if you set it, must not be shorter than request.
      backendRefs:
        - name: artifact-keeper-backend
          port: 8080
```

A `BackendTrafficPolicy` with `spec.timeout.http.requestTimeout` achieves the
same for every route of a gateway. Istio (`VirtualService` `timeout`) and
Contour (`HTTPProxy` `timeoutPolicy.response`) have equivalent settings.

### nginx

`proxy_read_timeout` defaults to **60 s**: the longest gap nginx waits between
two reads from the backend, which during a completion is the whole completion.

```nginx
location /v2/ {
    proxy_pass              http://artifact-keeper-backend:8080;
    proxy_read_timeout      3600s;
    proxy_send_timeout      3600s;
    client_max_body_size    0;      # layer size is enforced by MAX_UPLOAD_SIZE
    proxy_request_buffering off;    # stream layers instead of spooling them
}
```

For the ingress-nginx controller the same values are the
`nginx.ingress.kubernetes.io/proxy-read-timeout`, `proxy-send-timeout` and
`proxy-body-size` annotations.

## Client-side response-header limits

A proxy timeout is not the only limit. A client can give up on its own, and no
proxy or backend setting extends that.

containerd 2.3.0 and later set a hard-coded 30 s `ResponseHeaderTimeout` in
`DefaultHTTPTransport`, measured from the end of the request body to the
response headers. `hosts.toml` has `dial_timeout` but no setting for this one.
Whether a given tool inherits it depends on how that tool builds its HTTP
client, so check the tool and its version rather than assuming. Other Go clients
can set the same option to any value.

How to recognize it:

- The client reports `net/http: timeout awaiting response headers`, not a 504.
  containerd wraps this as `failed commit on ref "layer-sha256:..."`.
- Envoy logs the request with response flag `DC` (the downstream closed the
  connection), not `UT` (the upstream timed out).
- The backend logs `Completed blob upload` for that session, with no
  `Request completed` line for the request. The blob was stored; only the answer
  was lost.

Because a completion runs to its end without the client, the next push normally
finds the blob already there and skips that layer. If you hit this limit:

1. Retry the push after a short delay, long enough for the completion to finish.
   A pipeline retry with a delay is usually enough. Each oversized layer may fail
   once, so a push with several of them can take several attempts.
2. Keep the `/v2/` route timeout above the slowest completion, as described
   above, so that the proxy does not cut first.
3. If it keeps failing, use faster storage, split the largest layers, or push
   with a client that has no such limit. On object storage the server-side copy
   still takes time proportional to the layer.

## What the backend does when the proxy cuts a completion anyway

Since 1.11.7 a completion runs to its end even when the request that started
it is dropped by the proxy or the client:

- A retry of the same `PUT` (same session, same digest) that arrives while the
  completion is still running waits for it, up to
  `OCI_UPLOAD_COMPLETION_RETRY_WAIT_SECS`, and is answered as the completion
  was: `201 Created` with `Location` and `Docker-Content-Digest`, or the same
  error. If the completion is still running when the wait is over, the retry
  gets `503` with `Retry-After: 5`.
- A retry that arrives after the completion finished gets `201 Created` when
  the blob is in the repository.
- A retry with a different digest is still refused with `409`
  (`upload session is already being modified`).
- A completion whose replica died (crash, pod kill) holds the session for at
  most five minutes, after which a retry can take it over. Before 1.11.7 that
  was six hours.

When replicas sit behind a load balancer, a retry that lands on a different
replica than the running completion polls the session instead of waiting on
the completion directly; it settles the same way except that it cannot tell a
different digest apart while the first completion is running.

| Variable | Default | Meaning |
|---|---|---|
| `OCI_UPLOAD_COMPLETION_RETRY_WAIT_SECS` | `30` | How long a retried completion `PUT` waits for the completion it duplicates before answering `503` with `Retry-After`. `0` answers `503` at once. Capped at 3600. |

These behaviours make a cut completion recoverable, but each cut still costs
the client a retry and the layer's upload time again on the next attempt.
Setting the proxy timeouts above is the fix for a proxy cut; the retry handling
is a safety net.
