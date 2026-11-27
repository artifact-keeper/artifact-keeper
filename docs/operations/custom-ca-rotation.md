# Rotating custom HTTP CA certificates

Set `CUSTOM_CA_CERT_PATH` to a PEM file containing one or more certificates.
Custom certificates supplement the client's default trust sources; this does
not replace the operating system trust store.

## Publishing a revision

1. Validate the complete bundle before publishing it.
2. Write a temporary file in the same directory and atomically rename it over
   the configured file. Keep the configured path unchanged.
3. Verify the new bytes are visible from each backend container.
4. Look for `Activated custom CA revision` with the expected SHA-256 and
   certificate count in each backend's logs.

Set `CUSTOM_CA_RELOAD_POLL_INTERVAL_SECS` to the polling interval in whole
seconds. The default is **5 seconds**. Invalid values log a warning and use
the default. Set it to `0` to disable polling while still loading the
configured bundle on first use. With polling disabled, restart each backend
replica to pick up file changes.

The poller reopens the path, so it detects atomic renames and Kubernetes
projected volume symlink changes. Identical bytes do not rebuild clients or
repeat activation logs. Detection normally takes up to one poll interval,
plus filesystem propagation, file I/O, and replacement-client construction.
There is no hard wall-clock guarantee for an unresponsive network filesystem.

Retained pools opt in to automatic replacement. These include health probes,
repository egress, scanner integrations, retained OIDC services, import
clients, and Azure/GCS HTTP data-plane clients. Ordinary clients, such as
one-shot SSO, webhook and metadata requests, take the active trust snapshot
when built and keep it for that operation. They do not register a pool.

For each retained pool the backend rebuilds with the original SSRF, proxy,
redirect, timeout, and TLS verification settings. Rustls clients use the
crypto provider selected during startup on both the first build and reload.

## Removals and requests already in progress

A successful activation replaces every subscribed client's pool before new
requests can select it. This also replaces client-owned TLS session state.
Requests/builders created before activation and their response streams may
finish with the previous client; rotation does not abort active transfers.
Callers must not retain request builders indefinitely across a trust rotation.

A removed certificate stops authorizing subsequent requests only if no other
enabled trust source or certificate chain authorizes that endpoint. Test
removals with an isolated private CA absent from the default trust sources.
To remove the only custom CA and return to default trust, unset
`CUSTOM_CA_CERT_PATH` or publish an empty bundle, then restart each backend
replica. An empty update to an active bundle retains the previous roots.

## Failed updates and startup

The whole candidate bundle must parse and every certificate must load as an
X.509 trust anchor. Comments and non-certificate PEM sections are ignored.
A certificate-free bundle at startup leaves default trust in place. Once
custom roots are active, a certificate-free update retains them. Malformed
or incomplete certificate sections and oversized bundles (>4 MiB or 2,048
certificates) are rejected.
All replacement clients must build successfully before activation; a failure
in any client rejects the entire revision.

A failed update retains the **last known good trust set without expiration**.
`Custom CA reload failed` identifies the failure category without logging PEM
contents or filesystem paths. Identical failures warn at most once per minute;
a changed failure category warns immediately. Alert on this warning: retaining
old trust can delay removal of a compromised CA. Recovery to unchanged valid
bytes is also logged.

If no valid custom bundle has loaded yet, clients use their default trust
sources and report the load failure. When polling is enabled, the worker
retries so a bundle published after startup is picked up automatically. If
the backend logs `Could not start custom CA reload worker`, it continues using
the trust loaded on first use. Restart the affected replica to retry starting
the worker. Deployments that require a private CA from the first request
should publish and validate it before backend startup and gate readiness on
connectivity to the required service.

## Mounts and other TLS consumers

Mount the directory containing the bundle, or use a projected volume that
exposes updates. Kubernetes ConfigMap/Secret `subPath` mounts do not receive
projected updates. A single-file Docker bind mount may continue exposing the
old file after host-side replacement; check the backend-visible bytes.

The file path is captured when a client is built. Changing the configured path
or poll interval requires a backend restart. Each backend replica observes
its own filesystem and activates independently.

This mechanism covers the shared outbound **HTTP** clients. LDAP, SMTP,
OpenSearch SDK transports, S3/object_store SDK clients, and other TLS stacks
retain their existing configuration/reload behavior; do not infer that this
HTTP revision log confirms those consumers have reloaded. Dedicated cloud
metadata clients retain their own routing and trust policies.

Fallback: verify the published file is visible, then perform a controlled
backend restart/redeployment across all replicas.
