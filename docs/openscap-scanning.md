# OpenSCAP compliance scanning

When `OPENSCAP_URL` points the backend at the OpenSCAP sidecar
(`ghcr.io/artifact-keeper/artifact-keeper-openscap`), every container image
gets an `openscap` scan. The scan evaluates an XCCDF profile against the
image's own root filesystem. Its failed rules are recorded as policy findings.

## What is evaluated

1. The backend reads the image's layers from the repository's blob store. For
   an image index it uses the runnable platform manifest. It applies the
   layers in order, honouring whiteouts, into a per-scan directory under
   `SCAN_WORKSPACE_PATH`, which the sidecar mounts read-only.
2. The sidecar picks the datastream from the image's own `os-release`. The
   image ships RHEL 9 (`rhel9`) and CentOS Stream 9 (`cs9`) content. It then
   runs `oscap xccdf eval` with `OSCAP_PROBE_ROOT` pointing at that directory.

Unpacking is bounded by the scan-workspace limits (`MAX_SCAN_EXTRACTED_BYTES`,
200,000 entries, and the 10 GiB scan input limit). Every path and symlink is
resolved inside the image root. Symlinks are rewritten to relative targets
that stay inside it. Hard links must name a file inside it. Device nodes are
skipped, and setuid and setgid bits are dropped.

A scan is recorded `not_applicable`, with the reason, never as a pass, when:

- the artifact is not a runnable container image (RPM and DEB packages, Helm
  charts, signatures and SBOMs stored as OCI artifacts);
- the image's layers are not stored in the repository;
- the image has no `os-release`;
- no shipped datastream describes its OS (Debian, Alpine and RHEL 8 images,
  for example);
- no rule in the profile applies to it;
- the sidecar cannot enter the unpacked tree (see below).

Rules that check file owners or group owners are reported as not evaluated.
The backend does not run as root, so the unpacked tree cannot keep the
image's ownership.

## Profile

`OPENSCAP_PROFILE` on the backend selects the profile. The default is
`xccdf_org.ssgproject.content_profile_cis_server_l1` (CIS Level 1 - Server).
A profile that no shipped datastream defines fails the scan, and the error
lists the profiles that exist. List them yourself with:

```sh
docker exec artifact-keeper-openscap \
  oscap info --profiles /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

## Letting the sidecar enter the unpacked tree

oscap's probes `chroot(2)` into `OSCAP_PROBE_ROOT`. The sidecar runs as UID
1001, so this needs one of three things:

1. **Rootless Podman.** The wrapper starts oscap in a user namespace. No
   change is needed.
2. **Allow unprivileged user namespaces for the sidecar.** Docker's default
   seccomp profile blocks `unshare(CLONE_NEWUSER)` for a process without
   `CAP_SYS_ADMIN`. A Kubernetes pod with `seccompProfile: RuntimeDefault`
   blocks it the same way. In compose:

   ```yaml
   openscap:
     security_opt:
       - seccomp=unconfined
   ```

3. **Root mode.** Start the sidecar as root and opt in with
   `OPENSCAP_RUN_AS_ROOT=true`:

   ```yaml
   openscap:
     user: "0"
     environment:
       OPENSCAP_RUN_AS_ROOT: "true"
     cap_add:
       - DAC_READ_SEARCH   # optional: lets the scan read mode-0000 files
   ```

   Only the HTTP wrapper runs as root. Before it execs oscap, each scan's
   child process:
   - shrinks its capability bounding set to `CAP_SYS_CHROOT` (plus
     `CAP_DAC_READ_SEARCH`, read-only access to any file, when the container
     grants it);
   - drops to UID 1001 with only those capabilities;
   - sets `no_new_privs`.

   The probes therefore read the unpacked tree, which is mounted read-only,
   without holding root. This matters because the `rpminfo` probe drives
   librpm inside the image's tree, and librpm reads the image's rpm
   configuration. The container must keep `CAP_SETUID`, `CAP_SETGID`,
   `CAP_SETPCAP` and `CAP_SYS_CHROOT`, which Docker and Podman grant by
   default. Without `CAP_DAC_READ_SEARCH`, rules that read a file the image
   ships at mode 0000 (`/etc/shadow`) report `error`.

   `OPENSCAP_RUN_AS_ROOT` has no effect unless the process is root, and a
   root sidecar without it never runs oscap outside a user namespace.

On stock Docker with none of these, every OpenSCAP scan is recorded
`not_applicable` with that reason. The sidecar logs
`[openscap-wrapper] evaluated <path> isolation=userns|root` for every scan
it evaluates.

Run the OpenSCAP image from the same release as the backend. The backend
refuses an answer from an older wrapper, which evaluated its own filesystem,
and fails those scans.
