#!/bin/sh
# curl-sbom.sh <curl|libcurl> <CURL_VERSION> <CURL_SHA256> <libcurl location>
#
# Prints a CycloneDX 1.5 JSON document for the curl / libcurl a Dockerfile
# builds from source (#6003). Run in the builder stage from the same
# CURL_VERSION / CURL_SHA256 ARGs that fetch the tarball, so the SBOM cannot
# drift from what was built. The images install it as
# /usr/share/sbom/curl.cdx.json.
#
# Why: that curl is not an RPM, so RPM-database scanners (Trivy, and syft's
# RPM cataloger behind the BuildKit SBOM attestation) cannot see it.
# CPE-matching scanners that read embedded CycloneDX documents (syft's
# sbom-cataloger, and grype through it) can.
#
#   curl     the image ships the curl tool with libcurl linked statically
#            (docker/Dockerfile.backend): both components, curl depends on
#            libcurl.
#   libcurl  the image ships only the libcurl shared library
#            (docker/Dockerfile.openscap).
#
# POSIX sh and printf only: the UBI builder stages have no jq or python.
set -eu

[ $# -eq 4 ] || { echo "usage: $0 <curl|libcurl> <version> <sha256> <libcurl location>" >&2; exit 2; }
kind="$1" v="$2" sha="$3" where="$4"

case "$kind" in curl|libcurl) ;; *) echo "curl-sbom.sh: unknown kind '$kind'" >&2; exit 2 ;; esac
printf '%s\n' "$v" | grep -Eqx '[0-9]+(\.[0-9]+){1,3}' \
  || { echo "curl-sbom.sh: '$v' is not a plain curl version" >&2; exit 2; }
printf '%s\n' "$sha" | grep -Eqx '[0-9a-f]{64}' \
  || { echo "curl-sbom.sh: '$sha' is not a sha256" >&2; exit 2; }
case "$where" in *\"*|*\\*) echo "curl-sbom.sh: location must not need JSON escaping" >&2; exit 2 ;; esac

tarball="https://curl.se/download/curl-${v}.tar.xz"

# component <bom-ref/name> <type> <location>
component() {
  printf '    {\n'
  printf '      "bom-ref": "pkg:generic/%s@%s",\n' "$1" "$v"
  printf '      "type": "%s",\n' "$2"
  printf '      "name": "%s",\n' "$1"
  printf '      "version": "%s",\n' "$v"
  printf '      "description": "Built from source in this image, not installed from an RPM",\n'
  printf '      "licenses": [{ "license": { "id": "curl" } }],\n'
  printf '      "cpe": "cpe:2.3:a:haxx:%s:%s:*:*:*:*:*:*:*",\n' "$1" "$v"
  printf '      "purl": "pkg:generic/%s@%s",\n' "$1" "$v"
  printf '      "externalReferences": [\n'
  printf '        { "type": "website", "url": "https://curl.se/" },\n'
  printf '        { "type": "advisories", "url": "https://curl.se/docs/vuln-%s.html" },\n' "$v"
  printf '        { "type": "distribution", "url": "%s",\n' "$tarball"
  printf '          "hashes": [{ "alg": "SHA-256", "content": "%s" }] }\n' "$sha"
  printf '      ],\n'
  printf '      "properties": [{ "name": "artifact-keeper:location", "value": "%s" }]\n' "$3"
  printf '    }'
}

printf '{\n'
printf '  "bomFormat": "CycloneDX",\n'
printf '  "specVersion": "1.5",\n'
printf '  "version": 1,\n'
printf '  "metadata": {\n'
printf '    "tools": { "components": [{ "type": "application", "name": "curl-sbom.sh" }] }\n'
printf '  },\n'
printf '  "components": [\n'
if [ "$kind" = curl ]; then
  component curl application /usr/bin/curl
  printf ',\n'
fi
component libcurl library "$where"
printf '\n  ],\n'
printf '  "dependencies": [\n'
if [ "$kind" = curl ]; then
  printf '    { "ref": "pkg:generic/curl@%s", "dependsOn": ["pkg:generic/libcurl@%s"] },\n' "$v" "$v"
fi
printf '    { "ref": "pkg:generic/libcurl@%s", "dependsOn": [] }\n' "$v"
printf '  ]\n'
printf '}\n'
