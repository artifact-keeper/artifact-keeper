#!/usr/bin/env bash
#
# Disposable real-client dogfood harness for the experimental Open VSX gateway.
# It only permits the reviewed Red Hat YAML extension, and never edits a
# user's normal VS Code-family profile. See docs/vscode-openvsx-gateway.md.

set -euo pipefail

readonly DEFAULT_EXTENSION_ID='redhat.vscode-yaml'

usage() {
    cat <<'EOF'
Usage: AK_URL=https://ak.example AK_REPO=openvsx scripts/dogfood-vscode-openvsx.sh <command>

Commands:
  probe                 Verify AK's manifest, exact gallery query, latest lookup,
                        and AK-only rewritten asset URLs.
  vscodium-ui           Start an isolated VSCodium UI for a manual gallery search.
  code-server-ui        Start isolated code-server for a manual browser gallery search.
  install-vscodium TAG  Install redhat.vscode-yaml into a new isolated VSCodium profile.
  install-code-server TAG
                        Install redhat.vscode-yaml into a new isolated code-server profile.
  update-vscodium TAG   Install UPDATE_FROM_VERSION, then ask VSCodium to update it.
  update-code-server TAG
                        Install UPDATE_FROM_VERSION, then ask code-server to update it.

Required environment:
  AK_URL                 Public, anonymous-read Artifact Keeper origin (no path).
  AK_REPO                Public VS Code Remote repository key.

Optional environment:
  DOGFOOD_RUN_DIR        Artifact directory. Defaults to a fresh /tmp directory.
  VSCODIUM_BIN           VSCodium executable (default: codium).
  CODE_SERVER_BIN        code-server executable (default: code-server).
  UPDATE_FROM_VERSION    A previously published redhat.vscode-yaml version required
                         by update-* commands; it must be verified in probe.json.
  EXTENSION_ID           Reviewed dogfood candidate: redhat.vscode-yaml (default).
                         Other extensions are deliberately rejected to prevent
                         an accidental arbitrary install.
  TRACE_NETWORK=1        Record connect/send/receive syscalls for CLI install/update
                         commands when strace is available.
  CORS_ORIGIN            When set, probe also verifies a browser-gallery OPTIONS
                         preflight permits this exact origin.

TAG must be a simple label such as cold or warm. Use distinct tags for cold and
warm runs so the client has no local VSIX cache. AK's server-side asset cache
should be cold on the first run and warm on the second.
EOF
}

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_config() {
    : "${AK_URL:?set AK_URL to the public AK origin}"
    : "${AK_REPO:?set AK_REPO to the public Remote repository key}"
    [[ "$AK_URL" =~ ^https?://[^/]+$ ]] || fail 'AK_URL must be an origin without a path'
    [[ "$AK_REPO" =~ ^[A-Za-z0-9._-]+$ ]] || fail 'AK_REPO contains unsupported characters'
    AK_URL=${AK_URL%/}
    GALLERY_URL="$AK_URL/vscode/$AK_REPO/gallery"
    EXTENSION_ID=${EXTENSION_ID:-$DEFAULT_EXTENSION_ID}
    case "$EXTENSION_ID" in
        redhat.vscode-yaml) ;;
        *) fail "EXTENSION_ID is not a reviewed dogfood candidate: $EXTENSION_ID" ;;
    esac
    EXTENSION_PUBLISHER=${EXTENSION_ID%%.*}
    EXTENSION_NAME=${EXTENSION_ID#*.}
}

setup_run_dir() {
    if [[ -n "${DOGFOOD_RUN_DIR:-}" ]]; then
        RUN_DIR=$DOGFOOD_RUN_DIR
        mkdir -p "$RUN_DIR"
    else
        RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ak-vscode-openvsx.XXXXXX")
    fi
    printf 'dogfood artifacts: %s\n' "$RUN_DIR"
}

check_tag() {
    [[ "${1:-}" =~ ^[A-Za-z0-9._-]+$ ]] || fail 'TAG must use only letters, numbers, dot, underscore, or hyphen'
}

gallery_query_body() {
    jq -n --arg id "$EXTENSION_ID" '{
      filters: [{
        criteria: [{filterType: 7, value: $id}],
        pageNumber: 1,
        pageSize: 10,
        sortBy: 0,
        sortOrder: 0
      }],
      flags: 511
    }'
}

assert_ak_urls() {
    local file=$1
    jq -e --arg prefix "$AK_URL/vscode/$AK_REPO/" '
      [
        .results[].extensions[].versions[]? |
        .assetUri?, .fallbackAssetUri?, (.files[]?.source?)
      ] | length > 0 and all(startswith($prefix))
    ' "$file" >/dev/null || fail 'gallery response retains a non-AK asset URL'
}

probe() {
    need curl
    need jq
    require_config
    setup_run_dir

    curl --fail --show-error --silent "$GALLERY_URL/manifest" >"$RUN_DIR/manifest.json"
    jq -e --arg gallery "$GALLERY_URL" '
      .resources | any(.type == "ExtensionQueryService" and .id == ($gallery + "/extensionquery")) and
      any(.type == "ExtensionLatestVersionUriTemplate" and .id == ($gallery + "/{publisher}/{name}/latest"))
    ' "$RUN_DIR/manifest.json" >/dev/null || fail 'manifest does not name AK gallery query/latest endpoints'

    if [[ -n "${CORS_ORIGIN:-}" ]]; then
        curl --fail --show-error --silent -D "$RUN_DIR/cors-preflight.headers" -o /dev/null \
            -X OPTIONS \
            -H "origin: $CORS_ORIGIN" \
            -H 'access-control-request-method: POST' \
            -H 'access-control-request-headers: content-type, x-market-client-id, x-market-user-id, vscode-sessionid, x-market-search-activity-id' \
            "$GALLERY_URL/extensionquery"
        grep -Eiq "^access-control-allow-origin:[[:space:]]*${CORS_ORIGIN//./\\.}[[:space:]]*$" \
            "$RUN_DIR/cors-preflight.headers" || fail 'CORS preflight did not allow CORS_ORIGIN'
        local required_header
        for required_header in content-type x-market-client-id x-market-user-id vscode-sessionid x-market-search-activity-id; do
            grep -Eiq "^access-control-allow-headers:.*${required_header}" \
                "$RUN_DIR/cors-preflight.headers" || fail "CORS preflight did not allow $required_header"
        done
    fi

    gallery_query_body | curl --fail --show-error --silent \
        -H 'accept: application/json;api-version=3.0-preview.1' \
        -H 'content-type: application/json' \
        --data-binary @- "$GALLERY_URL/extensionquery" >"$RUN_DIR/probe.json"
    jq -e '
      .results[].extensions[] |
      select(.publisher.publisherName == $publisher and .extensionName == $name) |
      .versions | length > 0
    ' --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" \
      "$RUN_DIR/probe.json" >/dev/null || fail "AK did not resolve reviewed extension $EXTENSION_ID"
    assert_ak_urls "$RUN_DIR/probe.json"

    curl --fail --show-error --silent \
        "$GALLERY_URL/$EXTENSION_PUBLISHER/$EXTENSION_NAME/latest" >"$RUN_DIR/latest.json"
    jq -e '
      .publisher.publisherName == $publisher and
      .extensionName == $name and
      (.versions | length > 0)
    ' --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" \
      "$RUN_DIR/latest.json" >/dev/null || fail "AK latest lookup did not return $EXTENSION_ID"
    jq -e --arg prefix "$AK_URL/vscode/$AK_REPO/" '
      [.versions[] | .assetUri?, .fallbackAssetUri?, (.files[]?.source?)] |
      length > 0 and all(startswith($prefix))
    ' "$RUN_DIR/latest.json" >/dev/null || fail 'AK latest response retains a non-AK asset URL'

    # code-server currently derives this compatibility path from serviceUrl;
    # keep the direct probe so a manifest-only test cannot hide a regression.
    curl --fail --show-error --silent \
        "$GALLERY_URL/vscode/$EXTENSION_PUBLISHER/$EXTENSION_NAME/latest" \
        >"$RUN_DIR/latest-code-server.json"
    jq -e '
      .publisher.publisherName == $publisher and
      .extensionName == $name and
      (.versions | length > 0)
    ' --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" \
      "$RUN_DIR/latest-code-server.json" >/dev/null || fail 'code-server latest alias did not return the reviewed extension'
    jq -e --arg prefix "$AK_URL/vscode/$AK_REPO/" '
      [.versions[] | .assetUri?, .fallbackAssetUri?, (.files[]?.source?)] |
      length > 0 and all(startswith($prefix))
    ' "$RUN_DIR/latest-code-server.json" >/dev/null || fail 'code-server latest alias retains a non-AK asset URL'

    jq -r '
      .results[].extensions[] |
      select(.publisher.publisherName == $publisher and .extensionName == $name) |
      .versions[] | [.version, (.targetPlatform // "universal"), .lastUpdated] | @tsv
    ' --arg publisher "$EXTENSION_PUBLISHER" --arg name "$EXTENSION_NAME" \
      "$RUN_DIR/probe.json" >"$RUN_DIR/resolved-versions.tsv"
    local resolved_count
    resolved_count=$(wc -l <"$RUN_DIR/resolved-versions.tsv")
    printf 'probe passed; resolved %s version(s). Latest result:\n' "$resolved_count"
    head -n 1 "$RUN_DIR/resolved-versions.tsv"
    printf 'full version inventory: %s\n' "$RUN_DIR/resolved-versions.tsv"
}

client_env() {
    export VSCODE_GALLERY_SERVICE_URL="$GALLERY_URL"
    export VSCODE_GALLERY_ITEM_URL="$AK_URL/vscode/$AK_REPO/item"
    export VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$GALLERY_URL/{publisher}/{name}/latest"
    export VSCODE_GALLERY_LATEST_URL_TEMPLATE="$GALLERY_URL/{publisher}/{name}/latest"
    export EXTENSIONS_GALLERY
    EXTENSIONS_GALLERY=$(jq -cn \
        --arg service "$VSCODE_GALLERY_SERVICE_URL" \
        --arg item "$VSCODE_GALLERY_ITEM_URL" \
        --arg latest "$VSCODE_GALLERY_EXTENSION_URL_TEMPLATE" \
        '{serviceUrl: $service, itemUrl: $item, extensionUrlTemplate: $latest, controlUrl: ""}')
}

run_with_optional_trace() {
    local trace_file=$1
    shift
    if [[ "${TRACE_NETWORK:-0}" == 1 ]]; then
        need strace
        strace -f -qq -e trace=network -o "$trace_file" "$@"
    else
        "$@"
    fi
}

client_dirs() {
    local client=$1
    local tag=$2
    local client_root="$RUN_DIR/$client-$tag"
    PROFILE_DIR="$client_root/user-data"
    EXTENSIONS_DIR="$client_root/extensions"
    # VSCodium/code-server keep a small amount of process state outside the
    # explicit user-data directory on Linux. Keep that state disposable too;
    # otherwise a CLI dogfood run can touch the user's normal XDG profile.
    export XDG_CONFIG_HOME="$client_root/xdg/config"
    export XDG_CACHE_HOME="$client_root/xdg/cache"
    export XDG_STATE_HOME="$client_root/xdg/state"
    mkdir -p "$PROFILE_DIR" "$EXTENSIONS_DIR" \
        "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME"
}

install_vscodium() {
    local tag=$1
    local bin=${VSCODIUM_BIN:-codium}
    need "$bin"
    client_dirs vscodium "$tag"
    client_env
    run_with_optional_trace "$RUN_DIR/vscodium-$tag.network.strace" \
        env VSCODE_GALLERY_SERVICE_URL="$VSCODE_GALLERY_SERVICE_URL" \
        VSCODE_GALLERY_ITEM_URL="$VSCODE_GALLERY_ITEM_URL" \
        VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$VSCODE_GALLERY_EXTENSION_URL_TEMPLATE" \
        VSCODE_GALLERY_LATEST_URL_TEMPLATE="$VSCODE_GALLERY_LATEST_URL_TEMPLATE" \
        "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
        --install-extension "$EXTENSION_ID" --force
}

install_code_server() {
    local tag=$1
    local bin=${CODE_SERVER_BIN:-code-server}
    need "$bin"
    client_dirs code-server "$tag"
    client_env
    run_with_optional_trace "$RUN_DIR/code-server-$tag.network.strace" \
        env EXTENSIONS_GALLERY="$EXTENSIONS_GALLERY" \
        "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
        --install-extension "$EXTENSION_ID" --force
}

update_client() {
    local client=$1
    local tag=$2
    [[ -n "${UPDATE_FROM_VERSION:-}" ]] || fail 'set UPDATE_FROM_VERSION to a verified prior Open VSX version'
    [[ "$UPDATE_FROM_VERSION" =~ ^[0-9A-Za-z.+_-]+$ ]] || fail 'UPDATE_FROM_VERSION contains unsupported characters'
    if [[ "$client" == vscodium ]]; then
        local bin=${VSCODIUM_BIN:-codium}
        need "$bin"
        client_dirs vscodium "$tag"
        client_env
        # Seed an intentionally older reviewed release, then force the CLI's
        # normal latest-resolution path. This is a deterministic proxy update
        # test, not a claim that a background auto-update timer was exercised.
        run_with_optional_trace "$RUN_DIR/vscodium-$tag-update.network.strace" \
            env VSCODE_GALLERY_SERVICE_URL="$VSCODE_GALLERY_SERVICE_URL" \
            VSCODE_GALLERY_ITEM_URL="$VSCODE_GALLERY_ITEM_URL" \
            VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$VSCODE_GALLERY_EXTENSION_URL_TEMPLATE" \
            VSCODE_GALLERY_LATEST_URL_TEMPLATE="$VSCODE_GALLERY_LATEST_URL_TEMPLATE" \
            "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
            --install-extension "$EXTENSION_ID@$UPDATE_FROM_VERSION" --force
        run_with_optional_trace "$RUN_DIR/vscodium-$tag-latest.network.strace" \
            env VSCODE_GALLERY_SERVICE_URL="$VSCODE_GALLERY_SERVICE_URL" \
            VSCODE_GALLERY_ITEM_URL="$VSCODE_GALLERY_ITEM_URL" \
            VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$VSCODE_GALLERY_EXTENSION_URL_TEMPLATE" \
            VSCODE_GALLERY_LATEST_URL_TEMPLATE="$VSCODE_GALLERY_LATEST_URL_TEMPLATE" \
            "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
            --install-extension "$EXTENSION_ID" --force
    else
        local bin=${CODE_SERVER_BIN:-code-server}
        need "$bin"
        client_dirs code-server "$tag"
        client_env
        run_with_optional_trace "$RUN_DIR/code-server-$tag-update.network.strace" \
            env EXTENSIONS_GALLERY="$EXTENSIONS_GALLERY" \
            "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
            --install-extension "$EXTENSION_ID@$UPDATE_FROM_VERSION" --force
        run_with_optional_trace "$RUN_DIR/code-server-$tag-latest.network.strace" \
            env EXTENSIONS_GALLERY="$EXTENSIONS_GALLERY" \
            "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR" \
            --install-extension "$EXTENSION_ID" --force
    fi
}

start_vscodium_ui() {
    local bin=${VSCODIUM_BIN:-codium}
    need "$bin"
    client_dirs vscodium ui
    client_env
    printf 'Search for %s in the isolated Extensions UI.\n' "$EXTENSION_ID"
    env VSCODE_GALLERY_SERVICE_URL="$VSCODE_GALLERY_SERVICE_URL" \
        VSCODE_GALLERY_ITEM_URL="$VSCODE_GALLERY_ITEM_URL" \
        VSCODE_GALLERY_EXTENSION_URL_TEMPLATE="$VSCODE_GALLERY_EXTENSION_URL_TEMPLATE" \
        VSCODE_GALLERY_LATEST_URL_TEMPLATE="$VSCODE_GALLERY_LATEST_URL_TEMPLATE" \
        "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR"
}

start_code_server_ui() {
    local bin=${CODE_SERVER_BIN:-code-server}
    need "$bin"
    client_dirs code-server ui
    client_env
    printf 'Open the printed code-server URL and search for %s in Extensions.\n' "$EXTENSION_ID"
    env EXTENSIONS_GALLERY="$EXTENSIONS_GALLERY" \
        "$bin" --user-data-dir "$PROFILE_DIR" --extensions-dir "$EXTENSIONS_DIR"
}

main() {
    local command=${1:-}
    case "$command" in
        probe)
            probe
            ;;
        vscodium-ui)
            require_config; setup_run_dir; start_vscodium_ui
            ;;
        code-server-ui)
            require_config; setup_run_dir; start_code_server_ui
            ;;
        install-vscodium)
            require_config; setup_run_dir; check_tag "${2:-}"; install_vscodium "$2"
            ;;
        install-code-server)
            require_config; setup_run_dir; check_tag "${2:-}"; install_code_server "$2"
            ;;
        update-vscodium)
            require_config; setup_run_dir; check_tag "${2:-}"; update_client vscodium "$2"
            ;;
        update-code-server)
            require_config; setup_run_dir; check_tag "${2:-}"; update_client code-server "$2"
            ;;
        -h|--help|help|'')
            usage
            ;;
        *)
            usage >&2
            fail "unknown command: $command"
            ;;
    esac
}

main "$@"
