#!/bin/sh
# =============================================================================
# test-env.sh — load the throwaway e2e admin credential into a host script
# =============================================================================
#
# The credential itself is defined ONCE, in the repository-root `.env.test`
# (#3490, #3938); this helper is only the shell half of reading it. Source it,
# do not execute it:
#
#   . "$(dirname "$0")/../lib/test-env.sh"
#   ADMIN_PASS="${ADMIN_PASS:-$AK_TEST_ADMIN_PASSWORD}"
#
# It sets AK_TEST_ADMIN_PASSWORD, ADMIN_PASSWORD and ADMIN_PASS, and an
# exported value always wins over the file's default — `.env.test` spells every
# assignment with `:-` precisely so that sourcing it cannot clobber an override.
#
# `.env.test` is located by walking up from the calling script's directory (and
# then from $PWD), so this works from any depth and from any working directory.
# It is deliberately NOT an error for the file to be missing: a script running
# INSIDE an e2e container sees only its own mounted directory, and there compose
# has already injected the same variables from the same file.
#
# POSIX sh: these scripts run under Alpine's ash as well as bash.
# =============================================================================

_ak_find_env_test() {
    _ak_dir=$(CDPATH= cd -- "${1:-.}" 2>/dev/null && pwd) || return 1
    while :; do
        if [ -r "$_ak_dir/.env.test" ]; then
            printf '%s\n' "$_ak_dir/.env.test"
            return 0
        fi
        [ "$_ak_dir" = "/" ] && return 1
        _ak_dir=$(dirname -- "$_ak_dir")
    done
}

_ak_env_test=$(_ak_find_env_test "$(dirname -- "${0:-.}")") \
    || _ak_env_test=$(_ak_find_env_test "$PWD") \
    || _ak_env_test=""

if [ -n "$_ak_env_test" ]; then
    # shellcheck source=/dev/null
    . "$_ak_env_test"
fi

unset _ak_dir _ak_env_test
