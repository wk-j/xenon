#!/bin/sh
# Run Xenon locally for development.
#
# Handles the two things that are annoying to do by hand every time: generating
# a session secret and remembering to allow non-Secure cookies over plain HTTP.
# The secret is persisted in the data dir so restarting does not churn it.
#
#   scripts/dev.sh              # debug build on :8787
#   scripts/dev.sh --release    # optimized build
#   scripts/dev.sh --watch      # rebuild and restart on every save (cargo-watch)
#   scripts/dev.sh --reset      # wipe the database and blobs first
#   PORT=9000 scripts/dev.sh    # different port
#
# State lives in ~/.config/xenon, NOT in this checkout: the dev instance and an
# installed binary are then the same server, with the same accounts, whichever
# directory either was started from.
#
# NOT for production: this sets XENON_INSECURE_COOKIES=1, which drops `Secure`
# from the session cookie. Real deployments terminate TLS at a reverse proxy and
# must not set it. See README.md.

set -eu

cd "$(dirname "$0")/.."

DATA_DIR="${XENON_DATA_DIR:-$HOME/.config/xenon}"
PORT="${PORT:-${XENON_PORT:-8787}}"
CARGO_ARGS=""
RESET=0
WATCH=0

for arg in "$@"; do
    case "$arg" in
        --release) CARGO_ARGS="--release" ;;
        --reset) RESET=1 ;;
        --watch) WATCH=1 ;;
        -h | --help)
            # Print the header comment, stopping at the first line of code so
            # this cannot drift as the script grows.
            awk 'NR>1 && !/^#/ {exit} NR>1 {sub(/^# ?/, ""); print}' "$0"
            exit 0
            ;;
        *)
            echo "unknown option: $arg (try --help)" >&2
            exit 2
            ;;
    esac
done

if [ "$RESET" -eq 1 ]; then
    printf 'delete everything in %s (accounts, tokens, published resources)? [y/N] ' "$DATA_DIR"
    read -r reply
    case "$reply" in
        y | Y) rm -rf "$DATA_DIR" && echo "wiped $DATA_DIR" ;;
        *)
            echo "aborted"
            exit 1
            ;;
    esac
fi

mkdir -p "$DATA_DIR"

# Persist the secret so sessions behave consistently across restarts. 0600, and
# outside the checkout entirely, so it cannot be committed.
SECRET_FILE="$DATA_DIR/.session-secret"
if [ ! -f "$SECRET_FILE" ]; then
    umask 077
    openssl rand -hex 32 > "$SECRET_FILE"
    echo "generated a new session secret at $SECRET_FILE"
fi

XENON_SESSION_SECRET="$(cat "$SECRET_FILE")"
export XENON_SESSION_SECRET
export XENON_DATA_DIR="$DATA_DIR"
export XENON_PORT="$PORT"
export XENON_INSECURE_COOKIES=1
export RUST_LOG="${RUST_LOG:-info}"

# Point at the first-run screen only when there is no account yet, so the hint
# does not become noise on every subsequent start.
if [ ! -f "$DATA_DIR/xenon.db" ]; then
    echo
    echo "  First run. Open http://localhost:$PORT/register and create your account —"
    echo "  the first account becomes the admin and needs no invite code."
    echo
else
    echo "  http://localhost:$PORT/"
fi

# `cargo watch -x run` on its own starts a bare `cargo run` with none of the
# environment above, which is why it dies on the missing session secret. Launch
# it from here instead, so the secret, data dir, port and cookie flag are
# already exported into the watched process.
if [ "$WATCH" -eq 1 ]; then
    if ! command -v cargo-watch > /dev/null 2>&1; then
        echo "cargo-watch is not installed: cargo install cargo-watch" >&2
        exit 127
    fi
    echo "  watching src/, templates/ and assets/ — save to rebuild"
    echo
    # askama and include_str! both register their files as build inputs, so a
    # template or stylesheet edit triggers a rebuild without listing them here.
    exec cargo watch -x "run $CARGO_ARGS"
fi

exec cargo run $CARGO_ARGS
