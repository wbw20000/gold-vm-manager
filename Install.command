#!/bin/bash
# Source-only installer. Never launch the app/server/VM or change Gatekeeper.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
if ! /usr/bin/xcode-select -p >/dev/null 2>&1; then
    printf '%s\n' 'Apple Command Line Tools are required. Install them explicitly, then rerun this source installer.' >&2
    exit 1
fi
SOURCE_DIR="$(CDPATH= cd -P -- "$(/usr/bin/dirname "$0")" && /bin/pwd -P)"
if [ "$#" -eq 0 ]; then
    : "${HOME:?A user home directory is required}"
    if [ ! -d "$HOME/Applications" ]; then
        /bin/mkdir "$HOME/Applications"
    fi
    set -- --output "$HOME/Applications/Gold VM 管理器.app" --build-root "$SOURCE_DIR/build"
fi
exec /usr/bin/env -i HOME="${HOME:?}" PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
    PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    /usr/bin/python3 -s "$SOURCE_DIR/install_app.py" "$@"
