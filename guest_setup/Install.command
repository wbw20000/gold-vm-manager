#!/bin/bash
# User-run only, inside the freshly configured guest. Never run this on the host.
set -eu
set +x
umask 077
SETUP='/Volumes/My Shared Files/setup'
if [[ "$(/usr/bin/dirname -- "$0")" != "$SETUP" ]] || [[ ! -x /usr/bin/ruby ]]; then
  printf '%s\n' 'Run this file from /Volumes/My Shared Files/setup INSIDE the new guest. System Ruby is required.'
  exit 1
fi
exec /usr/bin/ruby "$SETUP/install_guest.rb" "$@"
