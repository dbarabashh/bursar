#!/bin/sh
set -eu

LABEL=dev.bursar.daemon
STATE=/var/db/bursar

[ "$(id -u)" = 0 ] || { echo 'run with sudo' >&2; exit 1; }

launchctl bootout system/$LABEL 2>/dev/null || true
rm -f /Library/LaunchDaemons/$LABEL.plist /usr/local/bin/bursar
rm -rf /opt/bursar
echo 'daemon stopped and code removed'

if [ "${1:-}" = "--purge" ]; then
  echo "this deletes $STATE, including the wallet key. Move the funds out first."
  printf 'type DELETE to continue: '
  read -r answer
  [ "$answer" = DELETE ] || { echo 'kept'; exit 0; }
  rm -rf "$STATE"
  dscl . -delete /Users/_bursar 2>/dev/null || true
  dscl . -delete /Groups/_bursar 2>/dev/null || true
  echo 'state, key and the _bursar user removed'
else
  echo "kept $STATE (key, policy, ledger, audit). Pass --purge to delete it."
fi
