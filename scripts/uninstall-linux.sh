#!/bin/sh
set -eu

UNIT=bursar
STATE=/var/lib/bursar

[ "$(id -u)" = 0 ] || { echo 'run with sudo' >&2; exit 1; }

systemctl disable --now $UNIT 2>/dev/null || true
rm -f /etc/systemd/system/$UNIT.service /usr/local/bin/bursar /usr/local/bin/bursar-update
systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/bursar
echo 'daemon stopped and code removed'

if [ "${1:-}" = "--purge" ]; then
  echo "this deletes $STATE, including the wallet key. Move the funds out first."
  printf 'type DELETE to continue: '
  read -r answer
  [ "$answer" = DELETE ] || { echo 'kept'; exit 0; }
  rm -rf "$STATE"
  rm -rf /etc/bursar
  userdel bursar 2>/dev/null || true
  groupdel bursar 2>/dev/null || true
  echo 'state, key and the bursar user removed'
else
  echo "kept $STATE (key, policy, ledger, audit). Pass --purge to delete it."
fi
