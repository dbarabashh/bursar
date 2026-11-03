#!/bin/sh
# TODO: not ready yet: a Linux installer (systemd unit and a system user); this script is macOS only.
set -eu

LABEL=dev.bursar.daemon
PREFIX=/opt/bursar
STATE=/var/db/bursar
RUNAS=_bursar
PLIST=/Library/LaunchDaemons/$LABEL.plist
SRC=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'run with sudo: sudo NODE="$(command -v node)" PAY_TO=0x... ./scripts/install-macos.sh'
[ -n "${NODE:-}" ] && [ -x "$NODE" ] || die 'pass NODE="$(command -v node)" so the daemon gets the same Node 22+ you use'
"$NODE" -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a>22||(a===22&&b>=18)?0:1)' || die "Node 22.18+ is required ($NODE is $("$NODE" -v))"
[ -d "$SRC/node_modules/@noble/curves" ] || die "run npm ci in $SRC first"

if ! dscl . -read /Users/$RUNAS >/dev/null 2>&1; then
  ID=$(
    for i in $(seq 450 499); do
      if ! dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$i" && ! dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$i"; then echo "$i"; break; fi
    done
  )
  [ -n "$ID" ] || die 'no free id in 450..499 for the role account'
  dscl . -create /Groups/$RUNAS
  dscl . -create /Groups/$RUNAS PrimaryGroupID "$ID"
  dscl . -create /Groups/$RUNAS RealName 'bursar daemon'
  dscl . -create /Users/$RUNAS
  dscl . -create /Users/$RUNAS UniqueID "$ID"
  dscl . -create /Users/$RUNAS PrimaryGroupID "$ID"
  dscl . -create /Users/$RUNAS UserShell /usr/bin/false
  dscl . -create /Users/$RUNAS NFSHomeDirectory /var/empty
  dscl . -create /Users/$RUNAS RealName 'bursar daemon'
  dscl . -create /Users/$RUNAS IsHidden 1
  echo "created hidden user $RUNAS (uid $ID), it cannot log in"
fi

rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new/bin" "$PREFIX.new/app"
install -m 755 "$NODE" "$PREFIX.new/bin/node"
cp -R "$SRC/src" "$SRC/node_modules" "$SRC/package.json" "$PREFIX.new/app/"
cat > "$PREFIX.new/bin/bursar" <<WRAP
#!/bin/sh
case "\${1:-}" in
  ''|keygen|-h|--help) ;;
  *) case " \$* " in *" --policy "*) ;; *) set -- "\$@" --policy $STATE/policy.yaml ;; esac ;;
esac
if [ "\$(id -un)" != "$RUNAS" ]; then exec sudo -u $RUNAS $PREFIX/bin/node $PREFIX/app/src/index.ts "\$@"; fi
exec $PREFIX/bin/node $PREFIX/app/src/index.ts "\$@"
WRAP
chmod 755 "$PREFIX.new/bin/bursar"
chown -R root:wheel "$PREFIX.new"
chmod -R go-w "$PREFIX.new"
rm -rf "$PREFIX.old"
[ -d "$PREFIX" ] && mv "$PREFIX" "$PREFIX.old"
mv "$PREFIX.new" "$PREFIX"
rm -rf "$PREFIX.old"
mkdir -p /usr/local/bin
ln -sf "$PREFIX/bin/bursar" /usr/local/bin/bursar
echo "installed code to $PREFIX (root-owned, your user cannot change it)"

mkdir -p "$STATE"
chown $RUNAS:$RUNAS "$STATE"
chmod 700 "$STATE"
if [ ! -f "$STATE/key" ]; then
  sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" keygen --out "$STATE/key" >/dev/null
  echo "generated a new wallet key in $STATE/key (only $RUNAS can read it)"
fi

NEW_TOKEN=
if [ ! -f "$STATE/policy.yaml" ]; then
  [ -n "${PAY_TO:-}" ] || die 'first install needs PAY_TO=0x... (the address your test merchant is paid to)'
  echo "$PAY_TO" | grep -Eq '^0x[0-9a-fA-F]{40}$' || die "PAY_TO is not an EVM address: $PAY_TO"
  NEW_TOKEN=$(openssl rand -hex 24)
  sed -e "s/__AGENT_TOKEN__/$NEW_TOKEN/" -e "s/__PAY_TO__/$PAY_TO/" "$SRC/policy.testnet.example.yaml" > "$STATE/policy.yaml"
  chown root:$RUNAS "$STATE/policy.yaml"
  chmod 640 "$STATE/policy.yaml"
  echo "wrote $STATE/policy.yaml (root owns it, $RUNAS can only read it)"
fi
sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml" >/dev/null || die "policy check failed, fix $STATE/policy.yaml (sudo nano $STATE/policy.yaml)"

cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>$RUNAS</string>
  <key>GroupName</key><string>$RUNAS</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PREFIX/bin/node</string>
    <string>$PREFIX/app/src/index.ts</string>
    <string>serve</string>
    <string>--policy</string>
    <string>$STATE/policy.yaml</string>
  </array>
  <key>WorkingDirectory</key><string>$STATE</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>$STATE/bursar.log</string>
  <key>StandardErrorPath</key><string>$STATE/bursar.log</string>
</dict>
</plist>
PL
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootout system/$LABEL 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 2
echo
echo "daemon: launchctl print system/$LABEL | grep state"
sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml"
if [ -n "$NEW_TOKEN" ]; then
  echo
  echo "agent token for claude-code (shown once, it is also in $STATE/policy.yaml):"
  echo "  $NEW_TOKEN"
fi
