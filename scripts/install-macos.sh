#!/bin/sh
set -eu

LABEL=dev.bursar.daemon
PREFIX=/opt/bursar
STATE=/var/db/bursar
RUNAS=_bursar
PLIST=/Library/LaunchDaemons/$LABEL.plist
SRC=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'run with sudo: sudo ./scripts/install-macos.sh'

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

# The daemon runs the official Node build pinned in node-release.sh, never the
# operator's own node (see that file for why).
. "$SRC/scripts/node-release.sh"
NODE_TMP=$(mktemp -d)
trap 'rm -rf "$NODE_TMP"' EXIT
NODE_DIR=$(fetch_node "$NODE_TMP")
echo "downloaded Node $NODE_VERSION (SHA-256 checked)"
if [ ! -d "$SRC/node_modules" ]; then
  # bursar-update: a fresh, root-owned checkout. Install from the lockfile and
  # never run package scripts as root.
  (cd "$SRC" && HOME="$NODE_TMP" npm_config_cache="$NODE_TMP/npm-cache" PATH="$NODE_DIR/bin:$PATH" \
    "$NODE_DIR/bin/npm" ci --ignore-scripts --no-audit --no-fund --loglevel=error) || die 'npm ci failed'
fi
[ -d "$SRC/node_modules/@noble/curves" ] || die "run npm ci in $SRC first"

rm -rf "$PREFIX.new"
mkdir -p "$PREFIX.new/bin" "$PREFIX.new/app"
install -m 755 "$NODE_DIR/bin/node" "$PREFIX.new/bin/node"
install -m 755 "$SRC/scripts/update.sh" "$PREFIX.new/bin/bursar-update"
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
ln -sf "$PREFIX/bin/bursar-update" /usr/local/bin/bursar-update
echo "installed code to $PREFIX (root-owned, your user cannot change it)"

# Record once, at the first install, where bursar-update fetches from and which
# keys must have signed what it installs. Root owns these; after this, a
# checkout your user can edit is never needed to update.
if [ ! -f /etc/bursar/update-repo ] && [ -n "${BURSAR_REPO_URL:-}" ] && [ -n "${BURSAR_ALLOWED_SIGNERS:-}" ]; then
  mkdir -p /etc/bursar
  printf '%s\n' "$BURSAR_REPO_URL" > /etc/bursar/update-repo
  printf '%s\n' "$BURSAR_ALLOWED_SIGNERS" > /etc/bursar/allowed_signers
  chown -R 0:0 /etc/bursar
  chmod 755 /etc/bursar
  chmod 644 /etc/bursar/update-repo /etc/bursar/allowed_signers
  echo "bursar-update will install only commits from $BURSAR_REPO_URL signed by:"
  sed 's/^/  /' /etc/bursar/allowed_signers
fi

mkdir -p "$STATE"
chown $RUNAS:$RUNAS "$STATE"
chmod 700 "$STATE"
if [ ! -f "$STATE/key" ]; then
  sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" keygen --out "$STATE/key" >/dev/null
  echo "generated a new wallet key in $STATE/key (only $RUNAS can read it)"
fi

NEW_TOKEN=
if [ "${POLICY_STDIN:-}" = 1 ]; then
  # `npm run setup` pipes the policy in (it already holds its own agent token),
  # so it never sits in a file the operator's user, and so an agent, could
  # rewrite while sudo asks for the password.
  if [ -f "$STATE/policy.yaml" ]; then
    [ "${REPLACE_POLICY:-}" = 1 ] || die "$STATE/policy.yaml exists; pass REPLACE_POLICY=1 to replace it"
    cp -p "$STATE/policy.yaml" "$STATE/policy.yaml.bak"
  fi
  NEW_POLICY="$NODE_TMP/policy.yaml"
  cat > "$NEW_POLICY"
  [ -s "$NEW_POLICY" ] || die "POLICY_STDIN=1 but no policy came in on stdin"
  install -o root -g $RUNAS -m 640 "$NEW_POLICY" "$STATE/policy.yaml"
  echo "wrote $STATE/policy.yaml from setup (root owns it, $RUNAS can only read it)"
elif [ ! -f "$STATE/policy.yaml" ]; then
  # The same policy `npm run setup` writes with its defaults (testnet, careful limits).
  # The token goes in through the environment, not a command line that ps shows.
  NEW_TOKEN=$("$PREFIX/bin/node" -e 'process.stdout.write(require("node:crypto").randomBytes(24).toString("hex"))')
  sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/setup.ts" --print-policy --yes \
    | BURSAR_NEW_TOKEN="$NEW_TOKEN" "$PREFIX/bin/node" -e '
        let s = "";
        process.stdin.on("data", (d) => (s += d)).on("end", () => {
          const p = "__AGENT_TOKEN_SET_BY_INSTALLER__";
          if (!s.includes(p)) process.exit(1);
          process.stdout.write(s.replace(p, process.env.BURSAR_NEW_TOKEN));
        });' > "$STATE/policy.yaml" || { rm -f "$STATE/policy.yaml"; die "could not write the default policy (npm run setup -- --print-policy --yes failed)"; }
  chown root:$RUNAS "$STATE/policy.yaml"
  chmod 640 "$STATE/policy.yaml"
  echo "wrote $STATE/policy.yaml (root owns it, $RUNAS can only read it)"
fi
if ! sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml" >/dev/null; then
  if [ "${POLICY_STDIN:-}" = 1 ] && [ -f "$STATE/policy.yaml.bak" ]; then
    mv "$STATE/policy.yaml.bak" "$STATE/policy.yaml"
    die "the new policy did not pass the check; the previous one is restored"
  fi
  die "policy check failed, fix $STATE/policy.yaml (sudo nano $STATE/policy.yaml)"
fi

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
# bootout returns before the old job is gone; bootstrapping too early fails
# with "5: Input/output error", so wait for it and retry a few times.
launchctl bootout system/$LABEL 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  launchctl print system/$LABEL >/dev/null 2>&1 || break
  sleep 1
done
loaded=
for _ in 1 2 3 4 5; do
  if launchctl bootstrap system "$PLIST" 2>/dev/null; then loaded=1; break; fi
  sleep 2
done
[ -n "$loaded" ] || launchctl bootstrap system "$PLIST" || die "launchd could not load $PLIST (see: sudo launchctl print system/$LABEL)"
sleep 2
echo
echo "daemon: launchctl print system/$LABEL | grep state"
sudo -u $RUNAS "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml"
if [ -n "$NEW_TOKEN" ]; then
  echo
  echo "agent token for claude-code (shown once, it is also in $STATE/policy.yaml):"
  echo "  $NEW_TOKEN"
fi
