#!/bin/sh
# Installs bursar on Linux (systemd): the daemon runs as a system user `bursar`
# that cannot log in, the key and policy live in /var/lib/bursar (only that user
# can read the key, only root can change the policy) and the code in a
# root-owned /opt/bursar. An agent running as you can do neither.
#   sudo NODE="$(command -v node)" ./scripts/install-linux.sh
set -eu

UNIT=bursar
PREFIX=/opt/bursar
STATE=/var/lib/bursar
RUNAS=bursar
SERVICE=/etc/systemd/system/$UNIT.service
SRC=$(cd "$(dirname "$0")/.." && pwd)

die() { echo "install: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'run with sudo: sudo ./scripts/install-linux.sh'
[ -d /run/systemd/system ] || die 'systemd is not running (on WSL: add "[boot] systemd=true" to /etc/wsl.conf and run wsl --shutdown)'
command -v sudo >/dev/null 2>&1 || die 'sudo is required (the bursar command uses it to run as the bursar user)'

# Run a command as the daemon user.
as_bursar() {
  if command -v runuser >/dev/null 2>&1; then runuser -u $RUNAS -- "$@"; else sudo -u $RUNAS "$@"; fi
}

if ! getent passwd $RUNAS >/dev/null 2>&1; then
  NOLOGIN=/usr/sbin/nologin
  [ -x "$NOLOGIN" ] || NOLOGIN=/sbin/nologin
  [ -x "$NOLOGIN" ] || NOLOGIN=/bin/false
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" --comment 'bursar daemon' $RUNAS
  echo "created system user $RUNAS (uid $(id -u $RUNAS)), it cannot log in"
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
chown -R root:root "$PREFIX.new"
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
  as_bursar "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" keygen --out "$STATE/key" >/dev/null
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
  as_bursar "$PREFIX/bin/node" "$PREFIX/app/src/setup.ts" --print-policy --yes \
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
if ! as_bursar "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml" >/dev/null; then
  if [ "${POLICY_STDIN:-}" = 1 ] && [ -f "$STATE/policy.yaml.bak" ]; then
    mv "$STATE/policy.yaml.bak" "$STATE/policy.yaml"
    die "the new policy did not pass the check; the previous one is restored"
  fi
  die "policy check failed, fix $STATE/policy.yaml (sudo nano $STATE/policy.yaml)"
fi

# No MemoryDenyWriteExecute: V8 needs writable+executable pages for its JIT.
cat > "$SERVICE" <<UNITFILE
[Unit]
Description=bursar wallet daemon
After=network-online.target
Wants=network-online.target

[Service]
User=$RUNAS
Group=$RUNAS
ExecStart=$PREFIX/bin/node $PREFIX/app/src/index.ts serve --policy $STATE/policy.yaml
WorkingDirectory=$STATE
Restart=always
RestartSec=10
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=$STATE
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNITFILE
chown root:root "$SERVICE"
chmod 644 "$SERVICE"
systemctl daemon-reload
systemctl enable $UNIT >/dev/null 2>&1
systemctl restart $UNIT
sleep 2
echo
systemctl is-active --quiet $UNIT || die "the daemon did not start, see: journalctl -u $UNIT -n 50"
echo "daemon: systemctl status $UNIT (logs: journalctl -u $UNIT)"
as_bursar "$PREFIX/bin/node" "$PREFIX/app/src/index.ts" address --policy "$STATE/policy.yaml"
if [ -n "$NEW_TOKEN" ]; then
  echo
  echo "agent token for claude-code (shown once, it is also in $STATE/policy.yaml):"
  echo "  $NEW_TOKEN"
fi
