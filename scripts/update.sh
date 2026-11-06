#!/bin/sh
# bursar-update: update an installed bursar from a signed commit, not from a
# checkout your user (and so an agent) can edit. Installed root-owned as
# /opt/bursar/bin/bursar-update; run it as `sudo bursar-update [ref]`.
#
# It clones the repository recorded at the first install, checks that the
# commit is signed by a key recorded then (/etc/bursar/allowed_signers, owned
# by root), and runs that commit's installer, which downloads the pinned
# official Node build and installs dependencies from the lockfile without
# running their scripts. Your policy, key and history are kept.
set -eu

CONF=/etc/bursar
REF=${1:-main}

die() { echo "bursar-update: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die 'run with sudo: sudo bursar-update [ref]'
[ -f "$CONF/update-repo" ] && [ -f "$CONF/allowed_signers" ] ||
  die "no trusted repository or signing key recorded in $CONF; see SETUP_GUIDE.md, section 10"
command -v git >/dev/null 2>&1 || die 'git is required'

REPO=$(cat "$CONF/update-repo")
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# Root's own git and npm settings only; nothing from the operator's home.
export HOME="$WORK" GIT_CONFIG_NOSYSTEM=1 npm_config_cache="$WORK/npm-cache"

echo "fetching $REPO ($REF)"
git clone --quiet --no-checkout "$REPO" "$WORK/src" || die "could not clone $REPO"
COMMIT=$(git -C "$WORK/src" rev-parse --verify --quiet "origin/$REF^{commit}" ||
  git -C "$WORK/src" rev-parse --verify --quiet "$REF^{commit}") || die "no commit or branch $REF in $REPO"
git -C "$WORK/src" -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$CONF/allowed_signers" \
  verify-commit "$COMMIT" 2>/dev/null ||
  die "commit $COMMIT is not signed by a key in $CONF/allowed_signers; not installing it"
git -C "$WORK/src" checkout --quiet --detach "$COMMIT"
echo "commit $COMMIT is signed by a trusted key"

case "$(uname -s)" in
  Darwin) INSTALLER=install-macos.sh ;;
  Linux) INSTALLER=install-linux.sh ;;
  *) die "unsupported system $(uname -s)" ;;
esac
sh "$WORK/src/scripts/$INSTALLER"
