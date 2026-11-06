# Sourced by the installers and by bursar-update. Never use the operator's own
# `node`: it can sit in a folder their user (and so an agent) can write, and a
# Homebrew or Linuxbrew build loads libraries from such folders every time the
# daemon starts. The daemon gets the official build instead, checked against
# a SHA-256 pinned here (and so covered by the signature on this commit).
NODE_VERSION=v22.23.4

node_sha256() {
  case "$1" in
    darwin-arm64) echo c9e1dbc748b33ed2d14f42445191ecaf14c56259c7a9a26d0042c49ec2b66428 ;;
    darwin-x64) echo efcc2b0db6f94bf53eddb038fe2b370277a042bd29e4f19b8f8e23598795b819 ;;
    linux-arm64) echo f7a1e486dbc8b286847815b477d4fb5e9fb963ed4489c3e1588853d685f589f9 ;;
    linux-x64) echo b8492284c76a54baf58d61668dd0e41ee0fc98adabf9503d30f05d08f55b4406 ;;
    *) return 1 ;;
  esac
}

# fetch_node <dir>: download and verify the pinned build into <dir>, print the
# folder holding bin/node and bin/npm.
fetch_node() {
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) platform=darwin-arm64 ;;
    Darwin-x86_64) platform=darwin-x64 ;;
    Linux-x86_64) platform=linux-x64 ;;
    Linux-aarch64 | Linux-arm64) platform=linux-arm64 ;;
    *) die "no pinned Node build for $(uname -s) $(uname -m)" ;;
  esac
  want=$(node_sha256 "$platform")
  name="node-$NODE_VERSION-$platform"
  url="https://nodejs.org/dist/$NODE_VERSION/$name.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$1/$name.tar.gz" "$url" || die "could not download $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$1/$name.tar.gz" "$url" || die "could not download $url"
  else
    die "curl or wget is needed to download Node"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$1/$name.tar.gz")
  else
    got=$(shasum -a 256 "$1/$name.tar.gz")
  fi
  [ "${got%% *}" = "$want" ] || die "$name.tar.gz does not match its pinned SHA-256; not installing it"
  tar -xzf "$1/$name.tar.gz" -C "$1"
  echo "$1/$name"
}
