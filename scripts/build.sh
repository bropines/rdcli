#!/usr/bin/env bash
# Cross-builds rdcli archives into dist/: build.sh VERSION [TARGET...]
# (targets as os/arch; default: every release target), plus SHA256SUMS.
set -euo pipefail

version=${1:?usage: build.sh VERSION [os/arch...]}
shift
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(linux/amd64 linux/arm64 linux/arm darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 freebsd/amd64)
fi

rm -rf dist
mkdir dist
for t in "${targets[@]}"; do
  os=${t%/*}
  arch=${t#*/}
  ext=""
  [ "$os" = windows ] && ext=.exe
  name="rdcli-${version}-${os}-${arch}"
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/bropines/rdcli/internal/cli.Version=${version}" \
    -o "dist/$name/rdcli$ext" ./cmd/rdcli
  cp README.md LICENSE NOTICE "dist/$name/"
  if [ "$os" = windows ]; then
    (cd dist && zip -qr "$name.zip" "$name")
  else
    tar -C dist -czf "dist/$name.tar.gz" "$name"
  fi
  rm -rf "dist/$name"
done
(cd dist && sha256sum -- * > SHA256SUMS)
