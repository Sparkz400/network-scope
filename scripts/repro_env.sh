#!/bin/sh
# Prints the environment of a reproducible release build as KEY=VALUE lines.
#
#   scripts/repro_env.sh <source-dir> >> "$GITHUB_ENV"                                   (workflow)
#   while IFS= read -r l; do export "$l"; done < <(scripts/repro_env.sh <source-dir>)    (bash)
#
# Run from a checkout of the repository: SOURCE_DATE_EPOCH is the commit time of HEAD there (kept
# if it is already set). <source-dir> is the directory cargo builds in, as the compiler sees it
# (on Windows the native path, e.g. "$GITHUB_WORKSPACE"); it is mapped to /build so the binary does
# not depend on where it was built. The rebuild-and-compare steps are in docs/src/supply-chain.md.
set -eu

src=${1:?usage: repro_env.sh <source-dir>}
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}
cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}

windows=false
if command -v cygpath >/dev/null 2>&1; then
  windows=true
  cargo_home=$(cygpath -w "$cargo_home")
  rustup_home=$(cygpath -w "$rustup_home")
fi

echo "SOURCE_DATE_EPOCH=$epoch"
echo "CARGO_INCREMENTAL=0"
echo "TZ=UTC"
echo "RUSTFLAGS=${RUSTFLAGS:-} --remap-path-prefix=$src=/build --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"
# The bundled C code (SQLite, ring) embeds __FILE__ paths; MSVC has no -ffile-prefix-map.
if [ "$windows" = false ]; then
  echo "CFLAGS=${CFLAGS:-} -ffile-prefix-map=$src=/build -ffile-prefix-map=$cargo_home=/cargo"
fi
