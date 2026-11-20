#!/bin/sh
# Builds network-scope-cli (and the GUI binary network-scope) twice from two exports of HEAD in
# different directories, each with a clean target folder, and compares the SHA-256 of the
# binaries: the check of the `reproducible` workflow, for a local machine (Linux, macOS, or Git
# Bash on Windows).
#
#   sh scripts/repro_check.sh [KEEP_DIR]
#   REPRO_BINS=network-scope-cli sh scripts/repro_check.sh   # only the command-line binary
#
# Needs a git checkout with HEAD committed (uncommitted changes are not built), tar and the
# toolchain of rust-toolchain.toml. The environment of both builds is scripts/repro_env.sh, the
# one release.yml uses. Takes two full release builds (some 7 minutes each on a fast machine).
# Both builds of each binary are kept in KEEP_DIR (default: ./repro-out) so that they can be compared with
# `cmp -l`, diffoscope or any PE/ELF tool. Exit code 0: identical, 1: different, 2: a build failed.
#
# On Windows keep the work folder path short (the default is under $TMPDIR or /tmp): the
# linker cannot open files whose path is longer than 260 characters, and cargo's build folder
# adds about 110. Set REPRO_WORK to a short folder (for example /c/r) if the build fails with
# LNK1104.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
keep=${1:-repro-out}
work=${REPRO_WORK:-$(mktemp -d)}
mkdir -p "$keep" "$work"
keep=$(cd "$keep" && pwd)

cd "$root"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
bins=${REPRO_BINS:-network-scope-cli network-scope}
exe=""
if command -v cygpath >/dev/null 2>&1; then exe=".exe"; fi

# Different depth and length on purpose: a build that depends on its location shows here.
dir1="$work/a/src"
dir2="$work/second-location/nested/copy"
mkdir -p "$dir1" "$dir2"
git archive HEAD | tar -x -C "$dir1"
git archive HEAD | tar -x -C "$dir2"

n=0
for dir in "$dir1" "$dir2"; do
  n=$((n + 1))
  # The directory as the compiler sees it: native path on Windows.
  native=$dir
  if command -v cygpath >/dev/null 2>&1; then native=$(cygpath -w "$dir"); fi
  env_lines="$(SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" sh "$here/repro_env.sh" "$native")"
  (
    while IFS= read -r line; do export "$line"; done <<EOF
$env_lines
EOF
    cd "$dir"
    flags=""
    for bin in $bins; do flags="$flags --bin $bin"; done
    # shellcheck disable=SC2086
    cargo build --release --locked $flags
  ) || { echo "build $n failed" >&2; exit 2; }
  for bin in $bins; do
    cp "$dir/target/release/$bin$exe" "$keep/$bin.$n$exe"
  done
done

if command -v sha256sum >/dev/null 2>&1; then
  sum() { sha256sum "$1" | cut -d' ' -f1; }
else
  sum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi
status=0
echo "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
for bin in $bins; do
  h1=$(sum "$keep/$bin.1$exe")
  h2=$(sum "$keep/$bin.2$exe")
  echo "$h1  $keep/$bin.1$exe"
  echo "$h2  $keep/$bin.2$exe"
  if [ "$h1" = "$h2" ]; then
    echo "$bin: both builds are identical."
  else
    echo "$bin: the builds differ ($(cmp -l "$keep/$bin.1$exe" "$keep/$bin.2$exe" | wc -l) bytes)." >&2
    status=1
  fi
done
if [ "$status" = 0 ]; then
  rm -rf "$work"
else
  echo "The work folder is kept: $work" >&2
fi
exit "$status"
