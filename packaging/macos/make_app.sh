#!/bin/sh
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
# Assembles "Network Scope.app" around the GUI binary, so that Finder, the Dock and Launchpad
# show the application icon (assets/icon/network-scope.icns) and name:
#
#   sh packaging/macos/make_app.sh <network-scope binary> <version> <output folder>
#
# The bundle is unsigned; release.yml signs, notarizes and staples it. Used by the release
# (package-macos) and checked by the macOS CI job.
set -eu

binary=${1:?usage: make_app.sh <binary> <version> <output folder>}
version=${2:?usage: make_app.sh <binary> <version> <output folder>}
out=${3:?usage: make_app.sh <binary> <version> <output folder>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# CFBundleVersion and CFBundleShortVersionString take numbers only: "0.7.0-rc.1" -> "0.7.0".
numeric=${version%%-*}
app="$out/Network Scope.app"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
sed "s/@VERSION@/$numeric/g" "$here/Info.plist" > "$app/Contents/Info.plist"
printf 'APPL????' > "$app/Contents/PkgInfo"
cp "$binary" "$app/Contents/MacOS/network-scope"
chmod +x "$app/Contents/MacOS/network-scope"
cp "$root/assets/icon/network-scope.icns" "$app/Contents/Resources/network-scope.icns"
if command -v plutil >/dev/null 2>&1; then
  plutil -lint "$app/Contents/Info.plist"
fi
echo "$app"
