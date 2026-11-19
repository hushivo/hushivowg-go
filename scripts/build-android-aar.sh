#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mobile_version=v0.0.0-20261117202452-47699113848a
hushivo_tools_dir="$(pwd)/.tools/android-mobile"
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.1.12297006}"
[[ -d "$ANDROID_NDK_HOME" ]] || { echo "Android NDK not found: $ANDROID_NDK_HOME" >&2; exit 1; }
mkdir -p "$hushivo_tools_dir" ../hushivo-app/modules/hushivo-vpn/android/libs
GOBIN="$hushivo_tools_dir" go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
GOBIN="$hushivo_tools_dir" go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
export PATH="$hushivo_tools_dir:$PATH"
gomobile init
(cd mobile && go mod tidy && gomobile bind -target=android -androidapi=24 -javapkg=com.hushivo -o ../../hushivo-app/modules/hushivo-vpn/android/libs/hushivowg.aar .)
echo 'Android AAR: hushivo-app/modules/hushivo-vpn/android/libs/hushivowg.aar'
