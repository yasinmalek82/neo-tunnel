#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C
version=v0.2.0
release="https://github.com/yasinmalek82/neo-tunnel/releases/download/$version"
if (( EUID != 0 )); then
    printf 'Run this installer as root or use sudo.\n' >&2
    exit 1
fi
if [[ $(uname -s) != Linux || ! -r /sys/fs/cgroup/cgroup.controllers ]] ||
   ! command -v systemctl >/dev/null || ! systemctl show -p SystemState --value >/dev/null 2>&1; then
    printf 'Linux with a running systemd and cgroup v2 is required.\n' >&2
    exit 1
fi
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    debian:12|debian:13|ubuntu:24.04|ubuntu:26.04|ubuntu:26.10) ;;
    *) printf 'Supported systems: Debian 12/13 and Ubuntu 24.04/26.04/26.10.\n' >&2; exit 1 ;;
esac
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) printf 'Supported architectures: amd64 and arm64.\n' >&2; exit 1 ;;
esac
bundle=
action=menu
while (( $# )); do
    case "$1" in
        --bundle)
            if (( $# < 2 )); then printf 'Missing bundle directory.\n' >&2; exit 2; fi
            bundle=$2
            shift 2;;
        --join-stdin) action=join; shift;;
        --install-only) action=none; shift;;
        *) printf 'Usage: install.sh [--bundle DIRECTORY] [--join-stdin | --install-only]\n' >&2; exit 2;;
    esac
done
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
archive="neo-tunnel-$version-linux-$arch.tar.gz"
if [[ -n $bundle ]]; then
    cp -- "$bundle/$archive" "$bundle/SHA256SUMS" "$tmp/"
else
    command -v curl >/dev/null || { printf 'Install curl or pass --bundle.\n' >&2; exit 1; }
    for name in "$archive" SHA256SUMS; do
        curl --fail --silent --show-error --location --proto '=https' --retry 2 --connect-timeout 10 --max-time 300 "$release/$name" -o "$tmp/$name"
    done
fi
(
    cd "$tmp"
    awk -v name="$archive" '$2 == name { print; count++ } END { if(count != 1) exit 1 }' SHA256SUMS > selected.sha256
    sha256sum -c selected.sha256
    tar --no-same-owner --no-same-permissions -xzf "$archive"
)
tree="$tmp/neo-tunnel"
for bin in neo-tunnel backhaul-probe frpc frps haproxy; do
    test -x "$tree/bin/$bin"
done
if ! getent group neo >/dev/null; then groupadd --system neo; fi
if ! id neo >/dev/null 2>&1; then
    useradd --system --gid neo --no-create-home --shell /usr/sbin/nologin neo
fi
install -d -m 0755 /usr/local/bin /usr/local/libexec/neo-tunnel /usr/local/share/neo-tunnel /etc/systemd/system
put() {
    local mode=$1 source=$2 target=$3 staged
    if [[ -f $target ]] && cmp -s -- "$source" "$target"; then return 0; fi
    staged=$(mktemp "$(dirname "$target")/.neo-install-XXXXXX")
    if install -m "$mode" -- "$source" "$staged" && mv -fT -- "$staged" "$target"; then return 0; fi
    rm -f -- "$staged"
    return 1
}
# Preflight collisions before touching executable paths. Existing wizard installs are idempotent.
receipt=/usr/local/share/neo-tunnel/install-version
if [[ -f $receipt ]] && [[ $(cat "$receipt") != "$version" ]]; then
    printf 'A different managed version is installed. Use a clean pilot host for this release.\n' >&2
    exit 1
fi
if [[ ! -f $receipt ]]; then
    for bin in /usr/local/bin/neo-tunnel /usr/local/bin/backhaul-probe /usr/local/libexec/neo-frp-run; do
        if [[ -e $bin ]]; then printf 'An unmanaged file exists at %s.\n' "$bin" >&2; exit 1; fi
    done
    for file in "$tree"/systemd/*; do
        if [[ -e /etc/systemd/system/${file##*/} ]]; then printf 'An unmanaged NEO service already exists.\n' >&2; exit 1; fi
    done
fi
# Record the version before copying so rerunning a partial install can complete it.
printf '%s\n' "$version" > "$tmp/version"
put 0644 "$tmp/version" "$receipt"
for bin in neo-tunnel backhaul-probe; do put 0755 "$tree/bin/$bin" "/usr/local/bin/$bin"; done
for bin in frpc frps haproxy; do put 0755 "$tree/bin/$bin" "/usr/local/libexec/neo-tunnel/$bin"; done
put 0755 "$tree/frp-run" /usr/local/libexec/neo-frp-run
for file in "$tree"/templates/*; do put 0644 "$file" "/usr/local/share/neo-tunnel/${file##*/}"; done
for file in "$tree"/systemd/*; do put 0644 "$file" "/etc/systemd/system/${file##*/}"; done
systemctl daemon-reload
case "$action" in
    join) /usr/local/bin/neo-tunnel join ;;
    menu) /usr/local/bin/neo-tunnel ;;
esac
