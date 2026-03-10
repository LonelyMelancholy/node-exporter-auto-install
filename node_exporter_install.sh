#!/bin/bash

[ "$1" != install_from_script ] && { echo "❌ Error: run only from node_cert_install"; exit 1; }

# root check
[[ $EUID -ne 0 ]] && { echo "❌ Error: you are not the root user, exit"; exit 1; }

# check another instanse of the script is not running
readonly LOCK_FILE="/run/lock/node_exporter_install.lock"
exec {fd}> "$LOCK_FILE" || { echo "❌ Error: cannot open lock file '$LOCK_FILE', exit"; exit 1; }
flock -n "$fd" || { echo "❌ Error: another instance is running, exit"; exit 1; }

# changing directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "❌ Error: couldn't change working directory, exit"; exit 1; }

# shellcheck disable=SC1091
source "node_name.cfg"

# main variables
LATEST_TAG=$(curl -Ls -o /dev/null -w '%{url_effective}' \
    "https://github.com/prometheus/node_exporter/releases/latest" \
    | awk -F'/tag/' '{print $2}')
OS_ARCH="linux-amd64"
NODE_EXPORTER_FILE="node_exporter-${LATEST_TAG#v}.${OS_ARCH}.tar.gz"
SHA256SUM_FILE="sha256sums.txt"
NODE_EXPORTER_URL="https://github.com/prometheus/node_exporter/releases/latest/download/"
MAX_ATTEMPTS=3
umask 022

# exit cleanup and log message function
# shellcheck disable=SC2329
exit_cleanup() {
    if rm -rf "$SCRIPT_DIR"; then
        echo "Success: delete tmp files"
    else
        echo "Error: delete tmp files"
    fi
}

# set trap for exit cleanup
trap 'exit_cleanup;' EXIT

# helper function
run_and_check() {
    local action="$1"
    shift 1
    if "$@" > /dev/null; then
        echo "✅ Success: $action"
    else
        echo "❌ Error: $action, exit"
        exit 1
    fi
}

# create user with check existense
node_exporter_user_add() { useradd -r -M -d /nonexistent -s /usr/sbin/nologin node_exporter || return 1; }
if ! getent passwd node_exporter &> /dev/null; then
    run_and_check "adding node_exporter user" node_exporter_user_add
else
    echo "✅ Success: user node_exporter already exist"
fi

# download function
_dl() { curl -fsSL -m 60 "$1" -o "$2"; }

_dl_with_retry() {
    local url="$1"
    local outfile="$2"
    local label="$3"
    local attempt=1

    while true; do
        echo "📢 Info: download ${label}, attempt ${attempt}, please wait"
        if ! _dl "$url" "$outfile"; then
            if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
                echo "❌ Error: download ${label} after ${attempt} attempts, exit"
                return 1
            fi
            sleep 60
            ((attempt++))
            continue
        else
            echo "✅ Success: download ${label} after ${attempt} attempts"
            return 0
        fi
    done
}

# download and check checksum function
download_and_verify() {
    local url="$1"
    local outfile="$2"
    local name="$3"
    local sha256sum_file="${outfile}.sha256sum"
    local expected_sha actual_sha

    # download main file
    _dl_with_retry "${url}${NODE_EXPORTER_FILE}" "$outfile" "$name" || exit 1

    # download checksum
    _dl_with_retry "${url}${SHA256SUM_FILE}" "$sha256sum_file" "${name}.sha256sum" || exit 1

    # reset sha
    expected_sha=""
    # extract sha256sum from sha256sum_file
    expected_sha="$(awk '/linux-amd64.tar.gz/ {print $1}' "$sha256sum_file")"
    if [ -z "$expected_sha" ]; then
        echo "❌ Error: parse SHA256 from ${sha256sum_file}, exit"
        exit 1
    else
        echo "✅ Success: parse SHA256 from ${sha256sum_file}"
    fi

    # extract actual sha256sum from .zip or .dat
    # reset sha
    actual_sha=""
    actual_sha="$(sha256sum "$outfile" 2>/dev/null | awk '{print $1}')"
    if [ -z "$actual_sha" ]; then
        echo "❌ Error: extract SHA256 from ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: extraction SHA256 from ${outfile}"
    fi

    # compare sha256sum checksum
    if [ "$expected_sha" != "$actual_sha" ]; then
        echo "📢 Info: expected SHA256 from '.sha256sum': $expected_sha"
        echo "📢 Info: actual SHA256 from '.tar.gz': $actual_sha"
        echo "❌ Error: compare, actual and expected SHA256 do not match for ${name}, exit"
        exit 1
    else
        echo "📢 Info: expected SHA256 from '.sha256sum': $expected_sha"
        echo "📢 Info: actual SHA256 from '.tar.gz': $actual_sha"
        echo "✅ Success: actual and expected SHA256 match for ${name}"
    fi

    # unpack archive
    if ! tar -xzf "$outfile" -C . &> /dev/null; then
        echo "❌ Error: extract ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: ${outfile} successfully extracted"
    fi
    # check node exporter binary
    if [ ! -f "node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" ]; then
        echo "❌ Error: node exporter binary is missing from folder after unpacking ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: node exporter binary exists in the folder after unpacking ${outfile}"
    fi

    return 0
}

download_and_verify "$NODE_EXPORTER_URL" "node_exporter.tar.gz" "node_exporter"

# make all directory for install bin and settings
mkdir -p "/usr/local/bin/service"
mkdir -p "/usr/local/lib/service"
mkdir -p /usr/local/etc/telegram
mkdir -p /usr/local/etc/node_exporter/tls

install -m 640 -o root -g node_exporter "ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
install -m 640 -o root -g node_exporter "${NODE}.crt" "/usr/local/etc/node_exporter/tls/${NODE}.crt"
install -m 640 -o root -g node_exporter "${NODE}.key" "/usr/local/etc/node_exporter/tls/${NODE}.key"
install -m 755 -o root -g root "node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" "/usr/local/bin/node_exporter"
install -m 755 -o root -g root "node_exporter_update.sh" "/usr/local/bin/service/node_exporter_update.sh"

# create user with check existense
telegram_gateway_user_add() { useradd -r -M -d /nonexistent -s /usr/sbin/nologin telegram_gateway || return 1; }
if ! getent passwd telegram_gateway &> /dev/null; then
    run_and_check "adding telegram_gateway user" telegram_gateway_user_add
else
    echo "✅ Success: user telegram_gateway already exist"
fi

if [[ -f "/usr/local/etc/telegram/secrets.env" ]]; then
    echo "✅ Success: Telegram secrets already installed"
else
    install -m 640 -g telegram_gateway -o root "secrets.env" "/usr/local/etc/telegram/secrets.env"
fi

if [[ -f "/usr/local/lib/service/telegram.lib.sh" ]]; then
    echo "✅ Success: Telegram library already installed"
else
    install -m 644 -g root -o root "telegram.lib.sh" "/usr/local/lib/service/telegram.lib.sh"
fi

# web-config
tee /usr/local/etc/node_exporter/mtls_auth.yml > /dev/null <<EOF
tls_server_config:
    cert_file: /usr/local/etc/node_exporter/tls/${NODE}.crt
    key_file:  /usr/local/etc/node_exporter/tls/${NODE}.key

    client_auth_type: RequireAndVerifyClientCert
    client_ca_file: /usr/local/etc/node_exporter/tls/ca.crt

    min_version: TLS13
EOF

# install node exporter systemd daemon
install -m 644 -o root -g root "node_exporter.service" "/etc/systemd/system/node_exporter.service"

# install node exporter updater systemd daemon and timer
install -m 644 -o root -g root "node_exporter_update.service" "/etc/systemd/system/node_exporter_update.service"
install -m 644 -o root -g root "node_exporter_update.timer" "/etc/systemd/system/node_exporter_update.timer"

# run all daemon
systemctl daemon-reload
systemctl enable -q --now node_exporter.service
systemctl enable -q --now node_exporter_update.timer
