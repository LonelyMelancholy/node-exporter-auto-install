#!/bin/bash

# root checking
if [[ $EUID -ne 0 ]]; then
    echo "❌ Error: you are not the root user, exit"
    exit 1
else
    echo "✅ Success: you are root user, continued"
fi

# check another instanse of the script is not running
readonly LOCK_FILE="/run/lock/node_exporter_install.lock"
exec 9> "$LOCK_FILE" || { echo "❌ Error: cannot open lock file '$LOCK_FILE', exit"; exit 1; }
flock -n 9 || { echo "❌ Error: another instance is running, exit"; exit 1; }

# changing directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "❌ Error: couldn't change working directory, exit"; exit 1; }

source "node_name.cfg"

# helper function
run_and_check() {
    action="$1"
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
    run_and_check "adding node exporter user" node_exporter_user_add
else
    echo "✅ Success: user node_exporter already exist"
fi

# main variables
LATEST_TAG=$(curl -Ls -o /dev/null -w '%{url_effective}' \
    "https://github.com/prometheus/node_exporter/releases/latest" \
    | awk -F'/tag/' '{print $2}')
OS_ARCH="linux-amd64"
NODE_EXPORTER_FILE="node_exporter-${LATEST_TAG#v}.${OS_ARCH}.tar.gz"
SHA256SUM_FILE="sha256sums.txt"
NODE_EXPORTER_URL="https://github.com/prometheus/node_exporter/releases/latest/download/"
TMP_DIR=$(mktemp -d)
MAX_ATTEMPTS=3

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
            (($attempt++))
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
    UNPACK_DIR="$TMP_DIR"

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

    local expected_label actual_label
    # compare sha256sum checksum
        expected_label=".sha256sum"
        actual_label=".tar.gz"

    if [ "$expected_sha" != "$actual_sha" ]; then
        echo "📢 Info: expected SHA256 from ${expected_label}: $expected_sha"
        echo "📢 Info: actual SHA256 from ${actual_label}: $actual_sha"
        echo "❌ Error: compare, actual and expected SHA256 do not match for ${name}, exit"
        exit 1
    else
        echo "📢 Info: expected SHA256 from ${expected_label}: $expected_sha"
        echo "📢 Info: actual SHA256 from ${actual_label}: $actual_sha"
        echo "✅ Success: actual and expected SHA256 match for ${name}"
    fi

    # unpack archive
    if ! mkdir -p "$UNPACK_DIR"; then
        echo "❌ Error: create directory for unpacking ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: directory for unpacking ${outfile} has been created"
    fi
    if ! tar -xzf "$outfile" -C "$UNPACK_DIR" &> /dev/null; then
        echo "❌ Error: extract ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: ${outfile} successfully extracted"
    fi
    # check xray binary
    if [ ! -f "$UNPACK_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" ]; then
        echo "❌ Error: node exporter binary is missing from folder after unpacking ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: node exporter binary exists in the folder after unpacking ${outfile}"
    fi

    return 0
}

download_and_verify "$NODE_EXPORTER_URL" "$TMP_DIR/node_exporter.tar.gz" "node_exporter"

# Копируем в директорию к бинарникам
install -m 755 -o root -g root "$UNPACK_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" "/usr/local/bin/node_exporter"
mkdir -p /usr/local/etc/node_exporter/tls

# web-config
tee /usr/local/etc/node_exporter/mtls_auth.yml > /dev/null <<EOF
tls_server_config:
    cert_file: /usr/local/etc/node_exporter/tls/${NODE}.crt
    key_file:  /usr/local/etc/node_exporter/tls/${NODE}.key

    client_auth_type: RequireAndVerifyClientCert
    client_ca_file: /usr/local/etc/node_exporter/tls/ca.crt

    min_version: TLS13
EOF

# create systemd daemon
tee /etc/systemd/system/node_exporter.service > /dev/null <<'EOF'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
    --web.listen-address=":9100" \
    --web.config.file=/usr/local/etc/node_exporter/mtls_auth.yml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

chown -R node_exporter:node_exporter /usr/local/etc/node_exporter/
chmod 755 -R /usr/local/etc/node_exporter/
chmod 750 /usr/local/etc/node_exporter/tls/

install -m 640 -o node_exporter -g node_exporter "ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
install -m 640 -o node_exporter -g node_exporter "${NODE}.crt" "/usr/local/etc/node_exporter/tls/${NODE}.crt"
install -m 600 -o node_exporter -g node_exporter "${NODE}.key" "/usr/local/etc/node_exporter/tls/${NODE}.key"

# run after generation sert
systemctl daemon-reload
systemctl enable --now node_exporter.service