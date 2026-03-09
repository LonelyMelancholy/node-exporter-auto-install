#!/bin/bash

# root checking
[[ $EUID -ne 0 ]] && { echo "❌ Error: you are not the root user, exit"; exit 1; }

# check another instanse of the script is not running
readonly LOCK_FILE="/run/lock/node_cert_install.lock"
exec {fd}> "$LOCK_FILE" || { echo "❌ Error: cannot open lock file '$LOCK_FILE', exit"; exit 1; }
flock -n "$fd" || { echo "❌ Error: another instance is running, exit"; exit 1; }

# changing directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "❌ Error: couldn't change working directory, exit"; exit 1; }

umask 022

# create working directory
TMP_DIR="$(mktemp -d)" || { echo "❌ Error: failed to create temporary directory, exit"; exit 1; }
readonly TMP_DIR

# exit cleanup and log message function
# shellcheck disable=SC2329
exit_cleanup() {
    if rm -rf "$TMP_DIR"; then
        echo "✅ Success: delete tmp files"
    else
        echo "❌ Error: delete tmp files"
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

read -rp "This script need to start on Prometheus node and have NODE_NAME.key privat key for node in /root/.ssh folder, yes if you agree: " AGREE

[[ $AGREE =~ ^[Yy][Ee][Ss]$ ]] || exit 0

read -rp "Type node domain address, for self monitoring type localhost or $(hostname).local: " NODE
[[ "$NODE" == "$(hostname).local" ]] && NODE=localhost

if [[ "$NODE" != "localhost" ]]; then
    read -rp "Type ssh node port: " PORT
    read -rp "Type node user: " NODE_USER
    ssh_key="/root/.ssh/${NODE}.key"
    [[ -f "$ssh_key" ]] || { echo "❌ Error: ssh key '$ssh_key' not found, exit!"; exit 1; }
fi
read -rp "First install? yes or no: " FIRST_INSTALL

# if first install == yes, install updater and other files
if [[ $FIRST_INSTALL =~ ^[Yy][Ee][Ss]$ ]]; then

    # check cert for decide this first install or not
    [[ -f "/etc/prometheus/ca.key" ]] && \
    { echo "❌ Error: found prometheus certificates, this not first install, check all the information you entered again, exit!"; exit 1; }

    mkdir -p "/usr/local/lib/service"
    mkdir -p "/usr/local/bin/service"
    mkdir -p /usr/local/etc/telegram
    mkdir -p /usr/local/etc/node_cert_update
    
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
        install -m 640 -g telegram_gateway -o root "cfg/secrets.env" "/usr/local/etc/telegram/secrets.env"
    fi

    if [[ -f "/usr/local/lib/service/telegram.lib.sh" ]]; then
        echo "✅ Success: Telegram library already installed"
    else
        install -m 644 -g root -o root "share/telegram.lib.sh" "/usr/local/lib/service/telegram.lib.sh"
    fi

    # install script for update and list nodes
    install -m 750 -g root -o root "node_cert_update.sh" "/usr/local/bin/service/node_cert_update.sh"
    install -m 640 -g root -o root "cfg/node_list.cfg" "/usr/local/etc/node_cert_update/node_list.cfg"

    # install update unit and timer
    install -m 644 -g root -o root "cfg/node_cert_update.service" "/etc/systemd/system/node_cert_update.service"
    install -m 644 -g root -o root "cfg/node_cert_update.timer" "/etc/systemd/system/node_cert_update.timer"

    systemctl daemon-reload
    systemctl enable -q --now node_cert_update.timer

    # generation Certificate Autority private key
    openssl genrsa -out "${TMP_DIR}/ca.key" 4096

    # generation Certificate Autority public sert
    openssl req -x509 -new -nodes -key "${TMP_DIR}/ca.key" -sha256 -days 455 -out "${TMP_DIR}/ca.crt" -subj "/CN=metrics-mtls-ca"

    # generate prometheus private sert
    openssl genrsa -out "${TMP_DIR}/prometheus_client.key" 2048

    # generate prometheus public sert
    openssl req -new -key "${TMP_DIR}/prometheus_client.key" -out "${TMP_DIR}/prometheus_client.crt" \
        -subj "/CN=prometheus"

    # make cfg for signature
    tee "${TMP_DIR}/prometheus_client.ext" > /dev/null <<'EOF'
[ v3_req ]
extendedKeyUsage = clientAuth
EOF

    # signature prometheus sertificate
    openssl x509 -req -in "${TMP_DIR}/prometheus_client.crt" -CA "${TMP_DIR}/ca.crt" -CAkey "${TMP_DIR}/ca.key" -CAcreateserial \
        -out "${TMP_DIR}/prometheus_client.crt" -days 45 -sha256 -extfile "${TMP_DIR}/prometheus_client.ext" -extensions v3_req

    install -m 640 -o root -g prometheus   "${TMP_DIR}/prometheus_client.crt"   "/etc/prometheus/prometheus_client.crt"
    install -m 640 -o root -g prometheus   "${TMP_DIR}/prometheus_client.key"   "/etc/prometheus/prometheus_client.key"
    install -m 640 -o root -g prometheus   "${TMP_DIR}/ca.crt"                  "/etc/prometheus/ca.crt"
    install -m 600 -o root -g root         "${TMP_DIR}/ca.key"                  "/etc/prometheus/ca.key"
fi

# generation private key for node
openssl genrsa -out "${TMP_DIR}/${NODE}.key" 2048

# generation public key for node
openssl req -new -key "${TMP_DIR}/${NODE}.key" -out "${TMP_DIR}/${NODE}.crt" -subj "/CN=${NODE}"

# make cfg for signature
tee "${TMP_DIR}/${NODE}.ext" > /dev/null <<EOF
[ v3_req ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${NODE}
EOF

# signature node sertificate
openssl x509 -req -in "${TMP_DIR}/${NODE}.crt" -CA "${TMP_DIR}/ca.crt" -CAkey "${TMP_DIR}/ca.key" -CAcreateserial \
  -out "${TMP_DIR}/${NODE}.crt" -days 45 -sha256 -extfile "${TMP_DIR}/${NODE}.ext" -extensions v3_req

tee "cfg/node_name.cfg" > /dev/null <<EOF
# file for transfer node name to remote host
# source in node_exporter_install
NODE="${NODE}"
EOF

if [[ "$NODE" == "localhost" ]]; then
    cp "node_exporter_install.sh" "cfg/node_exporter.service" "node_exporter_update.sh" "cfg/node_exporter_update.service" "cfg/node_exporter_update.timer" "cfg/node_name.cfg" "${TMP_DIR}/"
    cd "${TMP_DIR}" || exit 1
    bash node_exporter_install.sh
else
    REMOTE_TMP_DIR=$(ssh -o StrictHostKeyChecking=accept-new -p "${PORT}" -o BatchMode=yes -i "$ssh_key" "${NODE_USER}@${NODE}" 'mktemp -d')
    scp -P "${PORT}" -o BatchMode=yes -i "$ssh_key" "${TMP_DIR}/${NODE}.key" "${TMP_DIR}/${NODE}.crt" \
    "/etc/prometheus/ca.crt" "node_exporter_install.sh" "cfg/node_exporter.service" "node_exporter_update.sh" \
    "cfg/node_exporter_update.service" "cfg/node_exporter_update.timer" "cfg/node_name.cfg" "${NODE_USER}@${NODE}:${REMOTE_TMP_DIR}"
    ssh -p "${PORT}" -i "$ssh_key" "${NODE_USER}@${NODE}" "cd '${REMOTE_TMP_DIR}'; sudo -n bash node_exporter_install.sh"
fi

if ! grep -q "job_name: ${NODE}" /etc/prometheus/prometheus.yml; then
tee -a /etc/prometheus/prometheus.yml > /dev/null <<EOF
  - job_name: ${NODE}
    scheme: https
    static_configs:
      - targets: ["${NODE}:9100"]
    tls_config:
      ca_file: /etc/prometheus/ca.crt
      cert_file: /etc/prometheus/prometheus_client.crt
      key_file: /etc/prometheus/prometheus_client.key
      server_name: ${NODE}
      insecure_skip_verify: false
EOF
fi

# need to check resolve this section for prometheus .local domain
#if [[ ${NODE} != localhost ]] && ! grep -q "${NODE}" /etc/hosts; then
#    IP_NODE="$(getent hosts "${NODE}")"
#    if grep "${NODE}" "/etc/hosts"; then
#        echo "${NODE} already in /etc/hosts"
#    else
#        tee -a /etc/hosts > /dev/null <<EOF
#$IP_NODE
#EOF
#        echo "Add ${NODE} in /etc/hosts"
#    fi
#fi

systemctl restart prometheus.service

if [[ "$NODE" != "localhost" ]] && ! grep -q "${NODE}" /usr/local/etc/node_cert_update/node_list.cfg; then
    tee -a /usr/local/etc/node_cert_update/node_list.cfg > /dev/null <<EOF
${NODE} ${PORT} ${NODE_USER}
EOF
fi
