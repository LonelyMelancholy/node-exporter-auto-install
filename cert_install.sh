#!/bin/bash

# root checking
[[ $EUID -ne 0 ]] && { echo "❌ Error: you are not the root user, exit"; exit 1; }

LOCAL="$(hostname).local"
read -rp "This script need to start on Prometheus node and have NODE_NAME.key privat key for node in /root/.ssh folder, yes if you agree: " AGREE

[[ $AGREE =~ ^([yY]es)$ ]] || exit 0

read -rp "Type node address, for self monitoring type localhost: " NODE
if [[ "$NODE" == "$LOCAL" ]]; then
    NODE=localhost
fi
if [[ "$NODE" != "localhost" ]]; then
    read -rp "Type node port: " PORT
    read -rp "Type node user: " NODE_USER
fi
read -rp "First install? yes or no: " FIRST_INSTALL

if [[ $FIRST_INSTALL =~ ^([yY]es)$ ]]; then

mkdir -p "/var/log/service"
install -m 600 -g root -o root secrets.env /usr/local/etc/telegram/secrets.env

ssh_key="/root/.ssh/${NODE}.ssh_key"

install -m 755 -g root -o root "cert_update.sh" "/usr/local/bin/cert_update.sh"

install -m 644 -g root -o root "cert_update.cfg" "/usr/local/etc/cert_update.cfg"

tee /etc/systemd/system/node_cert_updater.service > /dev/null <<EOF
[Unit]
Description=Updater for node exporter and prometheus sert

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cert_update.sh
EOF

tee /etc/systemd/system/node_cert_updater.timer > /dev/null <<EOF
[Unit]
Description=Daily random timer 01:00-05:00 for node exporter and prometheus sert updater

[Timer]
OnCalendar=*-*-* 01:00:00
RandomizedDelaySec=4h
Persistent=true
Unit=node_cert_updater.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now node_cert_updater.timer

# generation Certificate Autority private key
openssl genrsa -out "/etc/prometheus/ca.key" 4096

# generation Certificate Autority public sert
openssl req -x509 -new -nodes -key "/etc/prometheus/ca.key" -sha256 -days 455 -out "/etc/prometheus/ca.crt" -subj "/CN=metrics-mtls-ca"

# generate prometheus private sert
openssl genrsa -out "/etc/prometheus/prometheus_client.key" 2048

# generate prometheus public sert
openssl req -new -key "/etc/prometheus/prometheus_client.key" -out "/etc/prometheus/prometheus_client.crt" \
  -subj "/CN=prometheus"

# make cfg for signature
tee "/etc/prometheus/prometheus_client.ext" > /dev/null <<'EOF'
[ v3_req ]
extendedKeyUsage = clientAuth
EOF

# signature prometheus sertificate
openssl x509 -req -in /etc/prometheus/prometheus_client.crt -CA /etc/prometheus/ca.crt -CAkey /etc/prometheus/ca.key -CAcreateserial \
  -out /etc/prometheus/prometheus_client.crt -days 45 -sha256 -extfile /etc/prometheus/prometheus_client.ext -extensions v3_req

chown -R prometheus:prometheus /etc/prometheus/
chmod 750 /etc/prometheus/
chmod 640 /etc/prometheus/prometheus_client.crt
chmod 640 /etc/prometheus/ca.crt
chmod 600 /etc/prometheus/prometheus_client.key
chmod 600 /etc/prometheus/ca.key
fi

# generation private key for node
openssl genrsa -out "/etc/prometheus/${NODE}.key" 2048

# generation public key for node
openssl req -new -key "/etc/prometheus/${NODE}.key" -out "/etc/prometheus/${NODE}.crt" -subj "/CN=${NODE}"

# make cfg for signature
tee "/etc/prometheus/${NODE}.ext" > /dev/null <<EOF
[ v3_req ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${NODE}
EOF

# signature node sertificate
openssl x509 -req -in "/etc/prometheus/${NODE}.crt" -CA "/etc/prometheus/ca.crt" -CAkey "/etc/prometheus/ca.key" -CAcreateserial \
  -out "/etc/prometheus/${NODE}.crt" -days 45 -sha256 -extfile "/etc/prometheus/${NODE}.ext" -extensions v3_req

tee node_name.cfg > /dev/null <<EOF
NODE="${NODE}"
EOF

if [[ "$NODE" == "localhost" ]]; then
    TEMP_DIR="$(mktemp -d)"
    cp "/etc/prometheus/${NODE}.key" "/etc/prometheus/${NODE}.crt" "/etc/prometheus/ca.crt" "node_exporter_install.sh" "node_name.cfg" "${TEMP_DIR}/"
    cd "$TEMP_DIR" || exit 1
    bash node_exporter_install.sh
else
    TEMP_DIR=$(ssh -o StrictHostKeyChecking=accept-new -p "${PORT}" -o BatchMode=yes -i "$ssh_key" "${NODE_USER}@${NODE}" 'mktemp -d')
    scp -P "${PORT}" -o BatchMode=yes -i "$ssh_key" "/etc/prometheus/${NODE}.key" "/etc/prometheus/${NODE}.crt" \
    "/etc/prometheus/ca.crt" "node_exporter_install.sh" "node_name.cfg" "${NODE_USER}@${NODE}:${TEMP_DIR}"
    ssh -p "${PORT}" -i "$ssh_key" "${NODE_USER}@${NODE}" "cd '${TEMP_DIR}'; sudo -n bash node_exporter_install.sh"
fi

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

if [[ ${NODE} != localhost ]]; then
    IP_NODE="$(getent hosts "${NODE}")"
    if grep "${NODE}" "/etc/hosts"; then
        echo "${NODE} already in /etc/hosts"
    else
        tee -a /etc/hosts > /dev/null <<EOF
$IP_NODE
EOF
        echo "Add ${NODE} in /etc/hosts"
    fi
fi

systemctl restart prometheus.service

if [[ "$NODE" != "localhost" ]]; then
    tee -a /usr/local/etc/cert_update.cfg > /dev/null <<EOF
${NODE} ${PORT} ${NODE_USER}
EOF
fi