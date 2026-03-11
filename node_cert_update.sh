#!/bin/bash

# export path just in case
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

# enable logging
exec > >(systemd-cat -t node_cert_update -p info) 2> >(systemd-cat -t node_cert_update -p err) 5> >(systemd-cat -t node_cert_update -p notice)

# start logging message
echo "########## node certificate update started - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5

# root check
[[ $EUID -ne 0 ]] && { echo "Error: you are not the root user, exit" >&2; exit 1; }

# changing directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "Error: couldn't change working directory, exit" >&2; exit 1; }

# exit logging message function
RC="1"
end_log() {
    if [[ "$RC" -eq "0" ]]; then
        echo "########## node certificate update ended - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5
    else
        echo "########## node certificate update failed - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5
    fi
}

# trap for the end log message for the end log
trap 'end_log;' EXIT

# create working directory
TMP_DIR="$(mktemp -d)" || { echo "❌ Error: failed to create temporary directory, exit"; exit 1; }
readonly TMP_DIR

# exit cleanup and log message function
# shellcheck disable=SC2329
exit_cleanup() {
    echo "cleanup started - $(date '+%Y-%m-%d %H:%M:%S')" >&5
    if rm -rf "$TMP_DIR"; then
        echo "Success: delete tmp files"
        echo "cleanup ended - $(date '+%Y-%m-%d %H:%M:%S')"  >&5
    else
        echo "Error: delete tmp files"
        echo "cleanup failed - $(date '+%Y-%m-%d %H:%M:%S')" >&2
    fi
}

# set trap for exit cleanup
trap 'end_log; exit_cleanup;' EXIT

# check another instanse of the script is not running
readonly LOCK_FILE="/run/lock/node_cert_update.lock"
exec {fd}> "$LOCK_FILE" || { echo "Error: cannot open lock file '$LOCK_FILE', exit" >&2; exit 1; }
flock -n "$fd" || { echo "Error: another instance is running, exit" >&2; exit 1; }

# source Telegram func library
# shellcheck source=share/telegram.lib.sh
source "/usr/local/lib/service/telegram.lib.sh" || { echo "Error: failed to source '/usr/local/lib/service/telegram.lib.sh', exit" >&2; exit 1; }

SERVER_LIST_FILE="/usr/local/etc/node_cert_update/node_list.cfg"
THRESHOLD_DAYS=15
THRESHOLD_DAYS_ROOT=90
ALL_TARGETS=()
MISSED_CERT_TARGETS=()
EXPIRED_TARGETS=()
NEED_TO_GENERATE_TARGETS=()
SSH_KEY_NOT_FOUND_TARGETS=()
SSH_CONNECT_FAILED_TARGETS=()
CERT_CHECK_ERROR_TARGETS=()
GENERATED_CRT_TARGETS=()

[[ ! -f "$SERVER_LIST_FILE" ]] && { echo "Error: check '$SERVER_LIST_FILE' missing or not a file, exit" >&2; exit 1; }
[[ ! -r "$SERVER_LIST_FILE" ]] && { echo "Error: check '$SERVER_LIST_FILE' missing or you do not have read permissions, exit" >&2; exit 1; }

days_left_cert() {
    local crt="$1"
    local end
    [[ ! -f "$crt" ]] && { echo "-1"; return 0; }
    end=$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | cut -d= -f2)
    echo $(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
}

ROOT_CRT="/etc/prometheus/ca.crt"
ROOT_EXPIRED="$(days_left_cert $ROOT_CRT)"
PROMETHEUS_CRT="/etc/prometheus/prometheus_client.crt"
PROMETHEUS_EXPIRED="$(days_left_cert $PROMETHEUS_CRT)"

# if we not have node_exporter user, set expired to 1000, this trigger number for skip update
# for not update node_exporter sertificates because node_exporter not installed
if ! getent passwd node_exporter &> /dev/null; then
    LOCALHOST_EXPIRED=1000
else
    LOCALHOST_CRT="/usr/local/etc/node_exporter/tls/localhost.crt"
    LOCALHOST_EXPIRED="$(days_left_cert $LOCALHOST_CRT)"
fi

if [[ $ROOT_EXPIRED -lt 0 ]]; then
    MISSED_CERT_TARGETS+=("ROOT_CRT")
    REPLACE_ALL=1
elif [[ $ROOT_EXPIRED -lt $THRESHOLD_DAYS_ROOT ]]; then
    EXPIRED_TARGETS+=("ROOT_CRT")
    REPLACE_ALL=1
else
    REPLACE_ALL=0
fi

while read -r NODE PORT NODE_USER; do
    # skip empty srting
    [[ -z "${NODE}" ]] && continue
    # skip commented string
    [[ "$NODE" =~ ^[[:space:]]*# ]] && continue
    # save string in massive with | as border
    ALL_TARGETS+=("${NODE}|${PORT}|${NODE_USER}")
done < "$SERVER_LIST_FILE"

if [[ $REPLACE_ALL == 0 ]]; then
    if [[ $PROMETHEUS_EXPIRED -lt 0 ]]; then
        MISSED_CERT_TARGETS+=("prometheus_client")
        REPLACE_PROMETHEUS=1
    elif [[ $PROMETHEUS_EXPIRED -lt $THRESHOLD_DAYS ]]; then
        EXPIRED_TARGETS+=("prometheus_client")
        REPLACE_PROMETHEUS=1
    else
        REPLACE_PROMETHEUS=0
    fi

    if [[ $LOCALHOST_EXPIRED -lt 0 ]]; then
        MISSED_CERT_TARGETS+=("localhost")
        REPLACE_LOCALHOST=1
    elif [[ $LOCALHOST_EXPIRED -lt $THRESHOLD_DAYS ]]; then
        EXPIRED_TARGETS+=("localhost")
        REPLACE_LOCALHOST=1
    else
        REPLACE_LOCALHOST=0
    fi

    for rec in "${ALL_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$rec"

        ssh_key="/root/.ssh/${NODE}.key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "Error: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi

        days_left="$(
            ssh -p "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${NODE_USER}@${NODE}" \
            "sudo -n bash -lc '$(declare -f days_left_cert); days_left_cert $remote_crt'"
        )" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "Error: ssh/openssl failed for $NODE (skip)" >&2
            continue
        }

        if [[ -z "$days_left" ]]; then
            CERT_CHECK_ERROR_TARGETS+=("${NODE}")
            echo "Error: error date check sert for $NODE (skip)" >&2
            continue
        fi

        # Если меньше THRESHOLD_DAYS — кладём в expiring
        if [[ $days_left -lt 0 ]]; then
            MISSED_CERT_TARGETS+=("${NODE}")
            NEED_TO_GENERATE_TARGETS+=("${NODE}|${PORT}|${NODE_USER}")
        elif [[ $days_left -lt $THRESHOLD_DAYS ]]; then
            EXPIRED_TARGETS+=("${NODE}")
            NEED_TO_GENERATE_TARGETS+=("${NODE}|${PORT}|${NODE_USER}")
        fi
    done
fi

if [[ $REPLACE_ALL == 1 ]]; then
   # generation Certificate Autority private key
    openssl genrsa -out "${TMP_DIR}/ca.key" 4096

    # generation Certificate Autority public sert
    openssl req -x509 -new -nodes -key "${TMP_DIR}/ca.key" -sha256 -days 455 -out "${TMP_DIR}/ca.crt" -subj "/CN=metrics-mtls-ca"

    install -m 640 -o root -g prometheus   "${TMP_DIR}/ca.crt"                  "/etc/prometheus/ca.crt"
    install -m 600 -o root -g root         "${TMP_DIR}/ca.key"                  "/etc/prometheus/ca.key"
fi

if [[ $REPLACE_ALL == 1 || $REPLACE_PROMETHEUS == 1 ]]; then
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
    openssl x509 -req -in "${TMP_DIR}/prometheus_client.crt" -CA "/etc/prometheus/ca.crt" -CAkey "/etc/prometheus/ca.key" -CAcreateserial \
        -out "${TMP_DIR}/prometheus_client.crt" -days 45 -sha256 -extfile "${TMP_DIR}/prometheus_client.ext" -extensions v3_req

    install -m 640 -o root -g prometheus   "${TMP_DIR}/prometheus_client.crt"   "/etc/prometheus/prometheus_client.crt"
    install -m 640 -o root -g prometheus   "${TMP_DIR}/prometheus_client.key"   "/etc/prometheus/prometheus_client.key"

    GENERATED_CRT_TARGETS+=("prometheus_client")

    systemctl restart prometheus.service
fi

generate_sert() {
    local node="$1"

    # generation private key for node
    openssl genrsa -out "${TMP_DIR}/${node}.key" 2048

    # generation public key for node
    openssl req -new -key "${TMP_DIR}/${node}.key" -out "${TMP_DIR}/${node}.crt" -subj "/CN=${node}"

    # make cfg for signature
    tee "${TMP_DIR}/${node}.ext" > /dev/null <<EOF
[ v3_req ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${node}
EOF

    # signature node sertificate
    openssl x509 -req -in "${TMP_DIR}/${node}.crt" -CA "/etc/prometheus/ca.crt" -CAkey "/etc/prometheus/ca.key" -CAcreateserial \
        -out "${TMP_DIR}/${node}.crt" -days 45 -sha256 -extfile "${TMP_DIR}/${node}.ext" -extensions v3_req
}

if [[ $REPLACE_ALL == 1 ]]; then
    for record in "${ALL_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$record"
        generate_sert "$NODE"

        ssh_key="/root/.ssh/${NODE}.key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "Error: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi

        REMOTE_TMP_DIR=$(ssh -p "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${NODE_USER}@${NODE}" 'mktemp -d')

        scp -P "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${TMP_DIR}/${NODE}.key" "${TMP_DIR}/${NODE}.crt" \
        "/etc/prometheus/ca.crt" "${NODE_USER}@${NODE}:${REMOTE_TMP_DIR}" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "Error: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        ssh -p "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${NODE_USER}@${NODE}" "cd $REMOTE_TMP_DIR && \
        sudo -n install -m 640 -o root -g node_exporter ca.crt /usr/local/etc/node_exporter/tls/ca.crt && \
        sudo -n install -m 640 -o root -g node_exporter ${NODE}.crt /usr/local/etc/node_exporter/tls/${NODE}.crt && \
        sudo -n install -m 640 -o root -g node_exporter ${NODE}.key /usr/local/etc/node_exporter/tls/${NODE}.key && \
        sudo -n systemctl restart node_exporter.service" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "Error: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        GENERATED_CRT_TARGETS+=("${NODE}")

    done

    # if replace all, check we have self monitoring or not, 1000 - trigger number we not have self monitoring
    if [[ ! "$LOCALHOST_EXPIRED" == 1000 ]]; then
        generate_sert "localhost"
        install -m 640 -o root -g node_exporter "/etc/prometheus/ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
        install -m 640 -o root -g node_exporter "${TMP_DIR}/localhost.crt" "/usr/local/etc/node_exporter/tls/localhost.crt"
        install -m 640 -o root -g node_exporter "${TMP_DIR}/localhost.key" "/usr/local/etc/node_exporter/tls/localhost.key"
        systemctl restart node_exporter.service
        GENERATED_CRT_TARGETS+=("localhost")
    fi
else
    if [[ $REPLACE_LOCALHOST == 1 ]]; then
        generate_sert "localhost"
        install -m 640 -o root -g node_exporter "/etc/prometheus/ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
        install -m 640 -o root -g node_exporter "${TMP_DIR}/localhost.crt" "/usr/local/etc/node_exporter/tls/localhost.crt"
        install -m 640 -o root -g node_exporter "${TMP_DIR}/localhost.key" "/usr/local/etc/node_exporter/tls/localhost.key"
        systemctl restart node_exporter.service
        GENERATED_CRT_TARGETS+=("localhost")
    fi

        for record in "${NEED_TO_GENERATE_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$record"
        generate_sert "$NODE"

        ssh_key="/root/.ssh/${NODE}.key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "Error: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi
        REMOTE_TMP_DIR=$(ssh -p "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${NODE_USER}@${NODE}" 'mktemp -d')

        scp -P "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${TMP_DIR}/${NODE}.key" "${TMP_DIR}/${NODE}.crt" \
        "/etc/prometheus/ca.crt" "${NODE_USER}@${NODE}:${REMOTE_TMP_DIR}" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "Error: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        ssh -p "${PORT}" -i "$ssh_key" -o ConnectTimeout=10 -o BatchMode=yes "${NODE_USER}@${NODE}" "cd $REMOTE_TMP_DIR && \
        sudo -n install -m 640 -o root -g node_exporter ca.crt /usr/local/etc/node_exporter/tls/ca.crt && \
        sudo -n install -m 640 -o root -g node_exporter ${NODE}.crt /usr/local/etc/node_exporter/tls/${NODE}.crt && \
        sudo -n install -m 640 -o root -g node_exporter ${NODE}.key /usr/local/etc/node_exporter/tls/${NODE}.key && \
        sudo -n systemctl restart node_exporter.service" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "Error: ssh/openssl failed for $NODE (skip)" >&2; continue; }
        GENERATED_CRT_TARGETS+=("${NODE}")
    done
fi

if [[ ${#GENERATED_CRT_TARGETS[@]} -gt 0 || ${#MISSED_CERT_TARGETS[@]} -gt 0 || \
${#EXPIRED_TARGETS[@]} -gt 0 || ${#SSH_KEY_NOT_FOUND_TARGETS[@]} -gt 0 || \
${#SSH_CONNECT_FAILED_TARGETS[@]} -gt 0 || ${#CERT_CHECK_ERROR_TARGETS[@]} -gt 0 ]]; then
    echo "Have changed sertificate or error, need Telegram message"
else
    echo "Dont have changed sertificate or error, no need Telegram message, exit"
    RC=0
    exit 0
fi

if [[ ${#SSH_KEY_NOT_FOUND_TARGETS[@]} -gt 0 || ${#SSH_CONNECT_FAILED_TARGETS[@]} -gt 0 || ${#CERT_CHECK_ERROR_TARGETS[@]} -gt 0 ]]; then
    TITLE="❌ <b>Scheduled sertificate update</b>"
else
    TITLE="✅ <b>Scheduled sertificate update</b>"
    RC=0
fi

MESSAGE="$TITLE
🖥️ <b>Host:</b> $(hostname)
⌚ <b>Time:</b> $(date '+%Y-%m-%d %H:%M:%S')
☑️ <b>Updated success sertificate hosts:</b>
$(printf '%s\n' "${GENERATED_CRT_TARGETS[@]}")
🔎 <b>Missed certificate hosts before update:</b>
$(printf '%s\n' "${MISSED_CERT_TARGETS[@]}")
⌚ <b>Expired certificate hosts before update:</b>
$(printf '%s\n' "${EXPIRED_TARGETS[@]}")
🔎 <b>SSH key missed hosts:</b>
$(printf '❌ %s\n' "${SSH_KEY_NOT_FOUND_TARGETS[@]}")
🌐 <b>SSH connect failed hosts:</b>
$(printf '❌ %s\n' "${SSH_CONNECT_FAILED_TARGETS[@]}")
📝 <b>Error checking certificate hosts:</b>
$(printf '❌ %s\n' "${CERT_CHECK_ERROR_TARGETS[@]}")
💾 <b>Update log:</b> journalctl -t node_cert_update"

echo "########## collected message - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5
echo "$MESSAGE"

telegram_message
