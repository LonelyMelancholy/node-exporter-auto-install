#!/bin/bash

# root check
[[ $EUID -ne 0 ]] && { echo "❌ Error: you are not the root user, exit"; exit 1; }

# export path just in case
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH

# main variables
readonly MAX_ATTEMPTS="3"

# enable logging, the directory should already be created, but let's check just in case
readonly LOG_DIR="/var/log/service"
readonly UPDATE_LOG="${LOG_DIR}/cert_update.$(date +"%Y-%m-%d").log"
exec &>> "$UPDATE_LOG" || { echo "❌ Error: cannot write to log '$UPDATE_LOG', exit"; exit 1; }

# start logging message
readonly DATE_START="$(date "+%Y-%m-%d %H:%M:%S")"
echo "########## certificate update upgrade started - $DATE_START ##########"

# exit logging message function
RC="1"
on_exit() {
    if [[ "$RC" -eq "0" ]]; then
        local date_end="$(date "+%Y-%m-%d %H:%M:%S")"
        echo "########## certificate update ended - $date_end ##########"
    else
        local date_fail="$(date "+%Y-%m-%d %H:%M:%S")"
        echo "########## certificate update failed - $date_fail ##########"
    fi
}

# trap for the end log message for the end log
trap 'on_exit' EXIT

# check another instance of the script is not running
readonly LOCK_FILE="/run/lock/cert_update.lock"
exec 99> "$LOCK_FILE" || { echo "❌ Error: cannot open lock file '$LOCK_FILE', exit"; exit 1; }
flock -n 99 || { echo "❌ Error: another instance is running, exit"; exit 1; }

# check secret file, if the file is ok, we source it.
readonly ENV_FILE="/usr/local/etc/telegram/secrets.env"
if [[ ! -f "$ENV_FILE" ]] || [[ "$(stat -L -c '%U:%a' "$ENV_FILE")" != "root:600" ]]; then
    echo "❌ Error: env file '$ENV_FILE' not found or has wrong permissions, exit"
    exit 1
fi
source "$ENV_FILE"

# check token from secret file
[[ -z "$BOT_TOKEN" ]] && { echo "❌ Error: Telegram bot token is missing in '$ENV_FILE', exit"; exit 1; }

# check group id from secret file
[[ -z "$GROUP_ID" ]] && { echo "❌ Error: Telegram group ID is missing in '$ENV_FILE', exit"; exit 1; }

# pure Telegram message function with checking the sending status
_tg_m() {
    local response
    response="$(curl -fsS -m 10 -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        --data-urlencode "chat_id=${GROUP_ID}" \
        --data-urlencode "parse_mode=HTML" \
        --data-urlencode "text=${MESSAGE}")" || return 1
    grep -Eq '"ok"[[:space:]]*:[[:space:]]*true' <<< "$response" || return 1
    return 0
}

# Telegram message with logging and retry
telegram_message() {
    local attempt="1"
    while true; do
        if ! _tg_m; then
            if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
                echo "❌ Error: failed to send Telegram message after $attempt attempts, exit"
                return 1
            fi
            sleep 60
            ((attempt++))
            continue
        else
            echo "✅ Success: message was sent to Telegram after $attempt attempt"
            return 0
        fi
    done
}


SERVER_LIST_FILE="/usr/local/etc/cert_update.cfg"
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

days_left_cert() {
    local crt="$1"
    local end
    [[ ! -f "$crt" ]] && { echo "-1"; return 0; }
    end=$(openssl x509 -in "$crt" -noout -days_left | cut -d= -f2)
    echo $(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
}

ROOT_CRT="/etc/prometheus/ca.crt"
ROOT_EXPIRED="$(days_left_cert $ROOT_CRT)"
PROMETHEUS_CRT="/etc/prometheus/prometheus_client.crt"
PROMETHEUS_EXPIRED="$(days_left_cert $PROMETHEUS_CRT)"
LOCALHOST_CRT="/usr/local/etc/node_exporter/tls/localhost.crt"
LOCALHOST_EXPIRED="$(days_left_cert $LOCALHOST_CRT)"

if [[ $ROOT_EXPIRED -lt 0 ]]; then
    MISSED_CERT_TARGETS+=("ROOT_CRT")
    REPLACE_ALL=1
elif [[ $ROOT_EXPIRED -lt $THRESHOLD_DAYS_ROOT ]]; then
    EXPIRED_TARGETS+=("ROOT_CRT")
    REPLACE_ALL=1
else
    REPLACE_ALL=0
fi

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


    while read -r NODE PORT NODE_USER; do
        # skip empty srting
        [[ -z "${NODE}" ]] && continue
        # skip commented string
        [[ "${NODE:0:1}" == "#" ]] && continue
        # save string in massive with | as border
        ALL_TARGETS+=("${NODE}|${PORT}|${NODE_USER}")
    done < "$SERVER_LIST_FILE"


    for rec in "${ALL_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$rec"

        ssh_key="/root/.ssh/${NODE}.ssh_key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "WARN: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi

        days_left="$(
            ssh -i "$ssh_key" -p "$PORT" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "${NODE_USER}@${NODE}" \
            "$(days_left_cert) $remote_crt"
        )" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "WARN: ssh/openssl failed for $NODE (skip)" >&2
            continue
        }

        if [[ -z "$days_left" ]]; then
            CERT_CHECK_ERROR_TARGETS+=("${NODE}")
            echo "WARN: error date check sert for $NODE (skip)" >&2
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
    openssl genrsa -out "/etc/prometheus/ca.key" 4096

    # generation Certificate Autority public sert
    openssl req -x509 -new -nodes -key "/etc/prometheus/ca.key" -sha256 -days 455 -out "/etc/prometheus/ca.crt" -subj "/CN=metrics-mtls-ca"
fi

if [[ $REPLACE_ALL == 1 || $REPLACE_PROMETHEUS == 1 ]]; then
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

    GENERATED_CRT_TARGETS+=("prometheus_client")

    chown -R prometheus:prometheus /etc/prometheus/
    chmod 750 /etc/prometheus/
    chmod 640 /etc/prometheus/prometheus_client.crt
    chmod 640 /etc/prometheus/ca.crt
    chmod 600 /etc/prometheus/prometheus_client.key
    chmod 600 /etc/prometheus/ca.key
fi

generate_sert() {
    local node="$1"
    # generation private key for node
    openssl genrsa -out "/etc/prometheus/${node}.key" 2048

    # generation public key for node
    openssl req -new -key "/etc/prometheus/${node}.key" -out "/etc/prometheus/${node}.crt" -subj "/CN=${node}"

    # make cfg for signature
    tee "/etc/prometheus/${node}.ext" > /dev/null <<EOF
[ v3_req ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[ alt_names ]
DNS.1 = ${node}
EOF

    # signature node sertificate
    openssl x509 -req -in "/etc/prometheus/${node}.crt" -CA "/etc/prometheus/ca.crt" -CAkey "/etc/prometheus/ca.key" -CAcreateserial \
    -out "/etc/prometheus/${node}.crt" -days 45 -sha256 -extfile "/etc/prometheus/${node}.ext" -extensions v3_req
}

if [[ $REPLACE_ALL == 1 ]]; then
    for record in "${ALL_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$record"
        generate_sert "$NODE"

        ssh_key="/root/.ssh/${NODE}.ssh_key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "WARN: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi

        TEMP_DIR=$(ssh -o StrictHostKeyChecking=accept-new -p "${PORT}" -o BatchMode=yes -i "$ssh_key" "${NODE_USER}@${NODE}" 'mktemp -d')

        scp -P "${PORT}" -o BatchMode=yes -i "$ssh_key" "/etc/prometheus/${NODE}.key" "/etc/prometheus/${NODE}.crt" \
        "/etc/prometheus/ca.crt" "${NODE_USER}@${NODE}:${TEMP_DIR}" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "WARN: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        ssh -p "${PORT}" -i "$ssh_key" "${NODE_USER}@${NODE}" "cd $TEMP_DIR; \
        sudo -n install -m 640 -o node_exporter -g node_exporter ca.crt /usr/local/etc/node_exporter/tls/ca.crt; \
        sudo -n install -m 640 -o node_exporter -g node_exporter ${NODE}.crt /usr/local/etc/node_exporter/tls/${NODE}.crt; \
        sudo -n install -m 600 -o node_exporter -g node_exporter ${NODE}.key /usr/local/etc/node_exporter/tls/${NODE}.key; \
        sudo -n systemctl restart node_exporter.service" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "WARN: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        GENERATED_CRT_TARGETS+=("${NODE}")

    done
        generate_sert "localhost"
        install -m 640 -o node_exporter -g node_exporter "/etc/prometheus/ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
        install -m 640 -o node_exporter -g node_exporter "/etc/prometheus/localhost.crt" "/usr/local/etc/node_exporter/tls/localhost.crt"
        install -m 600 -o node_exporter -g node_exporter "/etc/prometheus/localhost.key" "/usr/local/etc/node_exporter/tls/localhost.key"
        systemctl restart node_exporter.service
        GENERATED_CRT_TARGETS+=("localhost")
else
    if [[ $REPLACE_LOCALHOST == 1 ]]; then
        generate_sert "localhost"
        install -m 640 -o node_exporter -g node_exporter "/etc/prometheus/ca.crt" "/usr/local/etc/node_exporter/tls/ca.crt"
        install -m 640 -o node_exporter -g node_exporter "/etc/prometheus/localhost.crt" "/usr/local/etc/node_exporter/tls/localhost.crt"
        install -m 600 -o node_exporter -g node_exporter "/etc/prometheus/localhost.key" "/usr/local/etc/node_exporter/tls/localhost.key"
        systemctl restart node_exporter.service
        GENERATED_CRT_TARGETS+=("localhost")
    fi

        for record in "${NEED_TO_GENERATE_TARGETS[@]}"; do
        IFS='|' read -r NODE PORT NODE_USER <<< "$record"
        generate_sert "$NODE"

        ssh_key="/root/.ssh/${NODE}.ssh_key"
        remote_crt="/usr/local/etc/node_exporter/tls/${NODE}.crt"

        if [[ ! -f "$ssh_key" ]]; then
            SSH_KEY_NOT_FOUND_TARGETS+=("${NODE}")
            echo "WARN: ssh_key not found: $ssh_key for $NODE (skip)" >&2
            continue
        fi
        TEMP_DIR=$(ssh -o StrictHostKeyChecking=accept-new -p "${PORT}" -o BatchMode=yes -i "$ssh_key" "${NODE_USER}@${NODE}" 'mktemp -d')

        scp -P "${PORT}" -o BatchMode=yes -i "$ssh_key" "/etc/prometheus/${NODE}.key" "/etc/prometheus/${NODE}.crt" \
        "/etc/prometheus/ca.crt" "${NODE_USER}@${NODE}:${TEMP_DIR}" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "WARN: ssh/openssl failed for $NODE (skip)" >&2; continue; }

        ssh -p "${PORT}" -i "$ssh_key" "${NODE_USER}@${NODE}" "cd $TEMP_DIR; \
        sudo -n install -m 640 -o node_exporter -g node_exporter ca.crt /usr/local/etc/node_exporter/tls/ca.crt; \
        sudo -n install -m 640 -o node_exporter -g node_exporter ${NODE}.crt /usr/local/etc/node_exporter/tls/${NODE}.crt; \
        sudo -n install -m 600 -o node_exporter -g node_exporter ${NODE}.key /usr/local/etc/node_exporter/tls/${NODE}.key; \
        sudo -n systemctl restart node_exporter.service" || { SSH_CONNECT_FAILED_TARGETS+=("${NODE}")
            echo "WARN: ssh/openssl failed for $NODE (skip)" >&2; continue; }
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
💾 <b>Update log:</b> $UPDATE_LOG"

echo "########## collected message - $DATE_MESSAGE ##########"
echo "$MESSAGE"

telegram_message && RC=0
