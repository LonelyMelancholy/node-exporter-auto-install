# shellcheck disable=SC2148
#
# warning ------------------------------------------------------------- warning
# |        this is CUTTED lib version, only for notification in group         |
# |    if we have already installed full version, not install this version    |
# warning ------------------------------------------------------------- warning
#
# telegram sender message, if call telegram_message function, function send text in $MESSAGE variable
# if sending failed, RC_M not changed, if sending success RC_M=0
# RC_M - message sender return code
# external variable - $MESSAGE, $RC_M
# external file /usr/local/etc/telegram/secrets.env [root:telegram_gateway 640] with $BOT_TOKEN and $GROUP_ID

# check secret file, if the file have right permissions, we source it.
readonly ENV_FILE="/usr/local/etc/telegram/secrets.env"
if [[ ! -f "$ENV_FILE" ]] || [[ "$(stat -L -c '%U:%G:%a' "$ENV_FILE" 2> /dev/null)" != "root:telegram_gateway:640" ]]; then
    echo "Error: env file '$ENV_FILE' not found or has wrong permissions, exit" >&2
    exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE" || { echo "Error: failed to source '$ENV_FILE', exit" >&2; exit 1; }

# check token from secret file
[[ -z "$BOT_TOKEN" ]] && { echo "Error: Telegram bot token is missing in '$ENV_FILE', exit" >&2; exit 1; }

# check group id from secret file
[[ -z "$GROUP_ID" ]] && { echo "Error: Telegram group ID is missing in '$ENV_FILE', exit" >&2; exit 1; }

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

# Telegram message with final result logging and retry on failure
telegram_message() {
    local attempt=1
    local max_attempt=3
    local wait_sec=60
    while true; do
        if ! _tg_m; then
            if [[ "$attempt" -ge "$max_attempt" ]]; then
                echo "Error: failed to send Telegram message after $attempt attempts, exit" >&2
                exit 1
            fi
            echo "Info: failed to send Telegram message. Waiting ${wait_sec}s... attempt ${attempt}/${max_attempt}"
            sleep $wait_sec
            ((attempt++))
            continue
        else
            echo "Success: message was sent to Telegram after $attempt attempt"
            # shellcheck disable=SC2034
            RC_M=0
            return 0
        fi
    done
}
