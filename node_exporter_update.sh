#!/bin/bash

# export path just in case
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
TS=$(date '+%Y%m%d_%H%M%S')
DATE_START=$(date '+%Y-%m-%d %H:%M:%S')

# enable logging
exec > >(systemd-cat -t node_exporter_update -p info) 2> >(systemd-cat -t node_exporter_update -p err) 5> >(systemd-cat -t node_exporter_update -p notice)

# start logging message
echo "########## node exporter update started - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5

# root check
[[ $EUID -ne 0 ]] && { echo "Error: you are not the root user, exit"; exit 1; }

# check another instanse of the script is not running
readonly LOCK_FILE="/run/lock/node_exporter_update.lock"
exec {fd}> "$LOCK_FILE" || { echo "Error: cannot open lock file '$LOCK_FILE', exit"; exit 1; }
flock -n "$fd" || { echo "Error: another instance is running, exit"; exit 1; }

# changing directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "Error: couldn't change working directory, exit"; exit 1; }

# exit logging message function
RC="1"
end_log() {
    if [[ "$RC" -eq "0" ]]; then
        echo "########## node exporter update ended - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5
    else
        echo "########## node exporter update failed - $(date '+%Y-%m-%d %H:%M:%S') ##########" >&5
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

# source Telegram func library
# shellcheck source=share/telegram.lib.sh
source "/usr/local/lib/service/telegram.lib.sh" || { echo "Error: failed to source '/usr/local/lib/service/telegram.lib.sh', exit" >&2; exit 1; }

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

# cleanup old backup and log
cleanup_old() {
    local dir="$1"
    local pattern="$2"
    local keep="$3"
    local name="$4"
    local has_old=0
    local f
    local glob="${dir}/${pattern}"

    if ! compgen -G "$glob" > /dev/null; then
        STATUS_OLD_BACKUP_DEL+="☑️ old ${name} missing, skipping deletion"$'\n'
        return
    fi

    for f in "$dir"/$pattern; do
        [[ -n "$keep" && "$f" == "$keep" ]] && continue

        has_old=1
        echo "Info: deleting old ${name} $f"
        if rm -f -- "$f"; then
            echo "Success: old ${name} $f deleted"
            STATUS_OLD_BACKUP_DEL+="☑️ old ${name} deletion success"$'\n'
        else
            echo "Error: failed to delete old ${name} $f" >&2
            STATUS_OLD_BACKUP_DEL+="⚠️ old ${name} deletion failed"$'\n'
            FAIL_TD=1
        fi
    done

    if [[ $has_old == 0 ]]; then
        STATUS_OLD_BACKUP_DEL+="☑️ old ${name} missing, skipping deletion"$'\n'
    fi
}

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
    if ! tar -xzf "$outfile" -C "$TMP_DIR" &> /dev/null; then
        echo "❌ Error: extract ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: ${outfile} successfully extracted"
    fi
    # check node exporter binary
    if [ ! -f "$TMP_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" ]; then
        echo "❌ Error: node exporter binary is missing from folder after unpacking ${outfile}, exit"
        exit 1
    else
        echo "✅ Success: node exporter binary exists in the folder after unpacking ${outfile}"
    fi

    return 0
}


# backup function
_backup_old_file() {
    local backup_src="$1"
    local backup_dest="$2"
    local label="$3"
    if cp -p "$backup_src" "$backup_dest"; then
        echo "Success: ${label} backup completed"
    else
        echo "Error: ${label} backup failed, exit" >&2
        return 1
    fi
}

# function for start node_exporter.service and check status
_node_exporter_start_on_fail() {
    if systemctl start node_exporter.service &> /dev/null; then
        echo "Success: node_exporter.service started, try updating again later, exit"
    else
        echo "Critical Error: node_exporter.service does not start, exit" >&2
    fi
}

# install function for install bin and dat files
_install() {
    local install_mode="$1"
    local install_src="$2"
    local install_dest="$3"
    local name="$4"

        if install -m "$install_mode" -g root -o root "$install_src" "$install_dest"; then
            echo "Success: $name installed"
        else
            echo "Error: $name not installed, trying rollback" >&2
            if ! cp -p "${install_dest}.bak.${TS}" "$install_dest"; then
                echo "Error: $name rollback failed" >&2
            else
                echo "Success: $name rolled back successfully"
            fi
            _node_exporter_start_on_fail
            return 1
        fi
}

# install node_exporter files function
install_node_exporter() {
    N_E_NEW_VER=""
    N_E_OLD_VER=""

    # check node exporter version
    if [ -x "$TMP_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" ]; then
        N_E_NEW_VER="$("$TMP_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" --version | awk 'NR==1 {print $3; exit}')"
    else
        echo "Error: unknown new node_exporter version, exit" >&2
        return 1
    fi

    if [ -x "/usr/local/bin/node_exporter" ]; then
        N_E_OLD_VER="$(node_exporter --version | awk 'NR==1 {print $3; exit}')"
    else
        N_E_OLD_VER=""
        echo "Error: unknown old node_exporter version, exit" >&2
        return 1
    fi

    if [ -n "$N_E_NEW_VER" ] && [ -n "$N_E_OLD_VER" ] && [ "$N_E_NEW_VER" == "$N_E_OLD_VER" ]; then
        echo "Info: node_exporter already up to date $N_E_NEW_VER, skip update"
        N_E_UP_TO_DATE=1
    else
        echo "Info: current node_exporter version is $N_E_OLD_VER, latest is $N_E_NEW_VER, preparing to update"
        N_E_UP_TO_DATE=0
    fi

    # old file backup
    if [ "$N_E_UP_TO_DATE" = "0" ]; then
        # backup
        _backup_old_file "/usr/local/bin/node_exporter" "/usr/local/bin/node_exporter.bak.${TS}" "node_exporter bin" || return 1
    else
        echo "Info: node_exporter already up to date, backup not needed"
    fi

    # stop node_exporter service
    if systemctl stop node_exporter.service &> /dev/null; then
        echo "Success: node_exporter.service stopped, starting the update"
    else
        echo "Error: failed to stop node_exporter.service, cancelling update" >&2
        echo "Info: checking status node_exporter.service"
        if systemctl is-active --quiet node_exporter.service; then
            echo "Success: node_exporter.service is running, try updating again later, exit"
            return 1
        else
            echo "Error: node_exporter.service is not running, trying to start" >&2
            _node_exporter_start_on_fail
            return 1
        fi 
    fi

    # install node_exporter bin
    if [ "$N_E_UP_TO_DATE" = "0" ]; then
        _install "755" "$TMP_DIR/node_exporter-${LATEST_TAG#v}.${OS_ARCH}/node_exporter" "/usr/local/bin/node_exporter" "node_exporter binary" || return 1
    else
        echo "Info: node_exporter binary installation skipped"
    fi

    # start node exporter
    if systemctl start node_exporter.service > /dev/null 2>&1; then
        echo "Success: node_exporter.service updated and started"
    else
        echo "Critical Error: node_exporter.service does not start" >&2
        return 1
    fi

    return 0
}

cleanup_old "/usr/local/bin" "node_exporter.bak.*" "$XRAY_DIR/xray.bak.${TS}" "node exporter backup"

# update node exporter
if ! download_and_verify "$NODE_EXPORTER_URL" "$TMP_DIR/node_exporter.tar.gz" "node_exporter"; then
    NODE_EXPORTER_DOWNLOAD=0
    STATUS_NODE_EXPORTER_MESSAGE="❌ node exporter download failed"
else
    STATUS_NODE_EXPORTER_MESSAGE="☑️ node exporter download success"
    NODE_EXPORTER_DOWNLOAD=1
fi

if [ "$NODE_EXPORTER_DOWNLOAD" = "1" ]; then
    if ! install_node_exporter; then
        STATUS_INSTALL_MESSAGE="❌ node exporter install failed"
        NODE_EXPORTER_INSTALL=0
    else
        if [ "$N_E_UP_TO_DATE" = "1" ]; then
            STATUS_INSTALL_MESSAGE+="☑️ node exporter already up to date $XRAY_OLD_VER"
            NODE_EXPORTER_INSTALL=1
        else
            STATUS_INSTALL_MESSAGE+="☑️ node exporter updated from $XRAY_OLD_VER to $XRAY_NEW_VER"
            NODE_EXPORTER_INSTALL=1
        fi
    fi
else
    NODE_EXPORTER_INSTALL=0
    STATUS_INSTALL_MESSAGE="⚠️ node exporter install skip"
fi

# check final xray status
if systemctl is-active --quiet node_exporter.service; then
    STATUS_NODE_EXPORTER="☑️ Success: node_exporter.service is running"
else
    STATUS_NODE_EXPORTER="❌ Critical Error: node_exporter.service does not start"
fi

# select a title for the telegram message
if [ "$NODE_EXPORTER_DOWNLOAD" = "1" ] && [ "$NODE_EXPORTER_INSTALL" = "1" ]; then
    if [ "$FAIL_TD" = "0" ]; then
        MESSAGE_TITLE="<b>✅ Scheduled node exporter update</b>"
        RC=0
    else
        MESSAGE_TITLE="<b>⚠️ Scheduled node exporter update</b>"
        RC=0
    fi
else
    MESSAGE_TITLE="<b>❌ Scheduled node exporter update</b>"
    RC=1
fi

# collecting report for telegram message
MESSAGE="$MESSAGE_TITLE

🖥️ <b>Host:</b> $(hostname)
⌚ <b>Time start:</b> $DATE_START
⌚ <b>Time end:</b> $(date '+%Y-%m-%d %H:%M:%S')
${STATUS_OLD_BACKUP_DEL}${STATUS_NODE_EXPORTER_MESSAGE}
${STATUS_INSTALL_MESSAGE}
${STATUS_NODE_EXPORTER}
💾 <b>Update log:</b> journalctl -t node_exporter_update"

telegram_message

exit $RC
