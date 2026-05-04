#!/bin/bash

FLOO_GITHUB_REPO="ntetv/floo"
FLOO_RELEASE_BASE_URL="https://gh.5ieee.com/github.com/${FLOO_GITHUB_REPO}/releases/latest/download"
FLOO_SCRIPT_URL="https://raw.githubusercontent.com/${FLOO_GITHUB_REPO}/main/floo-macos.sh"

FLOO_APP_SUPPORT_DIR="${HOME}/Library/Application Support/Floo"
FLOO_CONF_DIR="${FLOO_APP_SUPPORT_DIR}/configs"
FLOO_PLIST_DIR="${FLOO_APP_SUPPORT_DIR}/plists"
FLOO_BIN_DIR="${FLOO_APP_SUPPORT_DIR}/bin"
FLOO_LOG_DIR="${HOME}/Library/Logs/Floo"
FLOO_LAUNCH_AGENTS_DIR="${HOME}/Library/LaunchAgents"
FLOO_BIN_SERVER="${FLOO_BIN_DIR}/floos"
FLOO_BIN_CLIENT="${FLOO_BIN_DIR}/flooc"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PLAIN='\033[0m'

error_and_exit() {
    printf '%b%s%b\n' "$RED" "$1" "$PLAIN" >&2
    exit 1
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

shopt -s nullglob

[[ $(uname -s) == "Darwin" ]] || error_and_exit "floo-macos.sh only supports macOS."

note() {
    printf '%b%s%b\n' "$YELLOW" "$1" "$PLAIN"
}

success() {
    printf '%b%s%b\n' "$GREEN" "$1" "$PLAIN"
}

error() {
    printf '%b%s%b\n' "$RED" "$1" "$PLAIN" >&2
}

ensure_dirs() {
    mkdir -p "$FLOO_CONF_DIR" "$FLOO_PLIST_DIR" "$FLOO_BIN_DIR" "$FLOO_LOG_DIR" "$FLOO_LAUNCH_AGENTS_DIR"
}

valid_id() {
    [[ $1 =~ ^[A-Za-z0-9_-]+$ ]]
}

format_target() {
    local input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo "127.0.0.1:$input"
    else
        echo "$input"
    fi
}

format_listener() {
    local input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo "0.0.0.0:$input"
    else
        echo "$input"
    fi
}

suggest_client_target() {
    local input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo "127.0.0.1:$input"
    elif [[ $input =~ ^[^:]+:([0-9]+)$ ]]; then
        echo "127.0.0.1:${BASH_REMATCH[1]}"
    else
        echo "127.0.0.1:22"
    fi
}

gen_creds() {
    local provided_psk=$1
    local provided_token=$2

    if [[ -n $provided_psk ]]; then
        psk=$provided_psk
    else
        psk=$(openssl rand -base64 32) || return 1
    fi

    if [[ -n $provided_token ]]; then
        token=$provided_token
    else
        token=$(openssl rand -hex 16) || return 1
    fi
}

parse_flag_value() {
    local arg=$1
    local prefix=$2
    if [[ $arg == ${prefix}=* ]]; then
        printf '%s\n' "${arg#${prefix}=}"
        return 0
    fi
    return 1
}

is_command_mode() {
    [[ $# -gt 0 && $1 != [0-9] ]]
}

base64_url_encode() {
    printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='
}

base64_url_decode() {
    local input=$1
    local normalized=${input//-/+}
    normalized=${normalized//_/\/}
    case $(( ${#normalized} % 4 )) in
        2) normalized+="==" ;;
        3) normalized+="=" ;;
    esac
    printf '%s' "$normalized" | openssl base64 -A -d
}

json_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '%s' "$value"
}

preset_json() {
    local server_addr=$1
    local cipher=$2
    local psk_value=$3
    local token_value=$4
    local proxy_mode=$5
    local map_name=$6
    local mode_value=$7
    local client_id=$8

    printf '{"server":"%s","cipher":"%s","psk":"%s","token":"%s","proxy_mode":"%s","map_name":"%s","mode":"%s","client_id":"%s"}' \
        "$(json_escape "$server_addr")" \
        "$(json_escape "$cipher")" \
        "$(json_escape "$psk_value")" \
        "$(json_escape "$token_value")" \
        "$(json_escape "$proxy_mode")" \
        "$(json_escape "$map_name")" \
        "$(json_escape "$mode_value")" \
        "$(json_escape "$client_id")"
}

json_get_string() {
    local json=$1
    local key=$2
    local value

    value=$(JSON_PAYLOAD="$json" python3 - "$key" <<'PY'
import json
import os
import sys

key = sys.argv[1]
try:
    data = json.loads(os.environ["JSON_PAYLOAD"])
except Exception:
    sys.exit(1)
value = data.get(key, "")
if isinstance(value, (str, int, float)):
    print(value)
PY
) || return 1

    printf '%s\n' "$value"
}

append_mode_if_needed() {
    local config_path=$1
    local mode_value=$2
    printf 'mode = %s\n\n' "$mode_value" >> "$config_path"
}

release_asset_name() {
    local arch
    arch=$(uname -m)
    case $arch in
        arm64|aarch64) echo "floo-aarch64-macos.tar.gz" ;;
        x86_64|amd64) echo "floo-x86_64-macos.tar.gz" ;;
        *)
            error "Unsupported macOS architecture: $arch"
            return 1
            ;;
    esac
}

fetch_url() {
    local url=$1
    local output=$2

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    else
        error "curl is required to download release assets."
        return 1
    fi
}

download_release_asset() {
    local asset_name=$1
    local output_path=$2
    local asset_url="${FLOO_RELEASE_BASE_URL}/${asset_name}"

    note "Downloading latest release asset: ${asset_name}"
    if fetch_url "$asset_url" "$output_path"; then
        return 0
    fi

    error "Failed to download ${asset_name}."
    return 1
}

find_local_binary() {
    local kind=$1
    local name
    local candidate

    case $kind in
        server) name="floos" ;;
        client) name="flooc" ;;
        *) return 1 ;;
    esac

    for candidate in \
        "$SCRIPT_DIR/$name" \
        "$SCRIPT_DIR/zig-out/bin/$name"
    do
        if [[ -x $candidate ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

install_local_binaries() {
    local install_kind=${1:-both}
    local server_src=""
    local client_src=""

    case $install_kind in
        server)
            server_src=$(find_local_binary server) || return 1
            install -m 755 "$server_src" "$FLOO_BIN_SERVER"
            ;;
        client)
            client_src=$(find_local_binary client) || return 1
            install -m 755 "$client_src" "$FLOO_BIN_CLIENT"
            ;;
        both)
            server_src=$(find_local_binary server) || return 1
            client_src=$(find_local_binary client) || return 1
            install -m 755 "$server_src" "$FLOO_BIN_SERVER"
            install -m 755 "$client_src" "$FLOO_BIN_CLIENT"
            ;;
        *)
            error "Unknown install kind: $install_kind"
            return 1
            ;;
    esac

    return 0
}

install_release_binaries() {
    local asset_name=$1
    local install_kind=${2:-both}
    local tmp_dir
    local server_bin=""
    local client_bin=""

    tmp_dir=$(mktemp -d) || return 1

    if ! download_release_asset "$asset_name" "$tmp_dir/$asset_name"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! tar -xzf "$tmp_dir/$asset_name" -C "$tmp_dir"; then
        error "Failed to extract ${asset_name}."
        rm -rf "$tmp_dir"
        return 1
    fi

    server_bin=$(find "$tmp_dir" -type f -name floos | head -n 1)
    client_bin=$(find "$tmp_dir" -type f -name flooc | head -n 1)

    case $install_kind in
        server)
            [[ -n $server_bin ]] || { error "Release archive does not contain floos."; rm -rf "$tmp_dir"; return 1; }
            install -m 755 "$server_bin" "$FLOO_BIN_SERVER"
            ;;
        client)
            [[ -n $client_bin ]] || { error "Release archive does not contain flooc."; rm -rf "$tmp_dir"; return 1; }
            install -m 755 "$client_bin" "$FLOO_BIN_CLIENT"
            ;;
        both)
            [[ -n $server_bin && -n $client_bin ]] || { error "Release archive does not contain floos/flooc."; rm -rf "$tmp_dir"; return 1; }
            install -m 755 "$server_bin" "$FLOO_BIN_SERVER"
            install -m 755 "$client_bin" "$FLOO_BIN_CLIENT"
            ;;
        *)
            error "Unknown install kind: $install_kind"
            rm -rf "$tmp_dir"
            return 1
            ;;
    esac

    rm -rf "$tmp_dir"
    return 0
}

ensure_binaries_installed() {
    local install_kind=${1:-both}
    local asset_name

    ensure_dirs

    if install_local_binaries "$install_kind"; then
        note "Installed managed binaries from local files next to the script."
        return 0
    fi

    asset_name=$(release_asset_name) || return 1
    install_release_binaries "$asset_name" "$install_kind"
}

binary_path_for_kind() {
    if [[ $1 == "server" ]]; then
        printf '%s\n' "$FLOO_BIN_SERVER"
    else
        printf '%s\n' "$FLOO_BIN_CLIENT"
    fi
}

ensure_binary_for_kind() {
    local kind=$1
    local binary_path

    binary_path=$(binary_path_for_kind "$kind")
    if [[ -x $binary_path ]]; then
        return 0
    fi

    ensure_binaries_installed "$kind"
}

config_mode_value() {
    local file=$1
    local line

    line=$(grep -m1 -E '^mode[[:space:]]*=' "$file" 2>/dev/null || true)
    if [[ $line =~ ^mode[[:space:]]*=[[:space:]]*([12])[[:space:]]*$ ]]; then
        echo "${BASH_REMATCH[1]}"
    else
        echo ""
    fi
}

config_kind_value() {
    local file=$1
    local line
    local has_bind=0
    local has_port=0
    local has_server=0

    while IFS= read -r line; do
        if [[ $line =~ ^#\ floo_role[[:space:]]*=[[:space:]]*(server|client)[[:space:]]*$ ]]; then
            echo "${BASH_REMATCH[1]}"
            return
        fi
        [[ $line =~ ^bind[[:space:]]*= ]] && has_bind=1
        [[ $line =~ ^port[[:space:]]*= ]] && has_port=1
        [[ $line =~ ^server[[:space:]]*= ]] && has_server=1
    done < "$file"

    if [[ $has_bind -eq 1 && $has_port -eq 1 ]]; then
        echo "server"
    elif [[ $has_server -eq 1 ]]; then
        echo "client"
    else
        echo "client"
    fi
}

service_role_for_kind() {
    if [[ $1 == "server" ]]; then
        echo "server"
    else
        echo "client"
    fi
}

config_path_for_id() {
    printf '%s/%s.toml\n' "$FLOO_CONF_DIR" "$1"
}

label_for_kind() {
    local kind=$1
    local id=$2
    printf 'com.ntetv.floo.%s.%s\n' "$kind" "$id"
}

plist_source_path() {
    local kind=$1
    local id=$2
    printf '%s/%s.plist\n' "$FLOO_PLIST_DIR" "$(label_for_kind "$kind" "$id")"
}

launchagent_plist_path() {
    local kind=$1
    local id=$2
    printf '%s/%s.plist\n' "$FLOO_LAUNCH_AGENTS_DIR" "$(label_for_kind "$kind" "$id")"
}

stdout_log_path() {
    local kind=$1
    local id=$2
    printf '%s/%s.out.log\n' "$FLOO_LOG_DIR" "$(label_for_kind "$kind" "$id")"
}

stderr_log_path() {
    local kind=$1
    local id=$2
    printf '%s/%s.err.log\n' "$FLOO_LOG_DIR" "$(label_for_kind "$kind" "$id")"
}

launch_domain() {
    local uid_value
    uid_value=$(id -u)
    if launchctl print "gui/${uid_value}" >/dev/null 2>&1; then
        printf 'gui/%s\n' "$uid_value"
    else
        printf 'user/%s\n' "$uid_value"
    fi
}

service_target() {
    local kind=$1
    local id=$2
    printf '%s/%s\n' "$(launch_domain)" "$(label_for_kind "$kind" "$id")"
}

xml_escape() {
    local value=$1
    value=${value//&/&amp;}
    value=${value//</&lt;}
    value=${value//>/&gt;}
    printf '%s' "$value"
}

write_instance_plist() {
    local kind=$1
    local id=$2
    local binary_path
    local config_path
    local label
    local source_path
    local stdout_path
    local stderr_path
    local launchagent_path

    ensure_binary_for_kind "$kind" || return 1
    ensure_dirs

    binary_path=$(binary_path_for_kind "$kind")
    config_path=$(config_path_for_id "$id")
    label=$(label_for_kind "$kind" "$id")
    source_path=$(plist_source_path "$kind" "$id")
    stdout_path=$(stdout_log_path "$kind" "$id")
    stderr_path=$(stderr_log_path "$kind" "$id")
    launchagent_path=$(launchagent_plist_path "$kind" "$id")

    touch "$stdout_path" "$stderr_path"

    cat > "$source_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$(xml_escape "$label")</string>
    <key>ProgramArguments</key>
    <array>
        <string>$(xml_escape "$binary_path")</string>
        <string>$(xml_escape "$config_path")</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$(xml_escape "$FLOO_APP_SUPPORT_DIR")</string>
    <key>ProcessType</key>
    <string>Background</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$(xml_escape "$stdout_path")</string>
    <key>StandardErrorPath</key>
    <string>$(xml_escape "$stderr_path")</string>
</dict>
</plist>
EOF

    if command -v plutil >/dev/null 2>&1; then
        plutil -lint "$source_path" >/dev/null || {
            error "Generated plist is invalid: $source_path"
            return 1
        }
    fi

    if [[ -f $launchagent_path ]]; then
        cp "$source_path" "$launchagent_path"
    fi
}

instance_exists() {
    local id=$1
    [[ -f $(config_path_for_id "$id") ]]
}

kind_for_id() {
    local id=$1
    config_kind_value "$(config_path_for_id "$id")"
}

mode_for_id() {
    local id=$1
    config_mode_value "$(config_path_for_id "$id")"
}

active_plist_path() {
    local kind=$1
    local id=$2
    local launchagent_path

    launchagent_path=$(launchagent_plist_path "$kind" "$id")
    if [[ -f $launchagent_path ]]; then
        printf '%s\n' "$launchagent_path"
    else
        plist_source_path "$kind" "$id"
    fi
}

is_service_loaded() {
    local kind=$1
    local id=$2
    launchctl print "$(service_target "$kind" "$id")" >/dev/null 2>&1
}

service_field() {
    local kind=$1
    local id=$2
    local field_pattern=$3

    launchctl print "$(service_target "$kind" "$id")" 2>/dev/null | awk -F'= ' -v pattern="$field_pattern" '$0 ~ pattern {print $2; exit}'
}

service_state() {
    local kind=$1
    local id=$2
    local state

    state=$(service_field "$kind" "$id" 'state = ')
    if [[ -n $state ]]; then
        printf '%s\n' "$state"
    else
        printf 'stopped\n'
    fi
}

service_pid() {
    local kind=$1
    local id=$2
    service_field "$kind" "$id" 'pid = '
}

wait_for_service_loaded() {
    local kind=$1
    local id=$2
    local expected_loaded=$3
    local attempts=${4:-20}
    local index
    local loaded=0

    for ((index = 0; index < attempts; index++)); do
        if is_service_loaded "$kind" "$id"; then
            loaded=1
        else
            loaded=0
        fi

        if [[ $loaded -eq $expected_loaded ]]; then
            return 0
        fi

        sleep 0.2
    done

    return 1
}

service_last_exit() {
    local kind=$1
    local id=$2
    service_field "$kind" "$id" 'last exit code = '
}

autostart_enabled() {
    local kind=$1
    local id=$2
    [[ -f $(launchagent_plist_path "$kind" "$id") ]]
}

list_instance_ids() {
    local config_file
    for config_file in "$FLOO_CONF_DIR"/*.toml; do
        basename "$config_file" .toml
    done
}

start_instance() {
    local kind=$1
    local id=$2
    local plist_path

    write_instance_plist "$kind" "$id" || return 1
    plist_path=$(active_plist_path "$kind" "$id")

    if is_service_loaded "$kind" "$id"; then
        launchctl kickstart -k "$(service_target "$kind" "$id")" || return 1
    else
        launchctl bootstrap "$(launch_domain)" "$plist_path" || return 1
    fi

    wait_for_service_loaded "$kind" "$id" 1 || return 1
}

restart_instance() {
    local kind=$1
    local id=$2

    write_instance_plist "$kind" "$id" || return 1
    if is_service_loaded "$kind" "$id"; then
        launchctl kickstart -k "$(service_target "$kind" "$id")" || return 1
    else
        start_instance "$kind" "$id" || return 1
        return 0
    fi

    wait_for_service_loaded "$kind" "$id" 1 || return 1
}

stop_instance() {
    local kind=$1
    local id=$2

    if is_service_loaded "$kind" "$id"; then
        launchctl bootout "$(service_target "$kind" "$id")" || return 1
        wait_for_service_loaded "$kind" "$id" 0 || return 1
    fi
}

enable_autostart_instance() {
    local kind=$1
    local id=$2
    local source_path
    local installed_path

    write_instance_plist "$kind" "$id" || return 1
    source_path=$(plist_source_path "$kind" "$id")
    installed_path=$(launchagent_plist_path "$kind" "$id")

    cp "$source_path" "$installed_path"

    if ! is_service_loaded "$kind" "$id"; then
        launchctl bootstrap "$(launch_domain)" "$installed_path" || return 1
    fi
}

disable_autostart_instance() {
    local kind=$1
    local id=$2
    local installed_path

    installed_path=$(launchagent_plist_path "$kind" "$id")
    rm -f "$installed_path"
}

remove_instance_files() {
    local kind=$1
    local id=$2

    rm -f "$(config_path_for_id "$id")"
    rm -f "$(plist_source_path "$kind" "$id")"
    rm -f "$(launchagent_plist_path "$kind" "$id")"
    rm -f "$(stdout_log_path "$kind" "$id")"
    rm -f "$(stderr_log_path "$kind" "$id")"
}

select_mode_value() {
    local choice

    echo "Performance mode:"
    echo "1. mode = 1"
    echo "2. mode = 2"
    read -r -p "Choose [1-2]: " choice

    case $choice in
        1|2) echo "$choice" ;;
        *) echo "" ;;
    esac
}

select_cipher() {
    local choice

    echo "Cipher:"
    echo "1. aes256gcm (recommended)"
    echo "2. chacha20poly1305"
    echo "3. none (debug only)"
    read -r -p "Choose [1-3, default 1]: " choice

    case $choice in
        2) echo "chacha20poly1305" ;;
        3) echo "none" ;;
        *) echo "aes256gcm" ;;
    esac
}

build_client_import_command() {
    local server_addr=$1
    local cipher=$2
    local psk_value=$3
    local token_value=$4
    local proxy_mode=$5
    local map_name=$6
    local mode_value=$7
    local client_id=$8
    local suggested_target=$9
    local preset

    [[ -n $FLOO_SCRIPT_URL ]] || return 0

    preset=$(base64_url_encode "$(preset_json "$server_addr" "$cipher" "$psk_value" "$token_value" "$proxy_mode" "$map_name" "$mode_value" "$client_id")")

    echo
    note "Client one-command import:"
    echo "bash <(curl -fsSL \"$FLOO_SCRIPT_URL\") import-client --preset=$preset --client-target=$suggested_target"
}

write_server_config() {
    local id=$1
    local tunnel_port=$2
    local cipher=$3
    local mode_value=$4
    local proxy_mode=$5
    local map_name=$6
    local port_input=$7
    local target
    local listener
    local config_path

    config_path=$(config_path_for_id "$id")
    target=$(format_target "$port_input")
    listener=$(format_listener "$port_input")

    cat > "$config_path" <<EOF
# floo_role = server
bind = "0.0.0.0"
port = $tunnel_port
cipher = "$cipher"
psk = "$psk"
token = "$token"

EOF
    append_mode_if_needed "$config_path" "$mode_value"
    if [[ $proxy_mode == "1" ]]; then
        printf '[services]\n%s = "%s"\n' "$map_name" "$target" >> "$config_path"
    else
        printf '[reverse_services]\n%s = "%s"\n' "$map_name" "$listener" >> "$config_path"
    fi
    chmod 600 "$config_path"
}

write_client_config() {
    local id=$1
    local server_addr=$2
    local cipher=$3
    local mode_value=$4
    local proxy_mode=$5
    local map_name=$6
    local port_input=$7
    local target
    local config_path

    config_path=$(config_path_for_id "$id")
    target=$(format_target "$port_input")

    cat > "$config_path" <<EOF
# floo_role = client
server = "$server_addr"
cipher = "$cipher"
psk = "$psk"
token = "$token"

EOF
    append_mode_if_needed "$config_path" "$mode_value"
    if [[ $proxy_mode == "1" ]]; then
        printf '[services]\n%s = "%s"\n' "$map_name" "$target" >> "$config_path"
    else
        printf '[reverse_services]\n%s = "%s"\n' "$map_name" "$target" >> "$config_path"
    fi
    chmod 600 "$config_path"
}

show_binary_status() {
    if [[ -x $FLOO_BIN_SERVER ]]; then
        echo "  floos: installed ($FLOO_BIN_SERVER)"
    else
        echo "  floos: missing"
    fi

    if [[ -x $FLOO_BIN_CLIENT ]]; then
        echo "  flooc: installed ($FLOO_BIN_CLIENT)"
    else
        echo "  flooc: missing"
    fi
}

print_instance_summary() {
    local id=$1
    local kind=$2
    local state=$3
    local pid=$4
    local autostart=$5

    if [[ -n $pid ]]; then
        printf '  [%s] %s state=%s pid=%s autostart=%s\n' "$id" "$kind" "$state" "$pid" "$autostart"
    else
        printf '  [%s] %s state=%s autostart=%s\n' "$id" "$kind" "$state" "$autostart"
    fi
}

status_text_for_instance() {
    local kind=$1
    local id=$2
    local state
    local pid

    state=$(service_state "$kind" "$id")
    pid=$(service_pid "$kind" "$id")

    if [[ $state == "running" || -n $pid ]]; then
        printf 'running\n'
    else
        printf 'stopped\n'
    fi
}

show_status() {
    local has_instance=0
    local id
    local kind
    local state
    local pid
    local autostart

    ensure_dirs

    echo "========================================"
    echo " Managed binaries"
    show_binary_status
    echo
    echo " Instances"

    for id in $(list_instance_ids); do
        has_instance=1
        kind=$(kind_for_id "$id")
        state=$(status_text_for_instance "$kind" "$id")
        pid=$(service_pid "$kind" "$id")
        if autostart_enabled "$kind" "$id"; then
            autostart="on"
        else
            autostart="off"
        fi
        print_instance_summary "$id" "$kind" "$state" "$pid" "$autostart"
    done

    if [[ $has_instance -eq 0 ]]; then
        echo "  none"
    fi
    echo "========================================"
}

show_instance_details() {
    local id=$1
    local kind
    local state
    local pid
    local last_exit
    local autostart

    instance_exists "$id" || {
        error "Unknown instance ID: $id"
        return 1
    }

    kind=$(kind_for_id "$id")
    state=$(status_text_for_instance "$kind" "$id")
    pid=$(service_pid "$kind" "$id")
    last_exit=$(service_last_exit "$kind" "$id")
    if autostart_enabled "$kind" "$id"; then
        autostart="enabled"
    else
        autostart="disabled"
    fi

    echo "ID: $id"
    echo "Kind: $kind"
    echo "Mode: $(mode_for_id "$id")"
    echo "Label: $(label_for_kind "$kind" "$id")"
    echo "State: $state"
    [[ -n $pid ]] && echo "PID: $pid"
    [[ -n $last_exit ]] && echo "Last exit code: $last_exit"
    echo "Autostart: $autostart"
    echo "Config: $(config_path_for_id "$id")"
    echo "Managed plist: $(plist_source_path "$kind" "$id")"
    echo "LaunchAgent: $(launchagent_plist_path "$kind" "$id")"
    echo "Stdout log: $(stdout_log_path "$kind" "$id")"
    echo "Stderr log: $(stderr_log_path "$kind" "$id")"
}

list_instances() {
    local has_instance=0
    local id
    local kind
    local state
    local pid
    local autostart

    ensure_dirs

    for id in $(list_instance_ids); do
        has_instance=1
        kind=$(kind_for_id "$id")
        state=$(status_text_for_instance "$kind" "$id")
        pid=$(service_pid "$kind" "$id")
        if autostart_enabled "$kind" "$id"; then
            autostart="on"
        else
            autostart="off"
        fi
        print_instance_summary "$id" "$kind" "$state" "$pid" "$autostart"
    done

    [[ $has_instance -eq 1 ]]
}

show_logs() {
    local id=${1:-}
    local kind
    local stdout_path
    local stderr_path

    ensure_dirs

    if [[ -z $id ]]; then
        local files=("$FLOO_LOG_DIR"/*.log)
        if [[ ${#files[@]} -eq 0 ]]; then
            error "No Floo logs found."
            return 1
        fi
        tail -n 50 -f "${files[@]}"
        return 0
    fi

    instance_exists "$id" || {
        error "Unknown instance ID: $id"
        return 1
    }

    kind=$(kind_for_id "$id")
    stdout_path=$(stdout_log_path "$kind" "$id")
    stderr_path=$(stderr_log_path "$kind" "$id")
    touch "$stdout_path" "$stderr_path"
    tail -n 50 -f "$stdout_path" "$stderr_path"
}

run_for_all_instances() {
    local action=$1
    local id
    local kind
    local ran=0

    for id in $(list_instance_ids); do
        kind=$(kind_for_id "$id")
        "$action" "$kind" "$id" || return 1
        ran=1
    done

    [[ $ran -eq 1 ]]
}

handle_import_client() {
    local preset=""
    local client_target=""
    local arg
    local preset_json_value
    local server_addr
    local cipher
    local psk_value
    local token_value
    local proxy_mode
    local map_name
    local mode_value
    local client_id
    local target

    shift
    for arg in "$@"; do
        if [[ $arg == --preset=* ]]; then
            preset=$(parse_flag_value "$arg" "--preset")
        elif [[ $arg == --client-target=* ]]; then
            client_target=$(parse_flag_value "$arg" "--client-target")
        else
            error "Unsupported argument: $arg"
            return 1
        fi
    done

    if [[ -z $preset || -z $client_target ]]; then
        error "Usage: import-client --preset=... --client-target=IP:PORT"
        return 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        error "python3 is required to parse --preset."
        return 1
    fi

    preset_json_value=$(base64_url_decode "$preset") || {
        error "Failed to decode --preset."
        return 1
    }

    server_addr=$(json_get_string "$preset_json_value" "server") || { error "Failed to parse preset field: server"; return 1; }
    cipher=$(json_get_string "$preset_json_value" "cipher") || { error "Failed to parse preset field: cipher"; return 1; }
    psk_value=$(json_get_string "$preset_json_value" "psk") || { error "Failed to parse preset field: psk"; return 1; }
    token_value=$(json_get_string "$preset_json_value" "token") || { error "Failed to parse preset field: token"; return 1; }
    proxy_mode=$(json_get_string "$preset_json_value" "proxy_mode") || { error "Failed to parse preset field: proxy_mode"; return 1; }
    map_name=$(json_get_string "$preset_json_value" "map_name") || { error "Failed to parse preset field: map_name"; return 1; }
    mode_value=$(json_get_string "$preset_json_value" "mode") || { error "Failed to parse preset field: mode"; return 1; }
    client_id=$(json_get_string "$preset_json_value" "client_id") || { error "Failed to parse preset field: client_id"; return 1; }

    [[ -n $server_addr && -n $map_name && -n $client_id ]] || {
        error "Preset is missing required fields."
        return 1
    }
    [[ $mode_value == "1" || $mode_value == "2" ]] || {
        error "Preset contains an invalid mode value."
        return 1
    }
    [[ $proxy_mode == "1" || $proxy_mode == "2" ]] || {
        error "Preset contains an invalid proxy mode."
        return 1
    }
    valid_id "$client_id" || {
        error "Preset contains an invalid client ID."
        return 1
    }
    instance_exists "$client_id" && {
        error "Instance ID already exists: $client_id"
        return 1
    }

    psk=$psk_value
    token=$token_value
    target=$(format_target "$client_target")
    ensure_binary_for_kind client || return 1
    write_client_config "$client_id" "$server_addr" "$cipher" "$mode_value" "$proxy_mode" "$map_name" "$target"
    start_instance "client" "$client_id" || return 1

    success "Client instance created and started: $client_id"
}

do_add() {
    local add_type
    local id
    local tunnel_port
    local proxy_mode
    local port_input
    local map_name
    local input_psk
    local input_token
    local cipher
    local mode_value
    local server_addr
    local public_server_addr
    local suggested_target
    local client_target_override

    echo "--- Add instance ---"
    echo "1. Server (floos)"
    echo "2. Client (flooc)"
    read -r -p "Choose type: " add_type
    [[ $add_type == "1" || $add_type == "2" ]] || { error "Invalid type."; return 1; }

    read -r -p "Config ID (letters/digits/_/-): " id
    valid_id "$id" || { error "Invalid ID."; return 1; }
    instance_exists "$id" && { error "ID already exists: $id"; return 1; }

    if [[ $add_type == "1" ]]; then
        read -r -p "Tunnel listen port: " tunnel_port
        [[ $tunnel_port =~ ^[0-9]+$ ]] || { error "Tunnel port must be numeric."; return 1; }
        read -r -p "Proxy mode (1=forward, 2=reverse): " proxy_mode
        [[ $proxy_mode == "1" || $proxy_mode == "2" ]] || { error "Invalid proxy mode."; return 1; }
        read -r -p "Target/listener address (port or IP:PORT): " port_input
        read -r -p "Service map name: " map_name
        read -r -p "PSK (blank = generate): " input_psk
        read -r -p "Token (blank = generate): " input_token
        cipher=$(select_cipher)
        mode_value=$(select_mode_value)
        [[ -n $mode_value ]] || { error "Invalid mode."; return 1; }
        gen_creds "$input_psk" "$input_token" || return 1
        write_server_config "$id" "$tunnel_port" "$cipher" "$mode_value" "$proxy_mode" "$map_name" "$port_input"
        start_instance "server" "$id" || return 1

        read -r -p "Public server address for import-client command (blank to skip): " public_server_addr
        if [[ -n $public_server_addr ]]; then
            suggested_target=$(suggest_client_target "$port_input")
            read -r -p "Client target for import-client command [${suggested_target}]: " client_target_override
            [[ -n $client_target_override ]] && suggested_target="$client_target_override"
            build_client_import_command "$public_server_addr" "$cipher" "$psk" "$token" "$proxy_mode" "$map_name" "$mode_value" "$id" "$suggested_target"
        fi
    else
        read -r -p "Tunnel server address (IP:PORT): " server_addr
        read -r -p "Proxy mode (1=forward, 2=reverse): " proxy_mode
        [[ $proxy_mode == "1" || $proxy_mode == "2" ]] || { error "Invalid proxy mode."; return 1; }
        read -r -p "Target address (port or IP:PORT): " port_input
        read -r -p "Service map name: " map_name
        read -r -p "PSK (blank = generate): " input_psk
        read -r -p "Token (blank = generate): " input_token
        cipher=$(select_cipher)
        mode_value=$(select_mode_value)
        [[ -n $mode_value ]] || { error "Invalid mode."; return 1; }
        gen_creds "$input_psk" "$input_token" || return 1
        write_client_config "$id" "$server_addr" "$cipher" "$mode_value" "$proxy_mode" "$map_name" "$port_input"
        start_instance "client" "$id" || return 1
    fi

    success "Instance created and started: $id"
    note "PSK: $psk"
    note "Token: $token"
}

delete_instance_by_id() {
    local id=$1
    local kind

    instance_exists "$id" || {
        error "Unknown instance ID: $id"
        return 1
    }

    kind=$(kind_for_id "$id")
    disable_autostart_instance "$kind" "$id"
    stop_instance "$kind" "$id" >/dev/null 2>&1 || true
    remove_instance_files "$kind" "$id"
    success "Deleted instance: $id"
}

do_delete() {
    local opt
    local id
    local confirm
    local all_id

    echo "1. Delete one instance"
    echo "2. Delete all instances"
    read -r -p "Choose: " opt

    case $opt in
        1)
            read -r -p "Instance ID: " id
            read -r -p "Delete $id? [y/N]: " confirm
            [[ $confirm == "y" ]] || return 0
            delete_instance_by_id "$id"
            ;;
        2)
            read -r -p "Delete ALL instances? [y/N]: " confirm
            [[ $confirm == "y" ]] || return 0
            if ! list_instances >/dev/null 2>&1; then
                note "No instances to delete."
                return 0
            fi
            for all_id in $(list_instance_ids); do
                delete_instance_by_id "$all_id" || return 1
            done
            ;;
        *)
            error "Invalid choice."
            return 1
            ;;
    esac
}

do_ctrl() {
    local action=$1
    local opt
    local id
    local kind

    echo "1. ${action} one instance"
    echo "2. ${action} all instances"
    read -r -p "Choose: " opt

    case $opt in
        1)
            read -r -p "Instance ID: " id
            instance_exists "$id" || { error "Unknown instance ID: $id"; return 1; }
            kind=$(kind_for_id "$id")
            case $action in
                start) start_instance "$kind" "$id" ;;
                stop) stop_instance "$kind" "$id" ;;
                restart) restart_instance "$kind" "$id" ;;
            esac
            success "${action} completed for $id"
            ;;
        2)
            if ! list_instances >/dev/null 2>&1; then
                note "No instances to operate on."
                return 0
            fi
            for id in $(list_instance_ids); do
                kind=$(kind_for_id "$id")
                case $action in
                    start) start_instance "$kind" "$id" ;;
                    stop) stop_instance "$kind" "$id" ;;
                    restart) restart_instance "$kind" "$id" ;;
                esac || return 1
            done
            success "${action} completed for all instances"
            ;;
        *)
            error "Invalid choice."
            return 1
            ;;
    esac
}

toggle_autostart_all() {
    local action=$1
    local id
    local kind

    if ! list_instances >/dev/null 2>&1; then
        note "No instances available."
        return 0
    fi

    for id in $(list_instance_ids); do
        kind=$(kind_for_id "$id")
        if [[ $action == "enable" ]]; then
            enable_autostart_instance "$kind" "$id" || return 1
        else
            disable_autostart_instance "$kind" "$id" || return 1
        fi
    done
}

show_help() {
    cat <<'EOF'
Usage:
  floo-macos.sh add
  floo-macos.sh delete <id|--all>
  floo-macos.sh start <id|--all>
  floo-macos.sh stop <id|--all>
  floo-macos.sh restart <id|--all>
  floo-macos.sh status [id]
  floo-macos.sh list
  floo-macos.sh logs [id]
  floo-macos.sh enable-autostart <id|--all>
  floo-macos.sh disable-autostart <id|--all>
  floo-macos.sh import-client --preset=... --client-target=IP:PORT
  floo-macos.sh help

Notes:
  - Managed data lives under ~/Library/Application Support/Floo
  - Logs live under ~/Library/Logs/Floo
  - Login autostart is installed into ~/Library/LaunchAgents
EOF
}

handle_named_instance_command() {
    local action=$1
    local target_id=${2:-}
    local kind

    if [[ -z $target_id ]]; then
        error "${action} requires an instance ID or --all."
        return 1
    fi

    if [[ $target_id == "--all" ]]; then
        if ! list_instances >/dev/null 2>&1; then
            note "No instances available."
            return 0
        fi
        case $action in
            start|stop|restart)
                for target_id in $(list_instance_ids); do
                    kind=$(kind_for_id "$target_id")
                    case $action in
                        start) start_instance "$kind" "$target_id" ;;
                        stop) stop_instance "$kind" "$target_id" ;;
                        restart) restart_instance "$kind" "$target_id" ;;
                    esac || return 1
                done
                ;;
            delete)
                for target_id in $(list_instance_ids); do
                    delete_instance_by_id "$target_id" || return 1
                done
                ;;
        esac
        return 0
    fi

    instance_exists "$target_id" || {
        error "Unknown instance ID: $target_id"
        return 1
    }

    kind=$(kind_for_id "$target_id")
    case $action in
        start) start_instance "$kind" "$target_id" ;;
        stop) stop_instance "$kind" "$target_id" ;;
        restart) restart_instance "$kind" "$target_id" ;;
        delete) delete_instance_by_id "$target_id" ;;
    esac
}

handle_autostart_command() {
    local action=$1
    local target_id=${2:-}
    local kind

    if [[ -z $target_id ]]; then
        error "${action}-autostart requires an instance ID or --all."
        return 1
    fi

    if [[ $target_id == "--all" ]]; then
        toggle_autostart_all "$action"
        return $?
    fi

    instance_exists "$target_id" || {
        error "Unknown instance ID: $target_id"
        return 1
    }

    kind=$(kind_for_id "$target_id")
    if [[ $action == "enable" ]]; then
        enable_autostart_instance "$kind" "$target_id"
    else
        disable_autostart_instance "$kind" "$target_id"
    fi
}

if is_command_mode "$@"; then
    case $1 in
        add)
            do_add
            ;;
        delete)
            handle_named_instance_command delete "${2:-}"
            ;;
        start)
            handle_named_instance_command start "${2:-}"
            ;;
        stop)
            handle_named_instance_command stop "${2:-}"
            ;;
        restart)
            handle_named_instance_command restart "${2:-}"
            ;;
        status)
            if [[ -n ${2:-} ]]; then
                show_instance_details "$2"
            else
                show_status
            fi
            ;;
        list)
            if ! list_instances; then
                note "No instances found."
            fi
            ;;
        logs)
            show_logs "${2:-}"
            ;;
        enable-autostart)
            handle_autostart_command enable "${2:-}"
            ;;
        disable-autostart)
            handle_autostart_command disable "${2:-}"
            ;;
        import-client)
            handle_import_client "$@"
            ;;
        help|-h|--help)
            show_help
            ;;
        *)
            error "Unsupported command: $1"
            show_help
            exit 1
            ;;
    esac
    exit $?
fi

while true; do
    show_status
    echo "Floo macOS launchd manager"
    echo "========================================"
    echo "1. Add instance"
    echo "2. Delete instance"
    echo "3. Start instance"
    echo "4. Stop instance"
    echo "5. Restart instance"
    echo "6. View logs"
    echo "7. List instances"
    echo "8. Enable login autostart"
    echo "9. Disable login autostart"
    echo "0. Exit"
    echo "========================================"
    read -r -p "Choose [0-9]: " main_opt

    case $main_opt in
        1) do_add ;;
        2) do_delete ;;
        3) do_ctrl start ;;
        4) do_ctrl stop ;;
        5) do_ctrl restart ;;
        6)
            read -r -p "Instance ID (blank = all Floo logs): " id
            show_logs "$id"
            ;;
        7)
            if ! list_instances; then
                note "No instances found."
            fi
            ;;
        8)
            read -r -p "Instance ID (or --all): " id
            handle_autostart_command enable "$id" && success "Autostart enabled."
            ;;
        9)
            read -r -p "Instance ID (or --all): " id
            handle_autostart_command disable "$id" && success "Autostart disabled."
            ;;
        0) exit 0 ;;
        *) error "Invalid option." ;;
    esac

done
