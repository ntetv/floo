#!/bin/bash

# ====================================================
# Floo 隧道管理脚本
# ====================================================

# 发布配置
FLOO_GITHUB_REPO="ntetv/floo"
FLOO_RELEASE_BASE_URL="https://gh.5ieee.com/github.com/${FLOO_GITHUB_REPO}/releases/latest/download"
# 可选：脚本上传到 GitHub 源码目录后，填写原始文件下载地址以输出客户端一键部署命令
FLOO_SCRIPT_URL="https://raw.githubusercontent.com/ntetv/floo/main/floo.sh"

# 配置路径
FLOO_CONF_DIR="/etc/floo"
FLOO_BIN_SERVER="/usr/local/bin/floos"
FLOO_BIN_CLIENT="/usr/local/bin/flooc"
FLOO_BIN_SERVER_LEGACY="/usr/local/bin/flos"
FLOO_BIN_CLIENT_LEGACY="/usr/local/bin/floc"
SYSTEMD_UNIT_DIR="/etc/systemd/system"

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
PLAIN='\033[0m'

shopt -s nullglob

# 权限检查
[[ $EUID -ne 0 ]] && echo -e "${RED}错误：必须以 root 权限运行！${PLAIN}" && exit 1

# --- 内部工具函数 ---

# 生成加密凭据
gen_creds() {
    local provided_psk=$1
    local provided_token=$2
    [[ -z $provided_psk ]] && psk=$(openssl rand -base64 32) || psk=$provided_psk
    [[ -z $provided_token ]] && token=$(openssl rand -hex 16) || token=$provided_token
}

# 校验实例 ID，避免生成异常路径和 unit 名
valid_id() {
    [[ $1 =~ ^[A-Za-z0-9_-]+$ ]]
}

# 格式化目标地址：纯端口默认回环，其余输入原样保留
format_target() {
    local input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo "127.0.0.1:$input"
    else
        echo "$input"
    fi
}

# 格式化监听地址：纯端口默认绑定全部地址，其余输入原样保留
format_listener() {
    local input=$1
    if [[ $input =~ ^[0-9]+$ ]]; then
        echo "0.0.0.0:$input"
    else
        echo "$input"
    fi
}

# 格式化客户端目标地址：默认沿用端口并回环到本地
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

release_asset_name() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64|amd64) echo "floo-x86_64-linux-musl.tar.gz" ;;
        aarch64|arm64) echo "floo-aarch64-linux-musl.tar.gz" ;;
        *)
            echo -e "${RED}不支持的架构: $arch${PLAIN}" >&2
            return 1
            ;;
    esac
}

# 下载单个文件，固定走 gh.5ieee.com 加速地址
fetch_url() {
    local url=$1
    local output=$2

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --show-progress --no-check-certificate "$url" -O "$output"
    else
        echo -e "${RED}错误：缺少 curl 或 wget，无法下载安装包。${PLAIN}"
        return 1
    fi
}

download_release_asset() {
    local asset_name=$1
    local output_path=$2
    local asset_url="${FLOO_RELEASE_BASE_URL}/${asset_name}"

    echo -e "${YELLOW}通过 gh.5ieee.com 下载最新版: ${asset_name}${PLAIN}"
    if fetch_url "$asset_url" "$output_path"; then
        return 0
    fi

    echo -e "${RED}错误：下载失败，请检查加速地址或发布文件是否有效。${PLAIN}"
    return 1
}

install_release_binaries() {
    local asset_name=$1
    local install_kind=${2:-both}
    local tmp_dir
    tmp_dir=$(mktemp -d) || return 1

    install -d "$FLOO_CONF_DIR" "$(dirname "$FLOO_BIN_SERVER")"

    if ! download_release_asset "$asset_name" "$tmp_dir/$asset_name"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    if ! tar -xzf "$tmp_dir/$asset_name" -C "$tmp_dir"; then
        echo -e "${RED}错误：解压安装包失败。${PLAIN}"
        rm -rf "$tmp_dir"
        return 1
    fi

    if [[ ! -f "$tmp_dir/floos" || ! -f "$tmp_dir/flooc" ]]; then
        echo -e "${RED}错误：安装包内未找到 floos/flooc 二进制文件。${PLAIN}"
        rm -rf "$tmp_dir"
        return 1
    fi

    case $install_kind in
        server)
            install -m 755 "$tmp_dir/floos" "$FLOO_BIN_SERVER"
            ln -sf "$FLOO_BIN_SERVER" "$FLOO_BIN_SERVER_LEGACY"
            ;;
        client)
            install -m 755 "$tmp_dir/flooc" "$FLOO_BIN_CLIENT"
            ln -sf "$FLOO_BIN_CLIENT" "$FLOO_BIN_CLIENT_LEGACY"
            ;;
        both)
            install -m 755 "$tmp_dir/floos" "$FLOO_BIN_SERVER"
            install -m 755 "$tmp_dir/flooc" "$FLOO_BIN_CLIENT"
            ln -sf "$FLOO_BIN_SERVER" "$FLOO_BIN_SERVER_LEGACY"
            ln -sf "$FLOO_BIN_CLIENT" "$FLOO_BIN_CLIENT_LEGACY"
            ;;
        *)
            echo -e "${RED}错误：未知安装类型 $install_kind${PLAIN}"
            rm -rf "$tmp_dir"
            return 1
            ;;
    esac

    rm -rf "$tmp_dir"
}

service_unit_name() {
    local base=$1
    local id=$2
    echo "${base}@${id}.service"
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

service_base_for_kind() {
    if [[ $1 == "server" ]]; then
        echo "floos"
    else
        echo "flooc"
    fi
}

service_role_for_kind() {
    if [[ $1 == "server" ]]; then
        echo "服务端"
    else
        echo "客户端"
    fi
}

service_unit_for_kind() {
    local kind=$1
    local id=$2
    echo "$(service_unit_name "$(service_base_for_kind "$kind")" "$id")"
}

service_unit_for_file() {
    local file=$1
    local id
    local kind

    id=$(basename "$file" .toml)
    kind=$(config_kind_value "$file")
    service_unit_for_kind "$kind" "$id"
}

control_config_unit() {
    local file=$1
    shift
    systemctl "$@" "$(service_unit_for_file "$file")" 2>/dev/null
}

control_all_units() {
    local toml
    local found=0

    for toml in "$FLOO_CONF_DIR"/*.toml; do
        found=1
        control_config_unit "$toml" "$@"
    done

    [[ $found -eq 1 ]]
}

collect_running_units() {
    local filter_kind=${1:-both}
    local toml
    local unit
    local kind

    for toml in "$FLOO_CONF_DIR"/*.toml; do
        kind=$(config_kind_value "$toml")
        case $filter_kind in
            both) ;;
            server|client)
                [[ $kind == "$filter_kind" ]] || continue
                ;;
        esac
        unit=$(service_unit_for_kind "$kind" "$(basename "$toml" .toml)")
        if systemctl is-active --quiet "$unit"; then
            printf '%s\n' "$unit"
        fi
    done
}

write_service_unit() {
    local unit_path=$1
    local binary_path=$2
    local description=$3
    local id=$4
    local extra_limits=$5

    cat <<EOF > "$unit_path"
[Unit]
Description=${description} - ${id}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${binary_path} ${FLOO_CONF_DIR}/${id}.toml
Restart=always
RestartSec=5
LimitNOFILE=1048576
User=root
OOMScoreAdjust=-1000
${extra_limits}

[Install]
WantedBy=multi-user.target
EOF
}

install_instance_unit() {
    local kind=$1
    local id=$2
    local mode_value=$3
    local unit_path="${SYSTEMD_UNIT_DIR}/$(service_unit_for_kind "$kind" "$id")"
    local binary_path
    local description
    local extra_limits=""

    if [[ "$kind" == "server" ]]; then
        binary_path="$FLOO_BIN_SERVER"
        description="Floo Server Instance"
    else
        binary_path="$FLOO_BIN_CLIENT"
        description="Floo Client Instance"
    fi

    case $mode_value in
        1)
            description="${description} (Mode 1)"
            ;;
        2)
            description="${description} (Mode 2)"
            extra_limits=$'LimitNOFILE=infinity\nLimitNPROC=infinity\nTasksMax=infinity'
            ;;
    esac

    write_service_unit "$unit_path" "$binary_path" "$description" "$id" "$extra_limits"
}

install_instance_units_from_configs() {
    local install_kind=${1:-both}
    local toml
    local kind
    local id
    local mode_value

    for toml in "$FLOO_CONF_DIR"/*.toml; do
        id=$(basename "$toml" .toml)
        kind=$(config_kind_value "$toml")
        case $install_kind in
            both) ;;
            server|client)
                [[ $kind == "$install_kind" ]] || continue
                ;;
        esac
        mode_value=$(config_mode_value "$toml")
        install_instance_unit "$kind" "$id" "$mode_value"
    done
}

restart_running_units() {
    local running_units=$1
    local unit
    local restart_failed=0

    [[ -z $running_units ]] && return 0

    echo -e "${YELLOW}检测到运行中的实例，正在重启使新版生效...${PLAIN}"
    while IFS= read -r unit; do
        [[ -z $unit ]] && continue
        if ! systemctl restart "$unit"; then
            echo -e "${RED}警告：$unit 重启失败，请执行 journalctl -u $unit -f 查看原因。${PLAIN}"
            restart_failed=1
        fi
    done <<< "$running_units"

    return $restart_failed
}

remove_instance_unit() {
    local kind=$1
    local id=$2
    rm -f "${SYSTEMD_UNIT_DIR}/$(service_unit_for_kind "$kind" "$id")"
}

show_all_logs() {
    local args=()
    local toml
    local unit

    for toml in "$FLOO_CONF_DIR"/*.toml; do
        unit=$(service_unit_for_file "$toml")
        args+=( -u "$unit" )
    done

    if [[ ${#args[@]} -eq 0 ]]; then
        journalctl -f
    else
        journalctl "${args[@]}" -f
    fi
}

select_mode_value() {
    local choice

    echo "性能模式:"
    echo "1. 低并发（写入 mode = 1）"
    echo "2. 高并发（写入 mode = 2，并使用高并发 service 参数）"
    read -r -p "选择 [1-2]: " choice

    case $choice in
        1|2) echo "$choice" ;;
        *) echo "" ;;
    esac
}

select_install_kind() {
    local choice

    echo "安装目标:"
    echo "1. 仅服务端 (floos)"
    echo "2. 仅客户端 (flooc)"
    echo "3. 服务端 + 客户端"
    read -r -p "选择 [1-3]: " choice

    case $choice in
        1) echo "server" ;;
        2) echo "client" ;;
        3) echo "both" ;;
        *) echo "" ;;
    esac
}

append_mode_if_needed() {
    local config_path=$1
    local mode_value=$2
    printf 'mode = %s\n\n' "$mode_value" >> "$config_path"
}

is_command_mode() {
    [[ $# -gt 0 && $1 != [0-9] ]]
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
    echo -e "${YELLOW}客户端一键部署命令（仅需修改 --client-target=...）：${PLAIN}"
    echo "bash <(curl -fsSL \"$FLOO_SCRIPT_URL\") import-client --preset=$preset --client-target=$suggested_target"
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
    local asset_name

    shift
    for arg in "$@"; do
        if [[ $arg == --preset=* ]]; then
            preset=$(parse_flag_value "$arg" "--preset")
        elif [[ $arg == --client-target=* ]]; then
            client_target=$(parse_flag_value "$arg" "--client-target")
        else
            echo -e "${RED}错误：不支持的参数 $arg${PLAIN}"
            return 1
        fi
    done

    if [[ -z $preset || -z $client_target ]]; then
        echo -e "${RED}错误：用法为 import-client --preset=... --client-target=IP:PORT${PLAIN}"
        return 1
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}错误：缺少 python3，无法解析客户端预设。${PLAIN}"
        return 1
    fi

    if ! preset_json_value=$(base64_url_decode "$preset"); then
        echo -e "${RED}错误：无法解码 --preset 参数。${PLAIN}"
        return 1
    fi

    server_addr=$(json_get_string "$preset_json_value" "server") || {
        echo -e "${RED}错误：无法解析预设中的 server。${PLAIN}"
        return 1
    }
    cipher=$(json_get_string "$preset_json_value" "cipher") || {
        echo -e "${RED}错误：无法解析预设中的 cipher。${PLAIN}"
        return 1
    }
    psk_value=$(json_get_string "$preset_json_value" "psk") || {
        echo -e "${RED}错误：无法解析预设中的 psk。${PLAIN}"
        return 1
    }
    token_value=$(json_get_string "$preset_json_value" "token") || {
        echo -e "${RED}错误：无法解析预设中的 token。${PLAIN}"
        return 1
    }
    proxy_mode=$(json_get_string "$preset_json_value" "proxy_mode") || {
        echo -e "${RED}错误：无法解析预设中的 proxy_mode。${PLAIN}"
        return 1
    }
    map_name=$(json_get_string "$preset_json_value" "map_name") || {
        echo -e "${RED}错误：无法解析预设中的 map_name。${PLAIN}"
        return 1
    }
    mode_value=$(json_get_string "$preset_json_value" "mode") || {
        echo -e "${RED}错误：无法解析预设中的 mode。${PLAIN}"
        return 1
    }
    client_id=$(json_get_string "$preset_json_value" "client_id") || {
        echo -e "${RED}错误：无法解析预设中的 client_id。${PLAIN}"
        return 1
    }

    [[ -n $server_addr && -n $map_name && -n $client_id ]] || {
        echo -e "${RED}错误：预设缺少必要字段。${PLAIN}"
        return 1
    }
    [[ $mode_value == "1" || $mode_value == "2" ]] || {
        echo -e "${RED}错误：预设中的 mode 非法。${PLAIN}"
        return 1
    }
    [[ $proxy_mode == "1" || $proxy_mode == "2" ]] || {
        echo -e "${RED}错误：预设中的代理模式非法。${PLAIN}"
        return 1
    }
    valid_id "$client_id" || {
        echo -e "${RED}错误：预设中的客户端 ID 非法。${PLAIN}"
        return 1
    }
    [[ ! -f "$FLOO_CONF_DIR/$client_id.toml" ]] || {
        echo -e "${RED}错误：客户端 ID $client_id 已存在。${PLAIN}"
        return 1
    }

    target=$(format_target "$client_target")

    if ! asset_name=$(release_asset_name); then
        return 1
    fi

    if ! install_release_binaries "$asset_name" "client"; then
        return 1
    fi

    cat <<EOF > "$FLOO_CONF_DIR/$client_id.toml"
# floo_role = client
server = "$server_addr"
cipher = "$cipher"
psk = "$psk_value"
token = "$token_value"

EOF
    append_mode_if_needed "$FLOO_CONF_DIR/$client_id.toml" "$mode_value"
    if [[ "$proxy_mode" == "1" ]]; then
        echo -e "[services]\n$map_name = \"$target\"" >> "$FLOO_CONF_DIR/$client_id.toml"
    else
        echo -e "[reverse_services]\n$map_name = \"$target\"" >> "$FLOO_CONF_DIR/$client_id.toml"
    fi
    chmod 600 "$FLOO_CONF_DIR/$client_id.toml"
    start_instance_unit "client" "$client_id" "$mode_value"

    echo -e "${GREEN}客户端实例 $client_id 创建并启动成功！${PLAIN}"
}

start_instance_unit() {
    local kind=$1
    local id=$2
    local mode_value=$3
    local unit_name

    install_instance_unit "$kind" "$id" "$mode_value"
    unit_name=$(service_unit_for_kind "$kind" "$id")
    systemctl daemon-reload
    systemctl enable --now "$unit_name"
}

# --- 核心菜单功能 ---

# 1. 安装新版
do_install() {
    local asset_name
    local install_kind
    local running_units=""

    echo -e "${YELLOW}正在安装 Floo 新版...${PLAIN}"
    echo -e "${YELLOW}发布源: ${FLOO_GITHUB_REPO} (gh.5ieee.com latest)${PLAIN}"

    install_kind=$(select_install_kind)
    [[ -z $install_kind ]] && echo -e "${RED}错误：安装目标只能选择 1、2 或 3。${PLAIN}" && return 1

    if ! asset_name=$(release_asset_name); then
        return 1
    fi

    running_units=$(collect_running_units "$install_kind")

    if ! install_release_binaries "$asset_name" "$install_kind"; then
        return 1
    fi

    install_instance_units_from_configs "$install_kind"

    systemctl daemon-reload
    if restart_running_units "$running_units"; then
        echo -e "${GREEN}安装完成！对应角色的二进制与实例服务已更新。${PLAIN}"
    else
        echo -e "${YELLOW}安装已完成，但有实例重启失败，请检查对应日志。${PLAIN}"
    fi
}

# 3. 添加实例
do_add() {
    local add_type
    local mode
    local id
    local tunnel_port
    local port_input
    local map_name
    local server_addr
    local input_psk
    local input_token
    local cipher_opt
    local cipher
    local target
    local listener
    local mode_value
    local suggested_target
    local public_server_addr

    echo -e "${YELLOW}--- 添加新实例 ---${PLAIN}"
    echo "1. 添加服务端 (floos)"
    echo "2. 添加客户端 (flooc)"
    read -r -p "选择类型: " add_type
    [[ "$add_type" != "1" && "$add_type" != "2" ]] && echo -e "${RED}错误：无效类型。${PLAIN}" && return

    read -r -p "配置 ID (字母/数字/下划线/短横线): " id
    valid_id "$id" || { echo -e "${RED}错误：ID 只能包含字母、数字、下划线和短横线。${PLAIN}"; return; }
    [[ -f "$FLOO_CONF_DIR/$id.toml" ]] && echo -e "${RED}错误：ID $id 已存在！${PLAIN}" && return

    if [[ "$add_type" == "1" ]]; then
        # --- 服务端逻辑 ---
        read -r -p "隧道监听端口: " tunnel_port
        read -r -p "代理模式 (1.正向 / 2.反向): " mode
        [[ "$mode" != "1" && "$mode" != "2" ]] && echo -e "${RED}错误：无效模式。${PLAIN}" && return

        read -r -p "模式地址 (正向填目标端口或 IP:PORT；反向填监听端口或 IP:PORT): " port_input
        read -r -p "代理端口映射名: " map_name
        read -r -p "PSK (留空自动生成): " input_psk
        read -r -p "Token (留空自动生成): " input_token
        echo "加密算法 (1.none / 2.chacha20poly1305): "
        read -r -p "选择 [1-2，默认1]: " cipher_opt
        [[ "$cipher_opt" == "2" ]] && cipher="chacha20poly1305" || cipher="none"

        mode_value=$(select_mode_value)
        [[ -z "$mode_value" ]] && echo -e "${RED}错误：mode 只能选择 1 或 2。${PLAIN}" && return
        gen_creds "$input_psk" "$input_token"
        target=$(format_target "$port_input")
        listener=$(format_listener "$port_input")

        cat <<EOF > "$FLOO_CONF_DIR/$id.toml"
# floo_role = server
bind = "0.0.0.0"
port = $tunnel_port
cipher = "$cipher"
psk = "$psk"
token = "$token"

EOF
        append_mode_if_needed "$FLOO_CONF_DIR/$id.toml" "$mode_value"
        if [[ "$mode" == "1" ]]; then
            echo -e "[services]\n$map_name = \"$target\"" >> "$FLOO_CONF_DIR/$id.toml"
        else
            echo -e "[reverse_services]\n$map_name = \"$listener\"" >> "$FLOO_CONF_DIR/$id.toml"
        fi
        chmod 600 "$FLOO_CONF_DIR/$id.toml"
        start_instance_unit "server" "$id" "$mode_value"
        suggested_target=$(suggest_client_target "$port_input")
        read -r -p "客户端连接地址 (默认使用本机 IP:端口，用于生成一键部署命令): " public_server_addr
        [[ -z $public_server_addr ]] && public_server_addr="$(hostname -I 2>/dev/null | awk '{print $1}'):$tunnel_port"
        [[ -z $public_server_addr ]] && public_server_addr="127.0.0.1:$tunnel_port"
        build_client_import_command "$public_server_addr" "$cipher" "$psk" "$token" "$mode" "$map_name" "$mode_value" "$id-client" "$suggested_target"
    else
        # --- 客户端逻辑 ---
        read -r -p "服务端隧道地址 (IP:端口): " server_addr
        read -r -p "代理模式 (1.正向 / 2.反向): " mode
        [[ "$mode" != "1" && "$mode" != "2" ]] && echo -e "${RED}错误：无效模式。${PLAIN}" && return

        read -r -p "模式地址 (如 22 或 127.0.0.1:22): " port_input
        read -r -p "代理端口映射名: " map_name
        read -r -p "PSK (必填/留空自动): " input_psk
        read -r -p "Token (必填/留空自动): " input_token
        echo "加密算法 (1.none / 2.chacha20poly1305): "
        read -r -p "选择 [1-2，默认1]: " cipher_opt
        [[ "$cipher_opt" == "2" ]] && cipher="chacha20poly1305" || cipher="none"

        mode_value=$(select_mode_value)
        [[ -z "$mode_value" ]] && echo -e "${RED}错误：mode 只能选择 1 或 2。${PLAIN}" && return
        gen_creds "$input_psk" "$input_token"
        target=$(format_target "$port_input")

        cat <<EOF > "$FLOO_CONF_DIR/$id.toml"
# floo_role = client
server = "$server_addr"
cipher = "$cipher"
psk = "$psk"
token = "$token"

EOF
        append_mode_if_needed "$FLOO_CONF_DIR/$id.toml" "$mode_value"
        if [[ "$mode" == "1" ]]; then
            echo -e "[services]\n$map_name = \"$target\"" >> "$FLOO_CONF_DIR/$id.toml"
        else
            echo -e "[reverse_services]\n$map_name = \"$target\"" >> "$FLOO_CONF_DIR/$id.toml"
        fi
        chmod 600 "$FLOO_CONF_DIR/$id.toml"
        start_instance_unit "client" "$id" "$mode_value"
    fi

    echo -e "${GREEN}实例 $id 创建并启动成功！${PLAIN}"
    echo -e "${YELLOW}PSK: $psk | Token: $token${PLAIN}"
}

# 4. 删除实例
do_delete() {
    local opt
    local id
    local conf
    local cfg_file

    echo "1. 删除指定 ID"
    echo "2. 删除全部 ID"
    read -r -p "选择: " opt

    if [[ "$opt" == "1" ]]; then
        read -r -p "输入 ID: " id
        cfg_file="$FLOO_CONF_DIR/$id.toml"
        [[ ! -f "$cfg_file" ]] && echo -e "${RED}错误：ID $id 不存在。${PLAIN}" && return

        read -r -p "确认删除 $id? (y/n): " conf
        [[ "$conf" != "y" ]] && return

        control_config_unit "$cfg_file" disable --now
        remove_instance_unit "$(config_kind_value "$cfg_file")" "$id"
        rm -f "$cfg_file"
    else
        read -r -p "确认清理全部实例? (y/n): " conf
        [[ "$conf" != "y" ]] && return

        control_all_units disable --now >/dev/null
        rm -f "${SYSTEMD_UNIT_DIR}"/floos@*.service "${SYSTEMD_UNIT_DIR}"/flooc@*.service
        rm -f "$FLOO_CONF_DIR"/*.toml
        systemctl daemon-reload
    fi

    echo -e "${GREEN}操作成功。${PLAIN}"
}

# 5/6. 控制逻辑
do_ctrl() {
    local action=$1
    local opt
    local id
    local cfg_file

    echo "1. $action 指定 ID"
    echo "2. $action 全部 ID"
    read -r -p "选择: " opt

    if [[ "$opt" == "1" ]]; then
        read -r -p "输入 ID: " id
        cfg_file="$FLOO_CONF_DIR/$id.toml"
        [[ ! -f "$cfg_file" ]] && echo -e "${RED}错误：ID $id 不存在。${PLAIN}" && return
        control_config_unit "$cfg_file" "$action"
    else
        if ! control_all_units "$action"; then
            echo -e "${YELLOW}暂无可操作实例。${PLAIN}"
        fi
    fi
}

# --- 主循环 ---

# 状态显示
show_status() {
    local has_instance=0
    local toml
    local id
    local kind
    local role
    local svc

    echo -e "${GREEN}========================================${PLAIN}"
    if [[ -x "$FLOO_BIN_SERVER" && -x "$FLOO_BIN_CLIENT" ]]; then
        echo -e " 安装状态: ${GREEN}已安装${PLAIN}"
        echo -e " 当前发布: ${GREEN}latest${PLAIN} (${FLOO_GITHUB_REPO} / gh.5ieee.com)"
    else
        echo -e " 安装状态: ${RED}未安装${PLAIN}"
    fi

    for toml in "$FLOO_CONF_DIR"/*.toml; do
        has_instance=1
        id=$(basename "$toml" .toml)
        kind=$(config_kind_value "$toml")
        role=$(service_role_for_kind "$kind")
        svc=$(service_unit_for_kind "$kind" "$id")

        if systemctl is-active --quiet "$svc"; then
            echo -e " [$id] $role ${GREEN}运行中${PLAIN}"
        else
            echo -e " [$id] $role ${RED}已停止${PLAIN}"
        fi
    done

    [[ $has_instance -eq 0 ]] && echo -e " 实例列表: 暂无"
    echo -e "${GREEN}========================================${PLAIN}"
}

if is_command_mode "$@"; then
    case $1 in
        import-client)
            handle_import_client "$@"
            exit $?
            ;;
        *)
            echo -e "${RED}错误：不支持的命令 $1${PLAIN}"
            exit 1
            ;;
    esac
fi

while true; do
    show_status
    echo -e "${GREEN}       Floo 隧道管理脚本${PLAIN}"
    echo -e "${GREEN}========================================${PLAIN}"
    echo "1. 安装新版    2. 卸载清理"
    echo "3. 添加实例    4. 删除实例"
    echo "5. 重启实例    6. 停止实例"
    echo "7. 查看日志    0. 退出脚本"
    echo -e "${GREEN}========================================${PLAIN}"
    read -r -p "请选择操作 [0-7]: " main_opt

    case $main_opt in
        1) do_install ;;
        2)
            read -r -p "确认卸载? (y/n): " conf
            if [[ "$conf" == "y" ]]; then
                control_all_units disable --now >/dev/null
                rm -rf "$FLOO_CONF_DIR"
                rm -f "${SYSTEMD_UNIT_DIR}"/floos@*.service "${SYSTEMD_UNIT_DIR}"/flooc@*.service
                rm -f "$FLOO_BIN_SERVER" "$FLOO_BIN_CLIENT" "$FLOO_BIN_SERVER_LEGACY" "$FLOO_BIN_CLIENT_LEGACY"
                systemctl daemon-reload
                echo "清理完毕。"
            fi
            ;;
        3) do_add ;;
        4) do_delete ;;
        5) do_ctrl "restart" ;;
        6) do_ctrl "stop" ;;
        7)
            read -r -p "输入 ID (回车看全部 Floo 日志): " id
            if [[ -z $id ]]; then
                show_all_logs
            elif [[ -f "$FLOO_CONF_DIR/$id.toml" ]]; then
                journalctl -u "$(service_unit_for_file "$FLOO_CONF_DIR/$id.toml")" -f
            else
                echo -e "${RED}错误：ID $id 不存在。${PLAIN}"
            fi
            ;;
        0) exit 0 ;;
        *) echo "无效选项" ;;
    esac
done
