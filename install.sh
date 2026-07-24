#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

XUI_FOLDER="${XUI_FOLDER:-/usr/local/x-ui}"
XUI_REPO="${XUI_REPO:-Lynn-Becky/xui}"
XUI_SERVICE_DIR="${XUI_SERVICE_DIR:-/etc/systemd/system}"
XUI_DB_FILE="${XUI_DB_FILE:-/etc/x-ui/x-ui.db}"
existing_database=false
[[ -f "$XUI_DB_FILE" ]] && existing_database=true

install_panel_settings_changed=false
install_panel_username=""
install_panel_password=""
install_panel_port=""
install_panel_base_path="/"

script_dir=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi

error() {
    echo -e "${red}$*${plain}" >&2
}

[[ $EUID -eq 0 ]] || { error "错误：必须使用 root 用户运行此脚本！"; exit 1; }

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    release="${ID,,}"
else
    error "未检测到系统版本，请联系脚本作者！"
    exit 1
fi

case "$release" in
    alpine|debian|ubuntu|armbian|raspbian|centos|rhel|rocky|almalinux|ol|fedora|amzn|amazon|arch|manjaro|parch|opensuse-tumbleweed|opensuse-leap|sles)
        ;;
    *)
        error "暂不支持的系统：${release}"
        exit 1
        ;;
esac

arch() {
    case "$(uname -m)" in
        x86_64|x64|amd64) echo amd64 ;;
        aarch64|arm64|armv8*) echo arm64 ;;
        *) return 1 ;;
    esac
}

arch="$(arch)" || { error "不支持的 CPU 架构：$(uname -m)"; exit 1; }
echo "系统：${release}，架构：${arch}"

install_base() {
    case "$release" in
        alpine)
            apk add --no-cache bash dcron curl wget tar tzdata socat ca-certificates openssl openrc
            ;;
        centos|rhel|rocky|almalinux|ol|fedora|amzn|amazon)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y cronie curl wget tar tzdata socat ca-certificates openssl
            else
                yum install -y cronie curl wget tar tzdata socat ca-certificates openssl
            fi
            ;;
        arch|manjaro|parch)
            pacman -Sy --noconfirm cronie curl wget tar tzdata socat ca-certificates openssl
            ;;
        opensuse-tumbleweed|opensuse-leap|sles)
            zypper --non-interactive refresh
            zypper --non-interactive install cron curl wget tar timezone socat ca-certificates openssl
            ;;
        debian|ubuntu|armbian|raspbian)
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y cron curl wget tar tzdata socat ca-certificates openssl
            ;;
        *)
            error "无法为 ${release} 选择包管理器。"
            exit 1
            ;;
    esac
}

service_stop() {
    if [[ "$release" == alpine ]]; then
        rc-service x-ui stop >/dev/null 2>&1 || true
    else
        systemctl stop x-ui >/dev/null 2>&1 || true
    fi
}

config_after_install() {
    echo -e "${yellow}出于安全考虑，新安装会随机生成面板账号、密码和端口。${plain}"
    local config_web_base_path="${XUI_WEB_BASE_PATH:-}"
    local config_account=""
    local config_password=""
    local config_port=""
    local config_confirm=""
    local config_input=""
    if [[ -z "$config_web_base_path" && ! -f "$XUI_DB_FILE" ]]; then
        config_web_base_path="$(gen_random_string 18)"
        echo -e "${green}已生成随机面板访问路径：/${config_web_base_path}/${plain}"
    fi
    if [[ -n "$config_web_base_path" ]]; then
        "$XUI_FOLDER/x-ui" setting -webBasePath "$config_web_base_path"
        config_web_base_path="${config_web_base_path#/}"
        config_web_base_path="${config_web_base_path%/}"
        echo -e "${green}面板访问路径：/${config_web_base_path}/${plain}"
    fi
    install_panel_base_path="/${config_web_base_path:+${config_web_base_path}/}"

    if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
        if [[ "$existing_database" == false ]]; then
            config_account="${XUI_USERNAME:-$(gen_random_string 12)}"
            config_password="${XUI_PASSWORD:-$(gen_random_string 24)}"
            config_port="${XUI_PORT:-$(gen_random_port)}"
            if ! is_valid_port "$config_port"; then
                config_port="$(gen_random_port)"
            fi
            "$XUI_FOLDER/x-ui" setting -username "$config_account" -password "$config_password" -port "$config_port"
            install_panel_settings_changed=true
        elif [[ -n "${XUI_USERNAME:-}" && -n "${XUI_PASSWORD:-}" ]]; then
            "$XUI_FOLDER/x-ui" setting -username "$XUI_USERNAME" -password "$XUI_PASSWORD"
        fi
        if [[ "$existing_database" == true ]] && is_valid_port "${XUI_PORT:-}"; then
            "$XUI_FOLDER/x-ui" setting -port "$XUI_PORT"
        fi
        echo -e "${yellow}非交互安装已使用环境变量或安全随机值配置面板。${plain}"
        return
    fi

    read -r -p "是否要手动设置用户名、密码和端口？[y/N] " config_confirm
    if [[ "$config_confirm" =~ ^[yY]$ ]]; then
        config_account="$(gen_random_string 12)"
        config_password="$(gen_random_string 24)"
        config_port="$(gen_random_port)"

        read -r -p "请设置您的账户名（随机账号：${config_account}，直接回车使用随机用户名）: " config_input
        [[ -n "$config_input" ]] && config_account="$config_input"
        read -r -p "请设置您的账户密码（随机密码：${config_password}，直接回车使用随机密码）: " config_input
        [[ -n "$config_input" ]] && config_password="$config_input"
        while true; do
            read -r -p "请设置面板访问端口（随机端口：${config_port}，范围 10000-65535，直接回车使用随机端口）: " config_input
            if [[ -z "$config_input" ]]; then
                break
            fi
            if is_valid_port "$config_input"; then
                config_port="$config_input"
                break
            fi
            error "端口必须在 1-65535 之间，请重新输入。"
        done
        "$XUI_FOLDER/x-ui" setting -username "$config_account" -password "$config_password" -port "$config_port"
        install_panel_settings_changed=true
    elif [[ "$existing_database" == false ]]; then
        config_account="$(gen_random_string 12)"
        config_password="$(gen_random_string 24)"
        config_port="$(gen_random_port)"
        "$XUI_FOLDER/x-ui" setting -username "$config_account" -password "$config_password" -port "$config_port"
        install_panel_settings_changed=true
        echo -e "${green}已使用安全随机的用户名、密码和端口。${plain}"
    else
        echo -e "${yellow}已保留现有面板账号、密码和端口。${plain}"
    fi

    if [[ "$install_panel_settings_changed" == true ]]; then
        install_panel_username="$config_account"
        install_panel_password="$config_password"
        install_panel_port="$config_port"
    fi
}

is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

gen_random_port() {
    local random_hex
    random_hex="$(openssl rand -hex 4)"
    printf '%d\n' "$((16#$random_hex % 55536 + 10000))"
}

get_server_ip() {
    local server_ip
    server_ip="$(curl -4fsS --connect-timeout 5 --max-time 10 https://api.ipify.org 2>/dev/null || true)"
    if [[ ! "$server_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        server_ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/ { print; exit }' || true)"
    fi
    printf '%s\n' "${server_ip:-<服务器 IP>}"
}

print_panel_login_info() {
    local settings
    local protocol="http"
    local username="$install_panel_username"
    local password="$install_panel_password"
    local port="$install_panel_port"
    local base_path="$install_panel_base_path"
    local server_ip

    settings="$("$XUI_FOLDER/x-ui" setting -show 2>/dev/null || true)"
    [[ -n "$username" ]] || username="$(printf '%s\n' "$settings" | awk -F ': ' '/^username: / { print substr($0, index($0, ": ") + 2); exit }')"
    [[ -n "$password" ]] || password="$(printf '%s\n' "$settings" | awk -F ': ' '/^userpasswd: / { print substr($0, index($0, ": ") + 2); exit }')"
    [[ -n "$port" ]] || port="$(printf '%s\n' "$settings" | awk -F ': ' '/^port: / { print substr($0, index($0, ": ") + 2); exit }')"
    base_path="$(printf '%s\n' "$settings" | awk -F ': ' '/^webBasePath: / { print substr($0, index($0, ": ") + 2); exit }')"
    [[ -n "$base_path" ]] || base_path="/"
    if [[ "$base_path" != /* ]]; then
        base_path="/${base_path}"
    fi
    [[ "$base_path" == */ ]] || base_path="${base_path}/"
    if printf '%s\n' "$settings" | grep -q '^webCertFile: /'; then
        protocol="https"
    fi
    server_ip="$(get_server_ip)"
    echo ""
    echo -e "${green}面板登录信息（请妥善保存）：${plain}"
    echo "用户名：${username}"
    echo "密码：${password}"
    echo "登录 URL：${protocol}://${server_ip}:${port}${base_path}"
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | cut -c "1-${length}"
}

tag_version=""

download_release() {
    local version="$1"
    local asset_suffix=""
    [[ "$release" == alpine ]] && asset_suffix="-alpine"
    local archive="${XUI_FOLDER}-linux-${arch}${asset_suffix}.tar.gz"
    local url
    if [[ -n "$version" ]]; then
        url="https://github.com/${XUI_REPO}/releases/download/${version}/x-ui-linux-${arch}${asset_suffix}.tar.gz"
        echo "开始安装 x-ui ${version}"
    else
        # The repository also publishes prereleases, which /releases/latest
        # deliberately excludes. The first visible release is the newest one.
        version="$(curl -fsSL --retry 3 "https://api.github.com/repos/${XUI_REPO}/releases?per_page=1" \
            | sed -n 's/.*\"tag_name\": \"\([^\"]*\)\".*/\1/p' | head -n 1 || true)"
        [[ -n "$version" ]] || { error "检测 x-ui 最新版本失败，请稍后重试或手动指定版本。"; exit 1; }
        url="https://github.com/${XUI_REPO}/releases/download/${version}/x-ui-linux-${arch}${asset_suffix}.tar.gz"
        echo "检测到 x-ui 最新版本：${version}，开始安装"
    fi
    curl -fL --retry 3 --connect-timeout 15 -o "$archive" "$url" || {
        rm -f "$archive"
        error "下载 x-ui 失败，请确保版本存在且服务器可以访问 GitHub。"
        exit 1
    }
    [[ -s "$archive" ]] || { rm -f "$archive"; error "下载的安装包为空。"; exit 1; }
    tag_version="$version"
}

install_openrc_service() {
    local service_url="https://raw.githubusercontent.com/${XUI_REPO}/main/x-ui.rc"
    local temp="/etc/init.d/x-ui.tmp.$$"
    if [[ -n "$script_dir" && -f "$script_dir/x-ui.rc" ]]; then
        install -m 0755 "${script_dir}/x-ui.rc" /etc/init.d/x-ui
    elif ! curl -fsSL -o "$temp" "$service_url" || [[ ! -s "$temp" ]]; then
        rm -f "$temp"
        error "下载 Alpine OpenRC 服务文件失败。"
        exit 1
    else
        mv -f "$temp" /etc/init.d/x-ui
    fi
    chmod +x /etc/init.d/x-ui
    rc-update add x-ui default >/dev/null
    rc-service x-ui restart
}

install_systemd_service() {
    install -d "$XUI_SERVICE_DIR"
    install -m 0644 "$XUI_FOLDER/x-ui.service" "$XUI_SERVICE_DIR/x-ui.service"
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl restart x-ui
}

configure_tls_after_install() {
    local mode="${XUI_SSL_MODE:-}"
    if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
        [[ -z "$mode" ]] && return 0
        /usr/bin/x-ui cert
        return
    fi
    if [[ "$existing_database" == true && -z "$mode" ]]; then
        return 0
    fi
    if [[ -z "$mode" ]]; then
        local configure_tls
        read -r -p "是否现在为面板配置 TLS 证书？[y/N] " configure_tls
        [[ "$configure_tls" =~ ^[yY]$ ]] || return 0
    fi
    /usr/bin/x-ui cert
}

install_x_ui() {
    local requested_version="${1:-}"
    local archive_suffix=""
    [[ "$release" == alpine ]] && archive_suffix="-alpine"
    local archive script_url script_temp
    service_stop
    download_release "$requested_version"
    archive="${XUI_FOLDER}-linux-${arch}${archive_suffix}.tar.gz"

    rm -rf "$XUI_FOLDER"
    tar -xzf "$archive" -C "$(dirname "$XUI_FOLDER")" || { rm -f "$archive"; error "解压 x-ui 安装包失败。"; exit 1; }
    rm -f "$archive"
    [[ -x "$XUI_FOLDER/x-ui" ]] || { error "安装包中缺少 x-ui 可执行文件。"; exit 1; }
    chmod +x "$XUI_FOLDER/x-ui" "$XUI_FOLDER/x-ui.sh" "$XUI_FOLDER/bin/xray-linux-${arch}"

    script_url="https://raw.githubusercontent.com/${XUI_REPO}/main/x-ui.sh"
    script_temp="/usr/bin/x-ui.tmp.$$"
    rm -f "$script_temp"
    if ! curl -fsSL -o "$script_temp" "$script_url" || [[ ! -s "$script_temp" ]]; then
        rm -f "$script_temp"
        error "下载 x-ui 管理脚本失败。"
        exit 1
    fi
    mv -f "$script_temp" /usr/bin/x-ui
    chmod +x /usr/bin/x-ui

    config_after_install
    if [[ "$release" == alpine ]]; then
        install_openrc_service
    else
        install_systemd_service
    fi

    configure_tls_after_install

    echo -e "${green}x-ui ${tag_version} 安装完成，面板已启动。${plain}"
    print_panel_login_info
}

echo -e "${green}开始安装 x-ui${plain}"
install_base
install_x_ui "${1:-}"
