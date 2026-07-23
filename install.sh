#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

XUI_FOLDER="${XUI_FOLDER:-/usr/local/x-ui}"
XUI_REPO="${XUI_REPO:-Lynn-Becky/Alpine-x-ui}"
XUI_SERVICE_DIR="${XUI_SERVICE_DIR:-/etc/systemd/system}"
XUI_DB_FILE="${XUI_DB_FILE:-/etc/x-ui/x-ui.db}"
existing_database=false
[[ -f "$XUI_DB_FILE" ]] && existing_database=true

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
            apk add --no-cache gcompat >/dev/null 2>&1 || true
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
    echo -e "${yellow}出于安全考虑，安装/更新完成后需要修改端口与账户密码。${plain}"
    local config_web_base_path="${XUI_WEB_BASE_PATH:-}"
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

    if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
        if [[ -n "${XUI_USERNAME:-}" && -n "${XUI_PASSWORD:-}" ]]; then
            "$XUI_FOLDER/x-ui" setting -username "$XUI_USERNAME" -password "$XUI_PASSWORD"
        fi
        if [[ "${XUI_PORT:-}" =~ ^[0-9]+$ ]] && (( XUI_PORT >= 1 && XUI_PORT <= 65535 )); then
            "$XUI_FOLDER/x-ui" setting -port "$XUI_PORT"
        fi
        echo -e "${yellow}非交互安装已跳过未通过环境变量提供的配置项。${plain}"
        return
    fi

    read -r -p "确认是否继续？[y/n] " config_confirm
    if [[ "$config_confirm" =~ ^[yY]$ ]]; then
        read -r -p "请设置您的账户名: " config_account
        read -r -p "请设置您的账户密码: " config_password
        read -r -p "请设置面板访问端口: " config_port
        if [[ -n "$config_account" && -n "$config_password" ]]; then
            "$XUI_FOLDER/x-ui" setting -username "$config_account" -password "$config_password"
        fi
        if [[ "$config_port" =~ ^[0-9]+$ ]] && (( config_port >= 1 && config_port <= 65535 )); then
            "$XUI_FOLDER/x-ui" setting -port "$config_port"
        fi
    else
        echo -e "${yellow}已取消，仍为默认设置，请及时修改。${plain}"
    fi
}

gen_random_string() {
    local length="$1"
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | cut -c "1-${length}"
}

tag_version=""

download_release() {
    local version="$1"
    local archive="${XUI_FOLDER}-linux-${arch}.tar.gz"
    local url
    if [[ -n "$version" ]]; then
        url="https://github.com/${XUI_REPO}/releases/download/${version}/x-ui-linux-${arch}.tar.gz"
        echo "开始安装 x-ui ${version}"
    else
        # The repository also publishes prereleases, which /releases/latest
        # deliberately excludes. The first visible release is the newest one.
        version="$(curl -fsSL --retry 3 "https://api.github.com/repos/${XUI_REPO}/releases?per_page=1" \
            | sed -n 's/.*\"tag_name\": \"\([^\"]*\)\".*/\1/p' | head -n 1 || true)"
        [[ -n "$version" ]] || { error "检测 x-ui 最新版本失败，请稍后重试或手动指定版本。"; exit 1; }
        url="https://github.com/${XUI_REPO}/releases/download/${version}/x-ui-linux-${arch}.tar.gz"
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
    local service_url="https://raw.githubusercontent.com/${XUI_REPO}/x-ui/x-ui.rc"
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
    local archive script_url script_temp
    service_stop
    download_release "$requested_version"
    archive="${XUI_FOLDER}-linux-${arch}.tar.gz"

    rm -rf "$XUI_FOLDER"
    tar -xzf "$archive" -C "$(dirname "$XUI_FOLDER")" || { rm -f "$archive"; error "解压 x-ui 安装包失败。"; exit 1; }
    rm -f "$archive"
    [[ -x "$XUI_FOLDER/x-ui" ]] || { error "安装包中缺少 x-ui 可执行文件。"; exit 1; }
    chmod +x "$XUI_FOLDER/x-ui" "$XUI_FOLDER/x-ui.sh" "$XUI_FOLDER/bin/xray-linux-${arch}"

    script_url="https://raw.githubusercontent.com/${XUI_REPO}/x-ui/x-ui.sh"
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
}

echo -e "${green}开始安装 x-ui${plain}"
install_base
install_x_ui "${1:-}"
