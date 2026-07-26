#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'
acme_sh='/root/.acme.sh/acme.sh'

#Add some basic function here
function LOGD() {
    echo -e "${yellow}[DEG] $* ${plain}"
}

function LOGE() {
    echo -e "${red}[ERR] $* ${plain}"
}

function LOGI() {
    echo -e "${green}[INF] $* ${plain}"
}
# check root
[[ $EUID -ne 0 ]] && LOGE "错误:  必须使用root用户运行此脚本!\n" && exit 1

# check os
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    release="${ID,,}"
else
    LOGE "未检测到系统版本，请联系脚本作者！\n" && exit 1
fi

os_version=""

# os version
if [[ -f /etc/os-release ]]; then
    os_version=$(awk -F'[= ."]' '/VERSION_ID/{print $3}' /etc/os-release)
fi
if [[ -z "$os_version" && -f /etc/lsb-release ]]; then
    os_version=$(awk -F'[= ."]+' '/DISTRIB_RELEASE/{print $2}' /etc/lsb-release)
fi

if [[ x"${release}" == x"centos" ]]; then
    if [[ ${os_version} -le 6 ]]; then
        LOGE "请使用 CentOS 7 或更高版本的系统！\n" && exit 1
    fi
elif [[ x"${release}" == x"ubuntu" ]]; then
    if [[ ${os_version} -lt 16 ]]; then
        LOGE "请使用 Ubuntu 16 或更高版本的系统！\n" && exit 1
    fi
elif [[ x"${release}" == x"debian" ]]; then
    if [[ ${os_version} -lt 8 ]]; then
        LOGE "请使用 Debian 8 或更高版本的系统！\n" && exit 1
    fi
fi

is_alpine() {
    [[ "$release" == "alpine" ]]
}

service_start() {
    if is_alpine; then rc-service x-ui start; else systemctl start x-ui; fi
}

service_stop() {
    if is_alpine; then rc-service x-ui stop; else systemctl stop x-ui; fi
}

service_restart() {
    if is_alpine; then rc-service x-ui restart; else systemctl restart x-ui; fi
}

service_status() {
    if is_alpine; then rc-service x-ui status; else systemctl status x-ui -l; fi
}

service_enable() {
    if is_alpine; then rc-update add x-ui default; else systemctl enable x-ui; fi
}

service_disable() {
    if is_alpine; then rc-update del x-ui default; else systemctl disable x-ui; fi
}

confirm() {
    if [[ $# > 1 ]]; then
        echo && read -p "$1 [默认$2]: " temp
        if [[ x"${temp}" == x"" ]]; then
            temp=$2
        fi
    else
        read -p "$1 [y/n]: " temp
    fi
    if [[ x"${temp}" == x"y" || x"${temp}" == x"Y" ]]; then
        return 0
    else
        return 1
    fi
}

confirm_restart() {
    confirm "是否重启面板，重启面板也会重启 xray" "y"
    if [[ $? == 0 ]]; then
        restart
    else
        show_menu
    fi
}

before_show_menu() {
    echo && echo -n -e "${yellow}按回车返回主菜单: ${plain}" && read temp
    show_menu
}

# run_installer downloads the installer to a file and runs it, reporting the
# real outcome.
#
# The previous form, bash <(curl ...) followed by a $? check, reports bash's exit
# status and not curl's: when the download fails — a 4xx, DNS failure, an on-path
# reset, or GitHub simply being unreachable — bash runs an empty script and exits
# 0, so a failed update was announced as a successful one.
run_installer() {
    local installer
    installer="$(mktemp -t x-ui-install.XXXXXXXXXX)" || {
        LOGE "创建临时文件失败"
        return 1
    }
    if ! curl -fsSL https://raw.githubusercontent.com/Lynn-Becky/xui/main/install.sh -o "$installer"; then
        rm -f "$installer"
        LOGE "下载安装脚本失败，请检查网络连接后重试"
        return 1
    fi
    if [[ ! -s "$installer" ]]; then
        rm -f "$installer"
        LOGE "下载的安装脚本为空"
        return 1
    fi
    bash "$installer"
    local status=$?
    rm -f "$installer"
    return $status
}

install() {
    if run_installer; then
        if [[ $# == 0 ]]; then
            start
        else
            start 0
        fi
    fi
}

update() {
    confirm "本功能会强制重装当前最新版，数据不会丢失，是否继续?" "n"
    if [[ $? != 0 ]]; then
        LOGE "已取消"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 0
    fi
    if run_installer; then
        LOGI "更新完成，已自动重启面板 "
        exit 0
    fi
    LOGE "更新失败，面板未做改动"
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
    return 1
}

uninstall() {
    confirm "确定要卸载面板吗,xray 也会卸载?" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    service_stop
    service_disable
    if is_alpine; then
        rm /etc/init.d/x-ui -f
    else
        rm /etc/systemd/system/x-ui.service -f
        systemctl daemon-reload
        systemctl reset-failed
    fi
    rm /etc/x-ui/ -rf
    rm /usr/local/x-ui/ -rf

    echo ""
    echo -e "卸载成功，如果你想删除此脚本，则退出脚本后运行 ${green}rm /usr/bin/x-ui -f${plain} 进行删除"
    echo ""

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

gen_random_password() {
    openssl rand -base64 48 2>/dev/null | tr -dc 'a-zA-Z0-9' | cut -c1-24
}

reset_user() {
    confirm "确定要重置面板用户名和密码吗（将生成一个随机密码）" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    local new_password
    new_password="$(gen_random_password)"
    if [[ ${#new_password} -lt 24 ]]; then
        LOGE "生成随机密码失败，请确认已安装 openssl"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    fi
    # Never reset to a fixed credential: this menu item used to set admin/admin,
    # which puts an internet-facing panel into a state scanners find within
    # minutes and leaves a guessable value in the database afterwards.
    #
    # The credentials travel in the environment rather than argv, because
    # /proc/<pid>/cmdline is world-readable and is captured by process auditing.
    XUI_SETTING_USERNAME="admin" XUI_SETTING_PASSWORD="$new_password" \
        /usr/local/x-ui/x-ui setting
    echo -e "用户名已重置为：${green}admin${plain}"
    echo -e "密码已重置为：${green}${new_password}${plain}"
    echo -e "${yellow}此密码只显示一次，请妥善保存并在登录后立即修改。${plain}"
    confirm_restart
}

reset_config() {
    confirm "确定要重置面板设置吗，账号数据、用户名密码、访问端口、访问路径和证书均会保留" "n"
    if [[ $? != 0 ]]; then
        if [[ $# == 0 ]]; then
            show_menu
        fi
        return 0
    fi
    /usr/local/x-ui/x-ui setting -reset
    echo -e "面板设置已重置。${green}访问端口、访问路径和 TLS 证书已保留${plain}，现在请重启面板"
    confirm_restart
}

check_config() {
    info=$(/usr/local/x-ui/x-ui setting -show true)
    if [[ $? != 0 ]]; then
        LOGE "get current settings error,please check logs"
        show_menu
    fi
    LOGI "${info}"
}

set_port() {
    echo && echo -n -e "输入端口号[1-65535]: " && read port
    if [[ -z "${port}" ]]; then
        LOGD "已取消"
        before_show_menu
    else
        /usr/local/x-ui/x-ui setting -port ${port}
        echo -e "设置端口完毕，现在请重启面板，并使用新设置的端口 ${green}${port}${plain} 访问面板"
        confirm_restart
    fi
}

start() {
    check_status
    if [[ $? == 0 ]]; then
        echo ""
        LOGI "面板已运行，无需再次启动，如需重启请选择重启"
    else
        service_start
        sleep 2
        check_status
        if [[ $? == 0 ]]; then
            LOGI "x-ui 启动成功"
        else
            LOGE "面板启动失败，可能是因为启动时间超过了两秒，请稍后查看日志信息"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

stop() {
    check_status
    if [[ $? == 1 ]]; then
        echo ""
        LOGI "面板已停止，无需再次停止"
    else
        service_stop
        sleep 2
        check_status
        if [[ $? == 1 ]]; then
            LOGI "x-ui 与 xray 停止成功"
        else
            LOGE "面板停止失败，可能是因为停止时间超过了两秒，请稍后查看日志信息"
        fi
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

restart() {
    service_restart
    sleep 2
    check_status
    if [[ $? == 0 ]]; then
        LOGI "x-ui 与 xray 重启成功"
    else
        LOGE "面板重启失败，可能是因为启动时间超过了两秒，请稍后查看日志信息"
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

status() {
    service_status
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable() {
    service_enable
    if [[ $? == 0 ]]; then
        LOGI "x-ui 设置开机自启成功"
    else
        LOGE "x-ui 设置开机自启失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

disable() {
    service_disable
    if [[ $? == 0 ]]; then
        LOGI "x-ui 取消开机自启成功"
    else
        LOGE "x-ui 取消开机自启失败"
    fi

    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

show_log() {
    if is_alpine; then
        if command -v logread >/dev/null 2>&1; then
            logread -f
        else
            LOGE "当前系统未安装日志读取工具 logread"
        fi
    else
        journalctl -u x-ui.service -e --no-pager -f
    fi
    if [[ $# == 0 ]]; then
        before_show_menu
    fi
}

enable_bbr() {
    if ! command -v sysctl >/dev/null 2>&1; then
        LOGE "系统缺少 sysctl，无法管理 BBR"
        return 1
    fi
    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        command -v modprobe >/dev/null 2>&1 && modprobe tcp_bbr 2>/dev/null || true
    fi
    if ! sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
        LOGE "当前内核不支持 BBR；本功能不会下载或替换内核"
        return 1
    fi
    local current_qdisc current_cc
    current_qdisc=$(sysctl -n net.core.default_qdisc)
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$current_cc" == "bbr" && "$current_qdisc" =~ ^(fq|cake)$ ]]; then
        LOGI "BBR 已启用"
        return 0
    fi
    mkdir -p /etc/sysctl.d
    {
        echo "#${current_qdisc}:${current_cc}"
        echo "net.core.default_qdisc = fq"
        echo "net.ipv4.tcp_congestion_control = bbr"
    } > /etc/sysctl.d/99-bbr-x-ui.conf
    if ! sysctl -p /etc/sysctl.d/99-bbr-x-ui.conf; then
        rm -f /etc/sysctl.d/99-bbr-x-ui.conf
        sysctl -w net.core.default_qdisc="$current_qdisc" >/dev/null 2>&1 || true
        sysctl -w net.ipv4.tcp_congestion_control="$current_cc" >/dev/null 2>&1 || true
        LOGE "应用 BBR sysctl 配置失败"
        return 1
    fi
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "bbr" && $(sysctl -n net.core.default_qdisc) == "fq" ]]; then
        LOGI "BBR 已成功启用"
    else
        LOGE "BBR 验证失败，请检查宿主机内核与容器权限"
        return 1
    fi
}

disable_bbr() {
    if ! command -v sysctl >/dev/null 2>&1; then
        LOGE "系统缺少 sysctl，无法管理 BBR"
        return 1
    fi
    if [[ -f /etc/sysctl.d/99-bbr-x-ui.conf ]]; then
        local old_settings old_qdisc old_cc
        old_settings=$(head -n 1 /etc/sysctl.d/99-bbr-x-ui.conf | tr -d '#')
        old_qdisc=${old_settings%:*}
        old_cc=${old_settings#*:}
        if [[ -z "$old_qdisc" || -z "$old_cc" || "$old_settings" != *:* ]]; then
            LOGE "BBR 备份配置无效，未做修改"
            return 1
        fi
        if ! sysctl -w net.core.default_qdisc="$old_qdisc" ||
            ! sysctl -w net.ipv4.tcp_congestion_control="$old_cc"; then
            LOGE "恢复原拥塞控制配置失败，已保留 x-ui BBR 配置以便重试"
            return 1
        fi
        rm -f /etc/sysctl.d/99-bbr-x-ui.conf
    else
        LOGI "未找到由 x-ui 创建的 BBR 配置"
        return 0
    fi
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == "$old_cc" && $(sysctl -n net.core.default_qdisc) == "$old_qdisc" ]]; then
        LOGI "BBR 已禁用并恢复原拥塞控制配置"
    else
        LOGE "BBR 仍处于启用状态"
        return 1
    fi
}

bbr_menu() {
    echo -e "${green}1.${plain} 启用 BBR"
    echo -e "${green}2.${plain} 禁用 BBR 并恢复原配置"
    echo -e "${green}0.${plain} 返回主菜单"
    read -p "请选择 [0-2]: " choice
    case "$choice" in
    1) enable_bbr; before_show_menu ;;
    2) disable_bbr; before_show_menu ;;
    0) show_menu ;;
    *) LOGE "请输入正确的数字 [0-2]"; bbr_menu ;;
    esac
}

update_shell() {
    local script_temp="/usr/bin/x-ui.tmp.$$"
    rm -f "$script_temp"
    if ! curl -fsSL --retry 3 -o "$script_temp" https://raw.githubusercontent.com/Lynn-Becky/xui/main/x-ui.sh ||
        [[ ! -s "$script_temp" ]]; then
        rm -f "$script_temp"
        echo ""
        LOGE "下载脚本失败，请检查本机能否连接 Github"
        before_show_menu
    else
        mv -f "$script_temp" /usr/bin/x-ui
        chmod +x /usr/bin/x-ui
        LOGI "升级脚本成功，请重新运行脚本" && exit 0
    fi
}

# 0: running, 1: not running, 2: not installed
check_status() {
    if is_alpine; then
        [[ -f /etc/init.d/x-ui ]] || return 2
        if rc-service x-ui status >/dev/null 2>&1; then
            return 0
        fi
        return 1
    else
        [[ -f /etc/systemd/system/x-ui.service ]] || return 2
        if systemctl is-active --quiet x-ui; then
            return 0
        fi
        return 1
    fi
}

check_enabled() {
    if is_alpine; then
        rc-update show default 2>/dev/null | grep -qE '^[[:space:]]*x-ui([[:space:]]|$)'
        return $?
    else
        systemctl is-enabled --quiet x-ui
        return $?
    fi
}

check_uninstall() {
    check_status
    if [[ $? != 2 ]]; then
        echo ""
        LOGE "面板已安装，请不要重复安装"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

check_install() {
    check_status
    if [[ $? == 2 ]]; then
        echo ""
        LOGE "请先安装面板"
        if [[ $# == 0 ]]; then
            before_show_menu
        fi
        return 1
    else
        return 0
    fi
}

show_status() {
    check_status
    case $? in
    0)
        echo -e "面板状态: ${green}已运行${plain}"
        show_enable_status
        ;;
    1)
        echo -e "面板状态: ${yellow}未运行${plain}"
        show_enable_status
        ;;
    2)
        echo -e "面板状态: ${red}未安装${plain}"
        ;;
    esac
    show_xray_status
}

show_enable_status() {
    check_enabled
    if [[ $? == 0 ]]; then
        echo -e "是否开机自启: ${green}是${plain}"
    else
        echo -e "是否开机自启: ${red}否${plain}"
    fi
}

check_xray_status() {
    count=$(ps -ef | grep "xray-linux" | grep -v "grep" | wc -l)
    if [[ count -ne 0 ]]; then
        return 0
    else
        return 1
    fi
}

show_xray_status() {
    check_xray_status
    if [[ $? == 0 ]]; then
        echo -e "xray 状态: ${green}运行${plain}"
    else
        echo -e "xray 状态: ${red}未运行${plain}"
    fi
}

is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]
}

is_ipv4() {
    local ip=$1 octet
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        local decimal=$((10#$octet))
        ((decimal >= 0 && decimal <= 255)) || return 1
    done
}

is_ipv6() {
    [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:]+$ ]]
}

install_acme() {
    if [[ -x "$acme_sh" ]]; then
        return 0
    fi
    LOGI "正在安装 acme.sh"
    # mktemp, not "/tmp/...$$": the PID space is small enough that an
    # unprivileged local user can pre-create every candidate path in /tmp as a
    # file they own (the sticky bit does not stop the owner from replacing it),
    # then swap the file between curl writing it and root executing it.
    local installer
    installer="$(mktemp -t acme-install-x-ui.XXXXXXXXXX)" || {
        LOGE "创建临时文件失败"
        return 1
    }
    if ! curl -fsSL https://get.acme.sh -o "$installer" || ! HOME=/root sh "$installer"; then
        rm -f "$installer"
        LOGE "安装 acme.sh 失败"
        return 1
    fi
    rm -f "$installer"
}

acme_reload_command() {
    echo "if command -v systemctl >/dev/null 2>&1 && systemctl restart x-ui; then exit 0; fi; if command -v rc-service >/dev/null 2>&1; then rc-service x-ui restart; else exit 1; fi"
}

restore_panel_service_state() {
    local should_run=$1
    if [[ "$should_run" == "true" ]]; then
        check_status || service_start
    elif check_status; then
        service_stop
    fi
}

configure_panel_certificate() {
    local cert_file=$1 key_file=$2 manage_permissions=${3:-false} should_run=${4:-auto}
    if [[ "$should_run" == "auto" ]]; then
        should_run=false
        check_status && should_run=true
    fi
    if [[ ! -s "$cert_file" || ! -s "$key_file" ]]; then
        LOGE "证书或私钥文件不存在/为空"
        restore_panel_service_state "$should_run"
        return 1
    fi
    if [[ "$manage_permissions" == "true" ]]; then
        if ! chmod 644 "$cert_file" || ! chmod 600 "$key_file"; then
            LOGE "设置证书文件权限失败"
            restore_panel_service_state "$should_run"
            return 1
        fi
    fi
    if ! /usr/local/x-ui/x-ui cert -webCert "$cert_file" -webCertKey "$key_file"; then
        LOGE "证书文件无法加载，未写入面板配置"
        restore_panel_service_state "$should_run"
        return 1
    fi
    if [[ "$should_run" == "true" ]]; then
        local service_loaded=true
        if check_status; then
            service_restart || service_loaded=false
        else
            service_start || service_loaded=false
        fi
        if [[ "$service_loaded" != "true" ]]; then
            service_start >/dev/null 2>&1 || true
            LOGE "证书已写入，但面板服务重载失败"
            return 1
        fi
    else
        if ! restore_panel_service_state false; then
            LOGE "证书已写入，但无法恢复面板原有的停止状态"
            return 1
        fi
    fi
    LOGI "面板 TLS 已配置：$cert_file"
}

issue_domain_certificate() {
    local domain=${XUI_DOMAIN:-} http_port=${XUI_ACME_HTTP_PORT:-80}
    if [[ -z "$domain" ]]; then
        if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
            LOGE "非交互模式必须提供 XUI_DOMAIN"
            return 1
        fi
        read -p "请输入已解析到本机的域名: " domain
    fi
    if ! is_domain "$domain"; then
        LOGE "域名格式无效: $domain"
        return 1
    fi
    if ! [[ "$http_port" =~ ^[0-9]+$ ]] || ((http_port < 1 || http_port > 65535)); then
        LOGE "XUI_ACME_HTTP_PORT 必须是 1-65535"
        return 1
    fi
    install_acme || return 1
    if [[ -n "${XUI_ACME_EMAIL:-}" ]] && ! "$acme_sh" --register-account -m "$XUI_ACME_EMAIL"; then
        LOGE "注册 ACME 账户失败"
        return 1
    fi
    if ! "$acme_sh" --set-default-ca --server letsencrypt --force; then
        LOGE "设置 Let's Encrypt CA 失败"
        return 1
    fi
    local was_running=false cert_dir="/root/cert/$domain" reload_cmd
    check_status && was_running=true
    [[ "$was_running" == "true" ]] && service_stop
    if ! "$acme_sh" --issue -d "$domain" --standalone --httpport "$http_port" --force; then
        restore_panel_service_state "$was_running"
        LOGE "域名证书签发失败，请确认外部 80 端口已转发到 $http_port"
        return 1
    fi
    mkdir -p "$cert_dir"
    reload_cmd=$(acme_reload_command)
    if ! "$acme_sh" --install-cert --force -d "$domain" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem" \
        --reloadcmd "$reload_cmd"; then
        restore_panel_service_state "$was_running"
        LOGE "安装域名证书或续期重载命令失败"
        return 1
    fi
    "$acme_sh" --upgrade --auto-upgrade >/dev/null 2>&1 || true
    configure_panel_certificate "$cert_dir/fullchain.pem" "$cert_dir/privkey.pem" true "$was_running"
}

issue_ip_certificate() {
    local ipv4=${XUI_IP:-} ipv6=${XUI_IPV6:-} http_port=${XUI_ACME_HTTP_PORT:-80}
    if [[ -z "$ipv4" ]]; then
        if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
            LOGE "非交互模式必须提供 XUI_IP"
            return 1
        fi
        read -p "请输入公网 IPv4: " ipv4
    fi
    if ! is_ipv4 "$ipv4"; then
        LOGE "IPv4 格式无效: $ipv4"
        return 1
    fi
    if [[ -n "$ipv6" ]] && ! is_ipv6 "$ipv6"; then
        LOGE "IPv6 格式无效: $ipv6"
        return 1
    fi
    if ! [[ "$http_port" =~ ^[0-9]+$ ]] || ((http_port < 1 || http_port > 65535)); then
        LOGE "XUI_ACME_HTTP_PORT 必须是 1-65535"
        return 1
    fi
    install_acme || return 1
    if [[ -n "${XUI_ACME_EMAIL:-}" ]] && ! "$acme_sh" --register-account -m "$XUI_ACME_EMAIL"; then
        LOGE "注册 ACME 账户失败"
        return 1
    fi
    if ! "$acme_sh" --set-default-ca --server letsencrypt --force; then
        LOGE "设置 Let's Encrypt CA 失败"
        return 1
    fi
    local was_running=false cert_dir="/root/cert/ip" reload_cmd
    local domain_args=(-d "$ipv4")
    [[ -n "$ipv6" ]] && domain_args+=(-d "$ipv6")
    check_status && was_running=true
    [[ "$was_running" == "true" ]] && service_stop
    if ! "$acme_sh" --issue "${domain_args[@]}" --standalone \
        --httpport "$http_port" --server letsencrypt \
        --certificate-profile shortlived --days 6 --force; then
        restore_panel_service_state "$was_running"
        LOGE "IP 证书签发失败；Let's Encrypt 仍需从外部访问 80 端口"
        return 1
    fi
    mkdir -p "$cert_dir"
    reload_cmd=$(acme_reload_command)
    if ! "$acme_sh" --install-cert --force -d "$ipv4" \
        --key-file "$cert_dir/privkey.pem" \
        --fullchain-file "$cert_dir/fullchain.pem" \
        --reloadcmd "$reload_cmd"; then
        restore_panel_service_state "$was_running"
        LOGE "安装 IP 证书或续期重载命令失败"
        return 1
    fi
    "$acme_sh" --upgrade --auto-upgrade >/dev/null 2>&1 || true
    configure_panel_certificate "$cert_dir/fullchain.pem" "$cert_dir/privkey.pem" true "$was_running"
}

use_existing_certificate() {
    local cert_file=${XUI_CERT_FILE:-} key_file=${XUI_KEY_FILE:-}
    if [[ -z "$cert_file" || -z "$key_file" ]]; then
        if [[ "${XUI_NONINTERACTIVE:-0}" == 1 || ! -t 0 ]]; then
            LOGE "非交互模式必须同时提供 XUI_CERT_FILE 和 XUI_KEY_FILE"
            return 1
        fi
        [[ -z "$cert_file" ]] && read -p "请输入完整证书文件路径: " cert_file
        [[ -z "$key_file" ]] && read -p "请输入私钥文件路径: " key_file
    fi
    configure_panel_certificate "$cert_file" "$key_file" false
}

ssl_cert_issue() {
    local mode=${XUI_SSL_MODE:-}
    if [[ -z "$mode" ]]; then
        echo -e "${green}1.${plain} 申请域名证书（HTTP-01）"
        echo -e "${green}2.${plain} 申请 IP 短期证书"
        echo -e "${green}3.${plain} 使用已有证书"
        echo -e "${green}0.${plain} 返回主菜单"
        read -p "请选择 [0-3]: " choice
        case "$choice" in
        1) mode=domain ;;
        2) mode=ip ;;
        3) mode=existing ;;
        0) show_menu; return ;;
        *) LOGE "请输入正确的数字 [0-3]"; return 1 ;;
        esac
    fi
    case "${mode,,}" in
    domain) issue_domain_certificate ;;
    ip) issue_ip_certificate ;;
    existing) use_existing_certificate ;;
    none|skip) LOGI "已跳过 TLS 配置" ;;
    *) LOGE "XUI_SSL_MODE 仅支持 domain、ip、existing、none"; return 1 ;;
    esac
}

show_usage() {
    echo "x-ui 管理脚本使用方法: "
    echo "------------------------------------------"
    echo "x-ui              - 显示管理菜单 (功能更多)"
    echo "x-ui start        - 启动 x-ui 面板"
    echo "x-ui stop         - 停止 x-ui 面板"
    echo "x-ui restart      - 重启 x-ui 面板"
    echo "x-ui status       - 查看 x-ui 状态"
    echo "x-ui enable       - 设置 x-ui 开机自启"
    echo "x-ui disable      - 取消 x-ui 开机自启"
    echo "x-ui log          - 查看 x-ui 日志"
    echo "x-ui update       - 更新 x-ui 面板"
    echo "x-ui install      - 安装 x-ui 面板"
    echo "x-ui uninstall    - 卸载 x-ui 面板"
    echo "x-ui cert         - 管理/申请面板 TLS 证书"
    echo "x-ui bbr          - 启用或禁用 BBR"
    echo "------------------------------------------"
}

show_menu() {
    echo -e "
  ${green}x-ui 面板管理脚本${plain}
  ${green}0.${plain} 退出脚本
————————————————
  ${green}1.${plain} 安装 x-ui
  ${green}2.${plain} 更新 x-ui
  ${green}3.${plain} 卸载 x-ui
————————————————
  ${green}4.${plain} 重置用户名密码
  ${green}5.${plain} 重置面板设置
  ${green}6.${plain} 设置面板端口
  ${green}7.${plain} 查看当前面板设置
————————————————
  ${green}8.${plain} 启动 x-ui
  ${green}9.${plain} 停止 x-ui
  ${green}10.${plain} 重启 x-ui
  ${green}11.${plain} 查看 x-ui 状态
  ${green}12.${plain} 查看 x-ui 日志
————————————————
  ${green}13.${plain} 设置 x-ui 开机自启
  ${green}14.${plain} 取消 x-ui 开机自启
————————————————
  ${green}15.${plain} 管理 BBR
  ${green}16.${plain} 管理/申请 SSL 证书
 "
    show_status
    echo && read -p "请输入选择 [0-16]: " num

    case "${num}" in
    0)
        exit 0
        ;;
    1)
        check_uninstall && install
        ;;
    2)
        check_install && update
        ;;
    3)
        check_install && uninstall
        ;;
    4)
        check_install && reset_user
        ;;
    5)
        check_install && reset_config
        ;;
    6)
        check_install && set_port
        ;;
    7)
        check_install && check_config
        ;;
    8)
        check_install && start
        ;;
    9)
        check_install && stop
        ;;
    10)
        check_install && restart
        ;;
    11)
        check_install && status
        ;;
    12)
        check_install && show_log
        ;;
    13)
        check_install && enable
        ;;
    14)
        check_install && disable
        ;;
    15)
        bbr_menu
        ;;
    16)
        ssl_cert_issue
        ;;
    *)
        LOGE "请输入正确的数字 [0-16]"
        ;;
    esac
}

if [[ $# > 0 ]]; then
    case $1 in
    "start")
        check_install 0 && start 0
        ;;
    "stop")
        check_install 0 && stop 0
        ;;
    "restart")
        check_install 0 && restart 0
        ;;
    "status")
        check_install 0 && status 0
        ;;
    "enable")
        check_install 0 && enable 0
        ;;
    "disable")
        check_install 0 && disable 0
        ;;
    "log")
        check_install 0 && show_log 0
        ;;
    "update")
        check_install 0 && update 0
        ;;
    "install")
        check_uninstall 0 && install 0
        ;;
    "uninstall")
        check_install 0 && uninstall 0
        ;;
    "cert")
        check_install 0 && ssl_cert_issue
        ;;
    "bbr")
        bbr_menu
        ;;
    *) show_usage ;;
    esac
else
    show_menu
fi
