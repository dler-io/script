#!/bin/bash
#
# 端口转发管理脚本
# 版本: 3.2.0

# 颜色定义
declare -A COLORS=(
    [CEND]="\033[0m"
    [CRED]="\033[1;31m"
    [CGREEN]="\033[1;32m"
)

# 打印颜色信息
print_color() {
    local color="$1"
    shift
    local message="$*"
    printf "%b%s%b\n" "${COLORS[$color]}" "$message" "${COLORS[CEND]}"
}

VERSION="3.2.0"

# 清理输入（去除首尾空格）
sanitize_input() {
    local input="$1"
    echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# 检测操作系统
detect_os() {
    local os_id=""
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            centos|rhel)
                os_id="centos"
                ;;
            debian)
                os_id="debian"
                ;;
            ubuntu)
                os_id="ubuntu"
                ;;
            *)
                os_id=""
                ;;
        esac
    fi
    
    if [ -z "$os_id" ]; then
        if [ -f /etc/issue ] && grep -qi "centos\|red hat\|rhel" /etc/issue 2>/dev/null; then
            os_id="centos"
        elif [ -f /etc/issue ] && grep -qi "debian" /etc/issue 2>/dev/null; then
            os_id="debian"
        elif [ -f /etc/issue ] && grep -qi "ubuntu" /etc/issue 2>/dev/null; then
            os_id="ubuntu"
        elif grep -qi "centos\|red hat\|rhel" /proc/version 2>/dev/null; then
            os_id="centos"
        elif grep -qi "debian" /proc/version 2>/dev/null; then
            os_id="debian"
        elif grep -qi "ubuntu" /proc/version 2>/dev/null; then
            os_id="ubuntu"
        fi
    fi
    
    if [ -z "$os_id" ]; then
        echo "unknown"
    else
        echo "$os_id"
    fi
}

RELEASE=$(detect_os)

# 检查root权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_color "CRED" "[错误] 此脚本需要root权限运行！"
        exit 1
    fi
}

# 验证IPv4地址格式
validate_ipv4() {
    local ip="$1"
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if [ "$octet" -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# 验证IPv6地址格式
validate_ipv6() {
    local ip="$1"
    if [[ $ip =~ : ]] && [[ ! $ip =~ ^fe80: ]]; then
        return 0
    fi
    return 1
}

# 验证端口号
validate_port() {
    local port="$1"
    port=$(sanitize_input "$port")
    
    if [[ $port =~ ^[0-9]+$ ]]; then
        if [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
            return 0
        fi
    elif [[ $port =~ ^[0-9]+-[0-9]+$ ]]; then
        local start_port=$(echo "$port" | cut -d'-' -f1)
        local end_port=$(echo "$port" | cut -d'-' -f2)
        if [ "$start_port" -ge 1 ] && [ "$start_port" -le 65535 ] && \
           [ "$end_port" -ge 1 ] && [ "$end_port" -le 65535 ] && \
           [ "$start_port" -le "$end_port" ]; then
            return 0
        fi
    fi
    return 1
}

# 安装必要软件包
install_iptables() {
    case "$RELEASE" in
        centos)
            yum makecache -q
            yum update -y -q
            yum install iptables iptables-services -y -q
            ;;
        debian|ubuntu)
            apt install iptables iptables-persistent -y -qq
            
            # 禁用UFW以防止冲突
            if command -v ufw >/dev/null 2>&1; then
                ufw disable
            fi
            ;;
        *)
            print_color "CRED" "[错误] 不支持的操作系统"
            exit 1
            ;;
    esac
    
    if ! command -v iptables >/dev/null 2>&1; then
        print_color "CRED" "[错误] 安装iptables失败，请检查！"
        exit 1
    fi
    
    print_color "CGREEN" "[信息] 安装 iptables 完毕！"
}

# 设置文件不可变属性
set_file_immutable() {
    local file="$1"
    local action="$2"
    if [ -f "$file" ]; then
        chattr "$action" "$file" 2>/dev/null || true
    fi
}

# 配置 TCP RST,ACK 过滤
configure_rst_ack_filter() {
    local cmd_prefix="$1"
    if ! command -v ${cmd_prefix} >/dev/null 2>&1; then
        return 0
    fi
    
    local rule_pattern="-p tcp --tcp-flags RST,ACK RST,ACK -j DROP"
    
    if ${cmd_prefix} -C FORWARD ${rule_pattern} 2>/dev/null; then
        local first_line=$(${cmd_prefix} -L FORWARD -n --line-numbers 2>/dev/null | tail -n +3 | head -1)
        if ! echo "$first_line" | grep -q "tcp.*tcp-flags.*RST,ACK.*RST,ACK.*DROP"; then
            ${cmd_prefix} -D FORWARD ${rule_pattern} 2>/dev/null || true
            ${cmd_prefix} -I FORWARD 1 ${rule_pattern} 2>/dev/null || true
        fi
    else
        ${cmd_prefix} -I FORWARD 1 ${rule_pattern} 2>/dev/null || true
    fi
}

# 启用IP转发
enable_ip_forward() {
    local FORWARD_CONFIG="net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# IPv4
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1

# IPv6
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# 禁用 ICMP (ping)
net.ipv4.icmp_echo_ignore_all = 1
net.ipv6.icmp.echo_ignore_all = 1"

    mkdir -p /etc/sysctl.d 2>/dev/null || true
    
    set_file_immutable /etc/sysctl.d/99-ip-forward.conf "-i"
    set_file_immutable /etc/sysctl.conf "-i"
    
    echo "$FORWARD_CONFIG" > /etc/sysctl.d/99-ip-forward.conf 2>/dev/null || true
    echo "$FORWARD_CONFIG" >> /etc/sysctl.conf 2>/dev/null || true
    
    set_file_immutable /etc/sysctl.d/99-ip-forward.conf "+i"
    set_file_immutable /etc/sysctl.conf "+i"

    sysctl --system >/dev/null 2>&1 || sysctl -p || true

    print_color "CGREEN" "[信息] 正在配置 TCP RST,ACK 过滤..."
    configure_rst_ack_filter "iptables"
    configure_rst_ack_filter "ip6tables"
    
    print_color "CGREEN" "[信息] IP 转发已启用，TCP RST,ACK 过滤已配置"
}

# 列出所有网卡的IPv4地址
list_all_ipv4() {
    declare -A ipv4_list
    local interfaces
    
    if command -v ip >/dev/null 2>&1; then
        # Linux 系统 - 使用 ip 命令
        interfaces=$(ip -4 addr show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v '^lo$')
        for iface in $interfaces; do
            local ipv4=$(ip -4 addr show "$iface" 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1 | head -1)
            if [ -n "$ipv4" ]; then
                ipv4_list["$iface"]="$ipv4"
            fi
        done
    elif command -v ifconfig >/dev/null 2>&1; then
        # macOS/BSD 系统 - 使用 ifconfig 命令
        interfaces=$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep -v '^lo' | grep -v '^lo0$')
        for iface in $interfaces; do
            local ipv4=$(ifconfig "$iface" 2>/dev/null | grep 'inet ' | grep -v 'inet6' | awk '{print $2}' | head -1)
            if [ -n "$ipv4" ]; then
                ipv4_list["$iface"]="$ipv4"
            fi
        done
    fi
    
    for iface in "${!ipv4_list[@]}"; do
        echo "${iface}|${ipv4_list[$iface]}"
    done
}

# 列出所有网卡的IPv6地址
list_all_ipv6() {
    declare -A ipv6_list
    local interfaces
    
    if command -v ip >/dev/null 2>&1; then
        # Linux 系统 - 使用 ip 命令
        interfaces=$(ip -6 addr show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}' | grep -v '^lo$')
        for iface in $interfaces; do
            local ipv6=$(ip -6 addr show "$iface" 2>/dev/null | grep 'inet6' | grep -v 'scope link' | awk '{print $2}' | cut -d'/' -f1 | head -1)
            if [ -n "$ipv6" ]; then
                ipv6_list["$iface"]="$ipv6"
            fi
        done
    elif command -v ifconfig >/dev/null 2>&1; then
        # macOS/BSD 系统 - 使用 ifconfig 命令
        interfaces=$(ifconfig -a | grep -E '^[a-z]' | awk '{print $1}' | sed 's/:$//' | grep -v '^lo$')
        for iface in $interfaces; do
            local ipv6=$(ifconfig "$iface" 2>/dev/null | grep 'inet6' | grep -v 'scopeid.*<link>' | awk '{print $2}' | grep -v -E '^fe80:' | head -1)
            if [ -n "$ipv6" ]; then
                ipv6_list["$iface"]="$ipv6"
            fi
        done
    fi
    
    for iface in "${!ipv6_list[@]}"; do
        echo "${iface}|${ipv6_list[$iface]}"
    done
}

# 让用户选择指定类型的IP地址
select_ip_address_by_type() {
    local ip_type="$1"
    local ip_list_func version_name validate_func
    
    if [ "$ip_type" = "4" ]; then
        ip_list_func="list_all_ipv4"
        version_name="IPv4"
        validate_func="validate_ipv4"
    else
        ip_list_func="list_all_ipv6"
        version_name="IPv6"
        validate_func="validate_ipv6"
    fi
    
    local ip_list=($(${ip_list_func}))
    
    if [ ${#ip_list[@]} -eq 0 ]; then
        print_color "CRED" "[错误] 未检测到任何 ${version_name} 地址" >&2
        return 1
    fi
    
    local idx=1
    local -A ip_map
    
    for item in "${ip_list[@]}"; do
        local iface=$(echo "$item" | cut -d'|' -f1)
        local ip=$(echo "$item" | cut -d'|' -f2)
        printf "  %b%d.%b %s: %s\n" "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "$iface" "$ip" >&2
        ip_map[$idx]="$ip|${ip_type}"
        idx=$((idx + 1))
    done
    echo >&2
    
    local total=$((idx - 1))
    local choice
    read -e -p "请选择要使用的 ${version_name} 地址 [1-${total}]（或输入 ${version_name} 地址）: " choice >&2
    choice=$(sanitize_input "$choice")
    
    if [ -z "$choice" ]; then
        print_color "CRED" "[错误] 必须选择一个 ${version_name} 地址" >&2
        return 1
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if [ "$choice" -ge 1 ] && [ "$choice" -le $total ]; then
            echo "${ip_map[$choice]}"
            return 0
        else
            print_color "CRED" "[错误] 无效的选择" >&2
            return 1
        fi
    else
        if ${validate_func} "$choice"; then
            echo "$choice|${ip_type}"
            return 0
        else
            print_color "CRED" "[错误] 无效的 ${version_name} 地址格式" >&2
            return 1
        fi
    fi
}

# 将协议号转换为协议名
get_protocol_name() {
    local proto_num="$1"
    case "$proto_num" in
        6)
            echo "TCP"
            ;;
        17)
            echo "UDP"
            ;;
        tcp|TCP)
            echo "TCP"
            ;;
        udp|UDP)
            echo "UDP"
            ;;
        *)
            echo "$proto_num" | tr '[:lower:]' '[:upper:]'
            ;;
    esac
}

# 显示转发规则配置信息
show_forward_config() {
    local title="$1"
    local rule_type="$2"
    local remote_port="$3"
    local remote_addr="$4"
    local local_port="$5"
    local local_addr="$6"
    local forward_type_text="$7"
    
    echo
    echo -e "——————————————————————————————
    ${title}

    规则类型: ${COLORS[CGREEN]}${rule_type}${COLORS[CEND]}
    远程端口: ${COLORS[CGREEN]}${remote_port}${COLORS[CEND]}
    远程地址: ${COLORS[CGREEN]}${remote_addr}${COLORS[CEND]}
    本地端口: ${COLORS[CGREEN]}${local_port}${COLORS[CEND]}
    本地地址: ${COLORS[CGREEN]}${local_addr}${COLORS[CEND]}
    转发类型: ${COLORS[CGREEN]}${forward_type_text}${COLORS[CEND]}
——————————————————————————————"
    echo
}

# 添加单个协议的转发规则
add_forward_rule_proto() {
    local ip_version="$1"
    local proto="$2"
    local local_addr="$3"
    local local_port_ipt="$4"
    local remote_addr="$5"
    local remote_port="$6"
    local remote_port_ipt="$7"
    
    local cmd_prefix="iptables"
    local cidr_suffix="/32"
    local remote_dest="${remote_addr}:${remote_port}"
    
    if [ "$ip_version" = "6" ]; then
        cmd_prefix="ip6tables"
        cidr_suffix="/128"
        remote_dest="[${remote_addr}]:${remote_port}"
    fi
    
    ${cmd_prefix} -t nat -A PREROUTING -p ${proto} -m ${proto} --dport "${local_port_ipt}" -j DNAT --to-destination "${remote_dest}" || {
        print_color "CRED" "[错误] 添加 ${proto^^} PREROUTING 规则失败"
        return 1
    }
    
    ${cmd_prefix} -t nat -A POSTROUTING -d "${remote_addr}${cidr_suffix}" -p ${proto} -m ${proto} --dport "${remote_port_ipt}" -j SNAT --to-source "${local_addr}" || {
        print_color "CRED" "[错误] 添加 ${proto^^} POSTROUTING 规则失败"
        return 1
    }
    
    return 0
}

# 创建转发规则
create_forward_rule() {
    local remote_port
    read -e -p "请输入远程端口 [1-65535]（支持端口段，默认 22-40000）: " remote_port
    remote_port=$(sanitize_input "$remote_port")
    remote_port=${remote_port:-"22-40000"}
    
    if ! validate_port "$remote_port"; then
        print_color "CRED" "[错误] 无效的端口格式！"
        exit 1
    fi
    
    local remote_addr
    read -e -p "请输入远程地址（IPv4 或 IPv6）: " remote_addr
    remote_addr=$(sanitize_input "$remote_addr")
    
    if [ -z "$remote_addr" ]; then
        print_color "CRED" "[错误] 远程地址不能为空"
        exit 1
    fi
    
    local ip_version
    if validate_ipv4 "$remote_addr"; then
        ip_version="4"
    elif validate_ipv6 "$remote_addr"; then
        ip_version="6"
    else
        print_color "CRED" "[错误] 无效的 IP 地址格式"
        exit 1
    fi
    
    local local_port
    read -e -p "请输入本地端口 [1-65535]（回车跟随远程端口）: " local_port
    local_port=$(sanitize_input "$local_port")
    local_port=${local_port:-"$remote_port"}
    
    if ! validate_port "$local_port"; then
        print_color "CRED" "[错误] 无效的本地端口格式！"
        exit 1
    fi
    
    echo
    local ip_with_type ret_code
    if [ "$ip_version" = "4" ]; then
        print_color "CGREEN" "请选择本地 IPv4 地址："
        ip_with_type=$(select_ip_address_by_type "4")
        ret_code=$?
    else
        print_color "CGREEN" "请选择本地 IPv6 地址："
        ip_with_type=$(select_ip_address_by_type "6")
        ret_code=$?
    fi
    
    if [ $ret_code -ne 0 ] || [ -z "$ip_with_type" ]; then
        print_color "CRED" "[错误] 未选择本地 IP 地址"
        exit 1
    fi
    
    local local_addr
    local_addr=$(echo "$ip_with_type" | cut -d'|' -f1)
    
    print_color "CGREEN" "请选择转发类型
 1. TCP
 2. UDP
 3. TCP + UDP"
    echo
    read -e -p "（默认 TCP + UDP）: " forward_type
    forward_type=$(sanitize_input "$forward_type")
    forward_type=${forward_type:-3}
    
    case "$forward_type" in
        1) forward_type_text="TCP" ;;
        2) forward_type_text="UDP" ;;
        3) forward_type_text="TCP + UDP" ;;
        *) forward_type=3; forward_type_text="TCP + UDP" ;;
    esac
    
    local rule_type="iptables"
    if [ "$ip_version" = "6" ]; then
        rule_type="ip6tables"
    fi
    
    show_forward_config "请检查转发规则配置是否有误！" "$rule_type" "$remote_port" "$remote_addr" "$local_port" "$local_addr" "$forward_type_text"
    
    read -e -p "请按回车键继续，如有配置错误请使用 CTRL + C 退出！" TRASH
    
    local remote_port_ipt=${remote_port//-/:}
    local local_port_ipt=${local_port//-/:}
    
    echo
    print_color "CGREEN" "[信息] 正在添加转发规则..."
    
    if [[ $forward_type == "1" || $forward_type == "3" ]]; then
        add_forward_rule_proto "$ip_version" "tcp" "$local_addr" "$local_port_ipt" "$remote_addr" "$remote_port" "$remote_port_ipt" || return 1
    fi
    
    if [[ $forward_type == "2" || $forward_type == "3" ]]; then
        add_forward_rule_proto "$ip_version" "udp" "$local_addr" "$local_port_ipt" "$remote_addr" "$remote_port" "$remote_port_ipt" || return 1
    fi
    
    print_color "CGREEN" "[信息] 转发规则添加成功"
    
    save_iptables
    
    show_forward_config "${COLORS[CGREEN]}✓ 创建转发规则完毕！${COLORS[CEND]}" "$rule_type" "$remote_port" "$remote_addr" "$local_port" "$local_addr" "$forward_type_text"
}

# 删除转发规则（选择 IPv4 或 IPv6）
delete_forward_rule() {
    echo
    print_color "CGREEN" "请选择要删除的规则类型："
    echo "  1. IPv4 转发规则"
    echo "  2. IPv6 转发规则"
    echo
    read -e -p "请输入选项 [1-2]: " rule_type
    rule_type=$(sanitize_input "$rule_type")
    
    case "$rule_type" in
        1)
            delete_iptables_rule
            ;;
        2)
            delete_ip6tables_rule
            ;;
        *)
            print_color "CRED" "[错误] 无效的选择"
            return 1
            ;;
    esac
}

# 删除转发规则
delete_tables_rule() {
    local ip_version="$1"
    local cmd_prefix="iptables"
    local version_text="IPv4"
    
    if [ "$ip_version" = "6" ]; then
        cmd_prefix="ip6tables"
        version_text="IPv6"
    fi
    
    while true; do
        local prerouting_rules=$(${cmd_prefix} -t nat -S PREROUTING 2>/dev/null | grep -v '^-P' | grep -v '^-N' | grep 'DNAT')
        
        if [ -z "$prerouting_rules" ]; then
            print_color "CRED" "[错误] 没有检测到 ${version_text} 转发规则"
            return 1
        fi
        
        echo
        print_color "CGREEN" "当前 ${version_text} 转发规则："
        echo
        
        local idx=1
        declare -A rule_map
        
        while IFS= read -r rule; do
            local proto=$(echo "$rule" | grep -oP '(?<=-p )\w+' || echo "unknown")
            local dport=$(echo "$rule" | grep -oP '(?<=--dport )[0-9:-]+' || echo "unknown")
            local dest=$(echo "$rule" | grep -oP '(?<=--to-destination )[^ ]+' || echo "unknown")
            
            proto=$(get_protocol_name "$proto")
            
            printf "%b%d.%b 协议: %s | 本地端口: %s | 转发到: %s\n" \
                "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "$proto" "$dport" "$dest"
            
            rule_map[$idx]="$rule"
            idx=$((idx + 1))
        done <<< "$prerouting_rules"
        
        echo
        read -e -p "请选择需要删除的规则编号（输入 'q' 退出）: " delete_id
        delete_id=$(sanitize_input "$delete_id")
        
        if [ "$delete_id" = "q" ] || [ "$delete_id" = "Q" ]; then
            print_color "CGREEN" "[信息] 退出删除模式"
            break
        fi
        
        if ! [[ "$delete_id" =~ ^[0-9]+$ ]]; then
            print_color "CRED" "[错误] 无效的选择，请输入数字或 'q' 退出"
            continue
        fi
        
        if [ -z "${rule_map[$delete_id]}" ]; then
            print_color "CRED" "[错误] 无效的规则编号"
            continue
        fi
        
        local rule_to_delete="${rule_map[$delete_id]}"
        local proto=$(echo "$rule_to_delete" | grep -oP '(?<=-p )\w+')
        local dport=$(echo "$rule_to_delete" | grep -oP '(?<=--dport )[0-9:-]+')
        local dest_full=$(echo "$rule_to_delete" | grep -oP '(?<=--to-destination )[^ ]+')
        local dest_ip
        if echo "$dest_full" | grep -q '\['; then
            dest_ip=$(echo "$dest_full" | sed 's/\[//g' | sed 's/\].*//g')
        else
            dest_ip=$(echo "$dest_full" | cut -d':' -f1)
        fi
        
        echo
        print_color "CGREEN" "[信息] 正在删除规则..."
        
        local pre_delete_cmd=$(echo "$rule_to_delete" | sed 's/-A PREROUTING/-D PREROUTING/')
        eval "${cmd_prefix} -t nat $pre_delete_cmd" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_color "CGREEN" "[信息] PREROUTING 规则删除成功"
        else
            print_color "CRED" "[错误] PREROUTING 规则删除失败"
            continue
        fi
        
        local post_rules=$(${cmd_prefix} -t nat -S POSTROUTING 2>/dev/null | grep "\-p $proto" | grep "dport $dport" | grep -E "(\-d $dest_ip|MASQUERADE)")
        
        if [ -n "$post_rules" ]; then
            while IFS= read -r post_rule; do
                local post_delete_cmd=$(echo "$post_rule" | sed 's/-A POSTROUTING/-D POSTROUTING/')
                eval "${cmd_prefix} -t nat $post_delete_cmd" 2>/dev/null
            done <<< "$post_rules"
            print_color "CGREEN" "[信息] POSTROUTING 规则删除成功"
        fi
        
        save_iptables
        echo
        print_color "CGREEN" "[信息] 规则删除完成！"
        
        local remaining_rules=$(${cmd_prefix} -t nat -S PREROUTING 2>/dev/null | grep 'DNAT')
        if [ -z "$remaining_rules" ]; then
            print_color "CGREEN" "[信息] 所有 ${version_text} 转发规则已删除完毕"
            break
        fi
    done
}

# 删除 IPv4 转发规则
delete_iptables_rule() {
    delete_tables_rule "4"
}

# 删除 IPv6 转发规则
delete_ip6tables_rule() {
    delete_tables_rule "6"
}

# 显示转发规则
show_tables_rules() {
    local ip_version="$1"
    local cmd_prefix="iptables"
    local version_text="iptables"
    
    if [ "$ip_version" = "6" ]; then
        cmd_prefix="ip6tables"
        version_text="ip6tables"
    fi
    
    local prerouting_rules postrouting_rules
    
    prerouting_rules=$(${cmd_prefix} -t nat -vnL PREROUTING 2>/dev/null | tail -n +3)
    postrouting_rules=$(${cmd_prefix} -t nat -vnL POSTROUTING 2>/dev/null | tail -n +3)
    
    if [ -z "$prerouting_rules" ] && [ -z "$postrouting_rules" ]; then
        print_color "CRED" "[错误] 没有检测到 ${version_text} 转发规则"
        return 1
    fi
    
    local rule_count=$(echo "$prerouting_rules" | grep -c '^')
    local rule_list=""
    
    for ((i = 1; i <= rule_count; i++)); do
        local pre_line=$(echo "$prerouting_rules" | sed -n "${i}p")
        local post_line=$(echo "$postrouting_rules" | sed -n "${i}p")
        local raw_proto=$(echo "$pre_line" | awk '{print $4}')
        local rule_type=$(get_protocol_name "$raw_proto")
        local rule_remote
        
        if [ "$ip_version" = "6" ]; then
            rule_remote=$(echo "$pre_line" | grep -oE 'to:\[[^]]+\]:[0-9:-]+|to:[^ ]+' | sed 's/to://')
        else
            rule_remote=$(echo "$pre_line" | grep -oE 'to:[^ ]+' | cut -d':' -f2-)
        fi
        
        local rule_local
        if echo "$post_line" | grep -q "MASQUERADE"; then
            rule_local="MASQUERADE"
        else
            rule_local=$(echo "$post_line" | grep -oE 'to:[^ ]+' | cut -d':' -f2-)
        fi
        
        rule_list+="${COLORS[CGREEN]}${i}.${COLORS[CEND]} "
        rule_list+="类型: ${rule_type} "
        rule_list+="本地地址: ${rule_local} "
        rule_list+="远程地址和端口: ${rule_remote}\n"
    done
    
    echo
    printf "当前有 %b%d%b 条 ${version_text} 转发规则\n" "${COLORS[CGREEN]}" "$rule_count" "${COLORS[CEND]}"
    echo -e "$rule_list"
    
    return 0
}

# 显示 iptables 规则
show_iptables_rules() {
    show_tables_rules "4"
}

# 显示 ip6tables 规则
show_ip6tables_rules() {
    show_tables_rules "6"
}

# 显示所有转发规则（IPv4 + IPv6）
show_all_rules() {
    local has_ipv4=0
    local has_ipv6=0
    local ipv4_rules=$(iptables -t nat -vnL PREROUTING | tail -n +3)
    
    if [ -n "$ipv4_rules" ]; then
        has_ipv4=1
    fi
    
    local ipv6_rules=$(ip6tables -t nat -vnL PREROUTING 2>/dev/null | tail -n +3)
    if [ -n "$ipv6_rules" ]; then
        has_ipv6=1
    fi
    
    if [ $has_ipv4 -eq 0 ] && [ $has_ipv6 -eq 0 ]; then
        print_color "CRED" "[错误] 没有检测到任何转发规则"
        return 1
    fi
    
    echo
    print_color "CGREEN" "========== 转发规则列表 =========="
    echo
    
    if [ $has_ipv4 -eq 1 ]; then
        print_color "CGREEN" "【IPv4 转发规则】"
        show_iptables_rules
    fi
    
    if [ $has_ipv6 -eq 1 ]; then
        if [ $has_ipv4 -eq 1 ]; then
            echo
        fi
        print_color "CGREEN" "【IPv6 转发规则】"
        show_ip6tables_rules
    fi
    
    return 0
}

# 保存iptables规则
save_iptables() {
    if [ "$RELEASE" = "debian" ] || [ "$RELEASE" = "ubuntu" ]; then
        if ! dpkg -l | grep -q iptables-persistent; then
            apt install -y iptables-persistent
        fi
    fi
    
    mkdir -p /etc/iptables
    
    print_color "CGREEN" "[信息] 正在保存 iptables 转发规则中！"
    
    if [ "$RELEASE" = "centos" ]; then
        service iptables save
        if command -v ip6tables >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ip6tables.service'; then
            service ip6tables save
        fi
    else
        netfilter-persistent save
    fi
    
    print_color "CGREEN" "[信息] 执行完毕！"
}

# 显示指定命令的规则
show_cmd_rules() {
    local cmd_prefix="$1"
    local title="$2"
    local output=$(${cmd_prefix} -L -n -v --line-numbers 2>/dev/null)
    if [ -n "$output" ]; then
        echo "$output"
    else
        print_color "CRED" "[错误] 无法查看 ${title} 规则"
    fi
}

# 查看完整的 iptables 规则
show_full_iptables_rules() {
    echo
    print_color "CGREEN" "========== IPv4 iptables 规则 (filter 表) =========="
    echo
    show_cmd_rules "iptables" "IPv4 iptables"
    
    if command -v ip6tables >/dev/null 2>&1; then
        echo
        print_color "CGREEN" "========== IPv6 ip6tables 规则 (filter 表) =========="
        echo
        show_cmd_rules "ip6tables" "IPv6 ip6tables"
    fi
    
    echo
    print_color "CGREEN" "========== NAT 表规则 =========="
    echo
    print_color "CGREEN" "【IPv4 NAT 表】"
    show_cmd_rules "iptables -t nat" "IPv4 NAT"
    
    if command -v ip6tables >/dev/null 2>&1; then
        echo
        print_color "CGREEN" "【IPv6 NAT 表】"
        show_cmd_rules "ip6tables -t nat" "IPv6 NAT"
    fi
    echo
}

# 清空指定命令的 iptables 规则
clear_tables_rules() {
    local cmd_prefix="$1"
    ${cmd_prefix} -P INPUT ACCEPT
    ${cmd_prefix} -P FORWARD ACCEPT
    ${cmd_prefix} -P OUTPUT ACCEPT
    ${cmd_prefix} -F
    ${cmd_prefix} -X
    ${cmd_prefix} -t nat -F
    ${cmd_prefix} -t nat -X
}

# 清空iptables规则
clear_iptables() {
    clear_tables_rules "iptables"
    
    if command -v ip6tables >/dev/null 2>&1; then
        clear_tables_rules "ip6tables"
    fi
    
    save_iptables
    
    if [ -f "/etc/iptables/rules.v4" ] || [ -f "/etc/iptables/rules.v6" ]; then
        rm -rf /etc/iptables
    fi
    
    print_color "CGREEN" "[信息] 执行完毕！所有规则已清空"
}

# 显示菜单
show_menu() {
    printf "端口转发管理脚本 %b[v%s]%b\n\n" "${COLORS[CRED]}" "$VERSION" "${COLORS[CEND]}"
    print_color "CGREEN" " 0. 安装 iptables / 启用 IP 转发"
    printf "%s\n" "————————————"
    print_color "CGREEN" " 1. 添加转发规则"
    print_color "CGREEN" " 2. 删除转发规则"
    print_color "CGREEN" " 3. 查看转发规则"
    print_color "CGREEN" " 4. 查看所有规则"
    print_color "CGREEN" " 5. 清空所有规则"
    printf "%s\n\n" "————————————"
}

# 主程序
main() {
    check_root
    show_menu
    
    local code
    read -e -p "请输入数字 [0-5]: " code
    code=$(sanitize_input "$code")
    
    case "$code" in
        0)
            install_iptables
            enable_ip_forward
            ;;
        1)
            create_forward_rule
            ;;
        2)
            delete_forward_rule
            ;;
        3)
            show_all_rules
            ;;
        4)
            show_full_iptables_rules
            ;;
        5)
            clear_iptables
            ;;
        *)
            print_color "CRED" "[错误] 请输入正确的数字！"
            ;;
    esac
}

main "$@"
exit 0