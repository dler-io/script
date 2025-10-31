#!/bin/bash
#
# 端口转发管理脚本
# 版本: 3.1.0
# 修复: IPv6地址解析、输入验证、删除规则逻辑

# 颜色定义
declare -A COLORS=(
    [CEND]="\033[0m"
    [CRED]="\033[1;31m"
    [CGREEN]="\033[1;32m"
    [CYELLOW]="\033[1;33m"
    [CSUCCESS]="\033[32m"
    [CFAILURE]="\033[1;31m"
    [CMSG]="\033[1;36m"
)

# 打印颜色信息
print_color() {
    local color="$1"
    shift
    local message="$*"
    printf "%b%s%b\n" "${COLORS[$color]}" "$message" "${COLORS[CEND]}"
}

VERSION="3.1.0"

# 清理输入（去除首尾空格）
sanitize_input() {
    local input="$1"
    echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            centos|rhel)
                echo "centos"
                ;;
            debian)
                echo "debian"
                ;;
            ubuntu)
                echo "ubuntu"
                ;;
            *)
                echo "unknown"
                ;;
        esac
    else
        # 备用检测方法
        if grep -qi "centos\|red hat\|rhel" /etc/issue 2>/dev/null || \
           grep -qi "centos\|red hat\|rhel" /proc/version 2>/dev/null; then
            echo "centos"
        elif grep -qi "debian" /etc/issue 2>/dev/null || \
             grep -qi "debian" /proc/version 2>/dev/null; then
            echo "debian"
        elif grep -qi "ubuntu" /etc/issue 2>/dev/null || \
             grep -qi "ubuntu" /proc/version 2>/dev/null; then
            echo "ubuntu"
        else
            echo "unknown"
        fi
    fi
}

RELEASE=$(detect_os)

# 检查root权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_color "CFAILURE" "[错误] 此脚本需要root权限运行！"
        exit 1
    fi
}

# 验证IPv4地址格式
validate_ipv4() {
    local ip="$1"
    # 支持 0.0.0.0（表示所有接口）
    if [ "$ip" = "0.0.0.0" ]; then
        return 0
    fi
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

# 验证IPv6地址格式（简化版）
validate_ipv6() {
    local ip="$1"
    # 支持 ::（表示所有接口）
    if [ "$ip" = "::" ]; then
        return 0
    fi
    # 基本的IPv6格式检查：包含冒号，且不是链路本地地址
    if [[ $ip =~ : ]] && [[ ! $ip =~ ^fe80: ]]; then
        return 0
    fi
    return 1
}

# 验证端口号
validate_port() {
    local port="$1"
    port=$(sanitize_input "$port")
    
    # 支持单个端口和端口范围
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
            print_color "CFAILURE" "[错误] 不支持的操作系统"
            exit 1
            ;;
    esac
    
    # 验证安装
    if ! command -v iptables >/dev/null 2>&1; then
        print_color "CFAILURE" "[错误] 安装iptables失败，请检查！"
        exit 1
    fi
    
    print_color "CSUCCESS" "[信息] 安装 iptables 完毕！"
}

# 启用IP转发
enable_ip_forward() {
    if [ -f /etc/sysctl.d/99-ip-forward.conf ]; then
        chattr -i /etc/sysctl.d/99-ip-forward.conf 2>/dev/null || true
    fi

    if [ -f /etc/sysctl.conf ]; then
        chattr -i /etc/sysctl.conf 2>/dev/null || true
    fi

    cat > /etc/sysctl.d/99-ip-forward.conf << 'EOF'
net.core.default_qdisc = fq
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
net.ipv6.icmp.echo_ignore_all = 1
EOF

    cat > /etc/sysctl.conf << 'EOF'
net.core.default_qdisc = fq
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
net.ipv6.icmp.echo_ignore_all = 1
EOF

    chattr +i /etc/sysctl.d/99-ip-forward.conf 2>/dev/null || true
    chattr +i /etc/sysctl.conf 2>/dev/null || true

    if systemctl is-enabled sysctl >/dev/null 2>&1; then
        systemctl enable sysctl >/dev/null 2>&1 || true
    fi

    sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-ip-forward.conf >/dev/null 2>&1 || true

    print_color "CSUCCESS" "[信息] IP 转发已启用"
}

# 列出所有网卡的IPv4地址 - 使用竖线分隔符
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
    
    # 输出结果 - 使用竖线分隔符避免冲突
    for iface in "${!ipv4_list[@]}"; do
        echo "${iface}|${ipv4_list[$iface]}"
    done
}

# 列出所有网卡的IPv6地址 - 修复：使用竖线分隔符
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
    
    # 输出结果 - 使用竖线分隔符，避免与IPv6地址中的冒号冲突
    for iface in "${!ipv6_list[@]}"; do
        echo "${iface}|${ipv6_list[$iface]}"
    done
}

# 让用户选择指定类型的IP地址 - 修复：使用竖线分隔符，支持0.0.0.0
select_ip_address_by_type() {
    local ip_type="$1"  # "4" for IPv4, "6" for IPv6
    
    if [ "$ip_type" = "4" ]; then
        # 只显示 IPv4
        local ip_list=($(list_all_ipv4))
        
        if [ ${#ip_list[@]} -eq 0 ]; then
            print_color "CFAILURE" "[错误] 未检测到任何 IPv4 地址" >&2
            return 1
        fi
        
        local idx=1
        local -A ip_map
        
        # 添加 0.0.0.0 选项（监听所有接口）
        printf "  %b%d.%b %s: %b%s%b %s\n" "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "所有接口" "${COLORS[CYELLOW]}" "0.0.0.0" "${COLORS[CEND]}" "(监听本机所有 IP)" >&2
        ip_map[$idx]="0.0.0.0|4"
        idx=$((idx + 1))
        
        for item in "${ip_list[@]}"; do
            local iface=$(echo "$item" | cut -d'|' -f1)
            local ip=$(echo "$item" | cut -d'|' -f2)
            printf "  %b%d.%b %s: %b%s%b\n" "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "$iface" "${COLORS[CYELLOW]}" "$ip" "${COLORS[CEND]}" >&2
            ip_map[$idx]="$ip|4"
            idx=$((idx + 1))
        done
        echo >&2
        
        local total=$((idx - 1))
        local choice
        read -e -p "请选择要使用的 IPv4 地址 [1-${total}]（直接回车默认选择所有接口，或输入 IPv4 地址）: " choice >&2
        choice=$(sanitize_input "$choice")
        
        if [ -z "$choice" ]; then
            # 直接回车，默认选择 0.0.0.0（所有接口）
            echo "0.0.0.0|4"
            return 0
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            if [ "$choice" -ge 1 ] && [ "$choice" -le $total ]; then
                echo "${ip_map[$choice]}"
                return 0
            else
                print_color "CFAILURE" "[错误] 无效的选择" >&2
                return 1
            fi
        else
            # 直接输入的IPv4地址 - 添加验证
            if validate_ipv4 "$choice"; then
                echo "$choice|4"
                return 0
            else
                print_color "CFAILURE" "[错误] 无效的 IPv4 地址格式" >&2
                return 1
            fi
        fi
    else
        # 只显示 IPv6
        local ip_list=($(list_all_ipv6))
        
        if [ ${#ip_list[@]} -eq 0 ]; then
            print_color "CFAILURE" "[错误] 未检测到任何 IPv6 地址" >&2
            return 1
        fi
        
        local idx=1
        local -A ip_map
        
        # 添加 :: 选项（监听所有接口）
        printf "  %b%d.%b %s: %b%s%b %s\n" "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "所有接口" "${COLORS[CYELLOW]}" "::" "${COLORS[CEND]}" "(监听本机所有 IPv6)" >&2
        ip_map[$idx]="::|6"
        idx=$((idx + 1))
        
        for item in "${ip_list[@]}"; do
            local iface=$(echo "$item" | cut -d'|' -f1)
            local ip=$(echo "$item" | cut -d'|' -f2)
            printf "  %b%d.%b %s: %b%s%b\n" "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" "$iface" "${COLORS[CYELLOW]}" "$ip" "${COLORS[CEND]}" >&2
            ip_map[$idx]="$ip|6"
            idx=$((idx + 1))
        done
        echo >&2
        
        local total=$((idx - 1))
        local choice
        read -e -p "请选择要使用的 IPv6 地址 [1-${total}]（直接回车默认选择所有接口，或输入 IPv6 地址）: " choice >&2
        choice=$(sanitize_input "$choice")
        
        if [ -z "$choice" ]; then
            # 直接回车，默认选择 ::（所有接口）
            echo "::|6"
            return 0
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
            if [ "$choice" -ge 1 ] && [ "$choice" -le $total ]; then
                echo "${ip_map[$choice]}"
                return 0
            else
                print_color "CFAILURE" "[错误] 无效的选择" >&2
                return 1
            fi
        else
            # 直接输入的IPv6地址 - 添加验证
            if validate_ipv6 "$choice"; then
                echo "$choice|6"
                return 0
            else
                print_color "CFAILURE" "[错误] 无效的 IPv6 地址格式" >&2
                return 1
            fi
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
            # 如果是其他值，尝试大写转换
            echo "$proto_num" | tr '[:lower:]' '[:upper:]'
            ;;
    esac
}

# 创建转发规则（统一处理IPv4和IPv6）
create_forward_rule() {
    # 输入验证和获取
    local remote_port
    read -e -p "请输入远程端口 [1-65535]（支持端口段，默认 22-40000）: " remote_port
    remote_port=$(sanitize_input "$remote_port")
    remote_port=${remote_port:-"22-40000"}
    
    if ! validate_port "$remote_port"; then
        print_color "CFAILURE" "[错误] 无效的端口格式！"
        exit 1
    fi
    
    local remote_addr
    read -e -p "请输入远程地址（IPv4 或 IPv6）: " remote_addr
    remote_addr=$(sanitize_input "$remote_addr")
    
    if [ -z "$remote_addr" ]; then
        print_color "CFAILURE" "[错误] 远程地址不能为空"
        exit 1
    fi
    
    # 检测远程地址类型并验证
    local ip_version
    if validate_ipv4 "$remote_addr"; then
        ip_version="4"
    elif validate_ipv6 "$remote_addr"; then
        ip_version="6"
    else
        print_color "CFAILURE" "[错误] 无效的 IP 地址格式"
        exit 1
    fi
    
    local local_port
    read -e -p "请输入本地端口 [1-65535]（回车跟随远程端口）: " local_port
    local_port=$(sanitize_input "$local_port")
    local_port=${local_port:-"$remote_port"}
    
    if ! validate_port "$local_port"; then
        print_color "CFAILURE" "[错误] 无效的本地端口格式！"
        exit 1
    fi
    
    # 根据远程地址类型选择本地地址
    echo
    local ip_with_type
    if [ "$ip_version" = "4" ]; then
        print_color "CMSG" "请选择本地 IPv4 地址："
        ip_with_type=$(select_ip_address_by_type "4")
    else
        print_color "CMSG" "请选择本地 IPv6 地址："
        ip_with_type=$(select_ip_address_by_type "6")
    fi
    
    if [ $? -ne 0 ] || [ -z "$ip_with_type" ]; then
        print_color "CFAILURE" "[错误] 未选择本地 IP 地址"
        exit 1
    fi
    
    local local_addr
    local_addr=$(echo "$ip_with_type" | cut -d'|' -f1)
    
    print_color "CMSG" "请选择转发类型
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
    
    # 确认配置
    local rule_type="iptables"
    if [ "$ip_version" = "6" ]; then
        rule_type="ip6tables"
    fi
    
    echo
    echo -e "——————————————————————————————
    请检查转发规则配置是否有误！

    规则类型: ${COLORS[CGREEN]}${rule_type}${COLORS[CEND]}
    远程端口: ${COLORS[CGREEN]}${remote_port}${COLORS[CEND]}
    远程地址: ${COLORS[CGREEN]}${remote_addr}${COLORS[CEND]}
    本地端口: ${COLORS[CGREEN]}${local_port}${COLORS[CEND]}
    本地地址: ${COLORS[CGREEN]}${local_addr}${COLORS[CEND]}
    转发类型: ${COLORS[CGREEN]}${forward_type_text}${COLORS[CEND]}
——————————————————————————————"
    echo
    
    read -e -p "请按回车键继续，如有配置错误请使用 CTRL + C 退出！" TRASH
    
    # 转换端口格式
    local remote_port_ipt=${remote_port//-/:}
    local local_port_ipt=${local_port//-/:}
    
    # 根据IP版本选择工具
    echo
    print_color "CMSG" "[信息] 正在添加转发规则..."
    
    if [ "$ip_version" = "4" ]; then
        # IPv4规则
        if [[ $forward_type == "1" || $forward_type == "3" ]]; then
            # 如果本地地址是 0.0.0.0，则不添加 POSTROUTING 的 SNAT 规则
            if [ "$local_addr" = "0.0.0.0" ]; then
                iptables -t nat -A PREROUTING -p tcp -m tcp --dport "${local_port_ipt}" -j DNAT --to-destination "${remote_addr}:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 TCP PREROUTING 规则失败"
                    return 1
                }
                # 对于 0.0.0.0，使用 MASQUERADE 代替 SNAT
                iptables -t nat -A POSTROUTING -d "${remote_addr}/32" -p tcp -m tcp --dport "${remote_port_ipt}" -j MASQUERADE || {
                    print_color "CFAILURE" "[错误] 添加 TCP POSTROUTING 规则失败"
                    return 1
                }
            else
                iptables -t nat -A PREROUTING -p tcp -m tcp --dport "${local_port_ipt}" -j DNAT --to-destination "${remote_addr}:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 TCP PREROUTING 规则失败"
                    return 1
                }
                iptables -t nat -A POSTROUTING -d "${remote_addr}/32" -p tcp -m tcp --dport "${remote_port_ipt}" -j SNAT --to-source "${local_addr}" || {
                    print_color "CFAILURE" "[错误] 添加 TCP POSTROUTING 规则失败"
                    return 1
                }
            fi
        fi
        
        if [[ $forward_type == "2" || $forward_type == "3" ]]; then
            if [ "$local_addr" = "0.0.0.0" ]; then
                iptables -t nat -A PREROUTING -p udp -m udp --dport "${local_port_ipt}" -j DNAT --to-destination "${remote_addr}:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 UDP PREROUTING 规则失败"
                    return 1
                }
                iptables -t nat -A POSTROUTING -d "${remote_addr}/32" -p udp -m udp --dport "${remote_port_ipt}" -j MASQUERADE || {
                    print_color "CFAILURE" "[错误] 添加 UDP POSTROUTING 规则失败"
                    return 1
                }
            else
                iptables -t nat -A PREROUTING -p udp -m udp --dport "${local_port_ipt}" -j DNAT --to-destination "${remote_addr}:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 UDP PREROUTING 规则失败"
                    return 1
                }
                iptables -t nat -A POSTROUTING -d "${remote_addr}/32" -p udp -m udp --dport "${remote_port_ipt}" -j SNAT --to-source "${local_addr}" || {
                    print_color "CFAILURE" "[错误] 添加 UDP POSTROUTING 规则失败"
                    return 1
                }
            fi
        fi
    else
        # IPv6规则
        if [[ $forward_type == "1" || $forward_type == "3" ]]; then
            # 如果本地地址是 ::，使用 MASQUERADE
            if [ "$local_addr" = "::" ]; then
                ip6tables -t nat -A PREROUTING -p tcp -m tcp --dport "${local_port_ipt}" -j DNAT --to-destination "[${remote_addr}]:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 TCP PREROUTING 规则失败"
                    return 1
                }
                ip6tables -t nat -A POSTROUTING -d "${remote_addr}/128" -p tcp -m tcp --dport "${remote_port_ipt}" -j MASQUERADE || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 TCP POSTROUTING 规则失败"
                    return 1
                }
            else
                ip6tables -t nat -A PREROUTING -p tcp -m tcp --dport "${local_port_ipt}" -j DNAT --to-destination "[${remote_addr}]:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 TCP PREROUTING 规则失败"
                    return 1
                }
                ip6tables -t nat -A POSTROUTING -d "${remote_addr}/128" -p tcp -m tcp --dport "${remote_port_ipt}" -j SNAT --to-source "${local_addr}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 TCP POSTROUTING 规则失败"
                    return 1
                }
            fi
        fi
        
        if [[ $forward_type == "2" || $forward_type == "3" ]]; then
            if [ "$local_addr" = "::" ]; then
                ip6tables -t nat -A PREROUTING -p udp -m udp --dport "${local_port_ipt}" -j DNAT --to-destination "[${remote_addr}]:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 UDP PREROUTING 规则失败"
                    return 1
                }
                ip6tables -t nat -A POSTROUTING -d "${remote_addr}/128" -p udp -m udp --dport "${remote_port_ipt}" -j MASQUERADE || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 UDP POSTROUTING 规则失败"
                    return 1
                }
            else
                ip6tables -t nat -A PREROUTING -p udp -m udp --dport "${local_port_ipt}" -j DNAT --to-destination "[${remote_addr}]:${remote_port}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 UDP PREROUTING 规则失败"
                    return 1
                }
                ip6tables -t nat -A POSTROUTING -d "${remote_addr}/128" -p udp -m udp --dport "${remote_port_ipt}" -j SNAT --to-source "${local_addr}" || {
                    print_color "CFAILURE" "[错误] 添加 IPv6 UDP POSTROUTING 规则失败"
                    return 1
                }
            fi
        fi
    fi
    
    print_color "CSUCCESS" "[信息] 转发规则添加成功"
    
    save_iptables
    
    echo
    echo -e "——————————————————————————————
    ${COLORS[CSUCCESS]}✓ 创建转发规则完毕！${COLORS[CEND]}

    规则类型: ${COLORS[CGREEN]}${rule_type}${COLORS[CEND]}
    远程端口: ${COLORS[CGREEN]}${remote_port}${COLORS[CEND]}
    远程地址: ${COLORS[CGREEN]}${remote_addr}${COLORS[CEND]}
    本地端口: ${COLORS[CGREEN]}${local_port}${COLORS[CEND]}
    本地地址: ${COLORS[CGREEN]}${local_addr}${COLORS[CEND]}
    转发类型: ${COLORS[CGREEN]}${forward_type_text}${COLORS[CEND]}
——————————————————————————————"
    echo
}

# 删除转发规则（选择 IPv4 或 IPv6）
delete_forward_rule() {
    echo
    print_color "CMSG" "请选择要删除的规则类型："
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
            print_color "CFAILURE" "[错误] 无效的选择"
            return 1
            ;;
    esac
}

# 修复：改进的删除 IPv4 转发规则逻辑
delete_iptables_rule() {
    while true; do
        # 获取所有PREROUTING规则
        local prerouting_rules=$(iptables -t nat -S PREROUTING | grep -v '^-P' | grep -v '^-N' | grep 'DNAT')
        
        if [ -z "$prerouting_rules" ]; then
            print_color "CFAILURE" "[错误] 没有检测到 IPv4 转发规则"
            return 1
        fi
        
        # 显示规则
        echo
        print_color "CSUCCESS" "当前 IPv4 转发规则："
        echo
        
        local idx=1
        declare -A rule_map
        
        while IFS= read -r rule; do
            # 解析规则信息
            local proto=$(echo "$rule" | grep -oP '(?<=-p )\w+' || echo "unknown")
            local dport=$(echo "$rule" | grep -oP '(?<=--dport )[0-9:-]+' || echo "unknown")
            local dest=$(echo "$rule" | grep -oP '(?<=--to-destination )[^ ]+' || echo "unknown")
            
            proto=$(get_protocol_name "$proto")
            
            printf "%b%d.%b %b协议:%b %s | %b本地端口:%b %s | %b转发到:%b %s\n" \
                "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$proto" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$dport" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$dest"
            
            # 保存完整规则用于删除
            rule_map[$idx]="$rule"
            idx=$((idx + 1))
        done <<< "$prerouting_rules"
        
        echo
        read -e -p "请选择需要删除的规则编号（输入 'q' 退出）: " delete_id
        delete_id=$(sanitize_input "$delete_id")
        
        if [ "$delete_id" = "q" ] || [ "$delete_id" = "Q" ]; then
            print_color "CMSG" "[信息] 退出删除模式"
            break
        fi
        
        if ! [[ "$delete_id" =~ ^[0-9]+$ ]]; then
            print_color "CFAILURE" "[错误] 无效的选择，请输入数字或 'q' 退出"
            continue
        fi
        
        if [ -z "${rule_map[$delete_id]}" ]; then
            print_color "CFAILURE" "[错误] 无效的规则编号"
            continue
        fi
        
        # 获取要删除的规则
        local rule_to_delete="${rule_map[$delete_id]}"
        
        # 提取关键信息用于匹配POSTROUTING规则
        local proto=$(echo "$rule_to_delete" | grep -oP '(?<=-p )\w+')
        local dport=$(echo "$rule_to_delete" | grep -oP '(?<=--dport )[0-9:-]+')
        local dest_full=$(echo "$rule_to_delete" | grep -oP '(?<=--to-destination )[^ ]+')
        local dest_ip=$(echo "$dest_full" | cut -d':' -f1)
        
        echo
        print_color "CMSG" "[信息] 正在删除规则..."
        
        # 删除PREROUTING规则（使用规则内容而非编号）
        local pre_delete_cmd=$(echo "$rule_to_delete" | sed 's/-A PREROUTING/-D PREROUTING/')
        eval "iptables -t nat $pre_delete_cmd" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_color "CSUCCESS" "[信息] PREROUTING 规则删除成功"
        else
            print_color "CFAILURE" "[错误] PREROUTING 规则删除失败"
            continue
        fi
        
        # 查找并删除对应的POSTROUTING规则
        # 注意：如果使用了 MASQUERADE，规则格式会不同
        local post_rules=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep "\-p $proto" | grep "dport $dport" | grep -E "(\-d $dest_ip|MASQUERADE)")
        
        if [ -n "$post_rules" ]; then
            while IFS= read -r post_rule; do
                local post_delete_cmd=$(echo "$post_rule" | sed 's/-A POSTROUTING/-D POSTROUTING/')
                eval "iptables -t nat $post_delete_cmd" 2>/dev/null
            done <<< "$post_rules"
            print_color "CSUCCESS" "[信息] POSTROUTING 规则删除成功"
        fi
        
        save_iptables
        echo
        print_color "CSUCCESS" "[信息] 规则删除完成！"
        
        # 检查是否还有规则
        local remaining_rules=$(iptables -t nat -S PREROUTING | grep 'DNAT')
        if [ -z "$remaining_rules" ]; then
            print_color "CMSG" "[信息] 所有 IPv4 转发规则已删除完毕"
            break
        fi
    done
}

# 修复：改进的删除 IPv6 转发规则逻辑
delete_ip6tables_rule() {
    while true; do
        # 获取所有PREROUTING规则
        local prerouting_rules=$(ip6tables -t nat -S PREROUTING 2>/dev/null | grep -v '^-P' | grep -v '^-N' | grep 'DNAT')
        
        if [ -z "$prerouting_rules" ]; then
            print_color "CFAILURE" "[错误] 没有检测到 IPv6 转发规则"
            return 1
        fi
        
        # 显示规则
        echo
        print_color "CSUCCESS" "当前 IPv6 转发规则："
        echo
        
        local idx=1
        declare -A rule_map
        
        while IFS= read -r rule; do
            # 解析规则信息
            local proto=$(echo "$rule" | grep -oP '(?<=-p )\w+' || echo "unknown")
            local dport=$(echo "$rule" | grep -oP '(?<=--dport )[0-9:-]+' || echo "unknown")
            local dest=$(echo "$rule" | grep -oP '(?<=--to-destination )[^ ]+' || echo "unknown")
            
            proto=$(get_protocol_name "$proto")
            
            printf "%b%d.%b %b协议:%b %s | %b本地端口:%b %s | %b转发到:%b %s\n" \
                "${COLORS[CGREEN]}" "$idx" "${COLORS[CEND]}" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$proto" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$dport" \
                "${COLORS[CYELLOW]}" "${COLORS[CEND]}" "$dest"
            
            # 保存完整规则用于删除
            rule_map[$idx]="$rule"
            idx=$((idx + 1))
        done <<< "$prerouting_rules"
        
        echo
        read -e -p "请选择需要删除的规则编号（输入 'q' 退出）: " delete_id
        delete_id=$(sanitize_input "$delete_id")
        
        if [ "$delete_id" = "q" ] || [ "$delete_id" = "Q" ]; then
            print_color "CMSG" "[信息] 退出删除模式"
            break
        fi
        
        if ! [[ "$delete_id" =~ ^[0-9]+$ ]]; then
            print_color "CFAILURE" "[错误] 无效的选择，请输入数字或 'q' 退出"
            continue
        fi
        
        if [ -z "${rule_map[$delete_id]}" ]; then
            print_color "CFAILURE" "[错误] 无效的规则编号"
            continue
        fi
        
        # 获取要删除的规则
        local rule_to_delete="${rule_map[$delete_id]}"
        
        # 提取关键信息用于匹配POSTROUTING规则
        local proto=$(echo "$rule_to_delete" | grep -oP '(?<=-p )\w+')
        local dport=$(echo "$rule_to_delete" | grep -oP '(?<=--dport )[0-9:-]+')
        local dest_full=$(echo "$rule_to_delete" | grep -oP '(?<=--to-destination )[^ ]+')
        # IPv6地址可能在方括号中
        local dest_ip=$(echo "$dest_full" | sed 's/\[//g' | sed 's/\].*//g')
        
        echo
        print_color "CMSG" "[信息] 正在删除规则..."
        
        # 删除PREROUTING规则（使用规则内容而非编号）
        local pre_delete_cmd=$(echo "$rule_to_delete" | sed 's/-A PREROUTING/-D PREROUTING/')
        eval "ip6tables -t nat $pre_delete_cmd" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_color "CSUCCESS" "[信息] PREROUTING 规则删除成功"
        else
            print_color "CFAILURE" "[错误] PREROUTING 规则删除失败"
            continue
        fi
        
        # 查找并删除对应的POSTROUTING规则
        # 注意：如果使用了 MASQUERADE，规则格式会不同
        local post_rules=$(ip6tables -t nat -S POSTROUTING 2>/dev/null | grep "\-p $proto" | grep "dport $dport" | grep -E "(\-d $dest_ip|MASQUERADE)")
        
        if [ -n "$post_rules" ]; then
            while IFS= read -r post_rule; do
                local post_delete_cmd=$(echo "$post_rule" | sed 's/-A POSTROUTING/-D POSTROUTING/')
                eval "ip6tables -t nat $post_delete_cmd" 2>/dev/null
            done <<< "$post_rules"
            print_color "CSUCCESS" "[信息] POSTROUTING 规则删除成功"
        fi
        
        save_iptables
        echo
        print_color "CSUCCESS" "[信息] 规则删除完成！"
        
        # 检查是否还有规则
        local remaining_rules=$(ip6tables -t nat -S PREROUTING 2>/dev/null | grep 'DNAT')
        if [ -z "$remaining_rules" ]; then
            print_color "CMSG" "[信息] 所有 IPv6 转发规则已删除完毕"
            break
        fi
    done
}

# 显示iptables规则
show_iptables_rules() {
    local prerouting_rules postrouting_rules
    
    prerouting_rules=$(iptables -t nat -vnL PREROUTING | tail -n +3)
    postrouting_rules=$(iptables -t nat -vnL POSTROUTING | tail -n +3)
    
    if [ -z "$prerouting_rules" ] && [ -z "$postrouting_rules" ]; then
        print_color "CFAILURE" "[错误] 没有检测到 iptables 转发规则"
        return 1
    fi
    
    local rule_count=$(echo "$prerouting_rules" | grep -c '^')
    local rule_list=""
    
    for ((i = 1; i <= rule_count; i++)); do
        local pre_line=$(echo "$prerouting_rules" | sed -n "${i}p")
        local post_line=$(echo "$postrouting_rules" | sed -n "${i}p")
        
        # 获取协议信息
        local raw_proto=$(echo "$pre_line" | awk '{print $4}')
        local rule_type=$(get_protocol_name "$raw_proto")
        
        # 提取目标地址（DNAT to:）
        local rule_remote=$(echo "$pre_line" | grep -oE 'to:[^ ]+' | cut -d':' -f2-)
        
        # 提取源地址（SNAT to: 或 MASQUERADE）
        local rule_local
        if echo "$post_line" | grep -q "MASQUERADE"; then
            rule_local="0.0.0.0"
        else
            rule_local=$(echo "$post_line" | grep -oE 'to:[^ ]+' | cut -d':' -f2-)
        fi
        
        rule_list+="${COLORS[CGREEN]}${i}.${COLORS[CEND]} "
        rule_list+="${COLORS[CYELLOW]}类型: ${COLORS[CEND]}${rule_type} "
        rule_list+="${COLORS[CYELLOW]}本地地址: ${COLORS[CEND]}${rule_local} "
        rule_list+="${COLORS[CYELLOW]}远程地址和端口: ${COLORS[CEND]}${rule_remote}\n"
    done
    
    echo
    printf "当前有 %b%d%b 条 iptables 转发规则\n" "${COLORS[CGREEN]}" "$rule_count" "${COLORS[CEND]}"
    echo -e "$rule_list"
    
    return 0
}

# 显示ip6tables规则
show_ip6tables_rules() {
    local prerouting_rules postrouting_rules
    
    prerouting_rules=$(ip6tables -t nat -vnL PREROUTING | tail -n +3)
    postrouting_rules=$(ip6tables -t nat -vnL POSTROUTING | tail -n +3)
    
    if [ -z "$prerouting_rules" ] && [ -z "$postrouting_rules" ]; then
        print_color "CFAILURE" "[错误] 没有检测到 ip6tables 转发规则"
        return 1
    fi
    
    local rule_count=$(echo "$prerouting_rules" | grep -c '^')
    local rule_list=""
    
    for ((i = 1; i <= rule_count; i++)); do
        local pre_line=$(echo "$prerouting_rules" | sed -n "${i}p")
        local post_line=$(echo "$postrouting_rules" | sed -n "${i}p")
        
        # 获取协议信息
        local raw_proto=$(echo "$pre_line" | awk '{print $4}')
        local rule_type=$(get_protocol_name "$raw_proto")
        
        # 提取目标地址（DNAT to:）
        local rule_remote=$(echo "$pre_line" | grep -oE 'to:\[[^]]+\]:[0-9:-]+|to:[^ ]+' | sed 's/to://')
        
        # 提取源地址（SNAT to: 或 MASQUERADE）
        local rule_local
        if echo "$post_line" | grep -q "MASQUERADE"; then
            rule_local="::"
        else
            rule_local=$(echo "$post_line" | grep -oE 'to:[^ ]+' | cut -d':' -f2-)
        fi
        
        rule_list+="${COLORS[CGREEN]}${i}.${COLORS[CEND]} "
        rule_list+="${COLORS[CYELLOW]}类型: ${COLORS[CEND]}${rule_type} "
        rule_list+="${COLORS[CYELLOW]}本地地址: ${COLORS[CEND]}${rule_local} "
        rule_list+="${COLORS[CYELLOW]}远程地址和端口: ${COLORS[CEND]}${rule_remote}\n"
    done
    
    echo
    printf "当前有 %b%d%b 条 ip6tables 转发规则\n" "${COLORS[CGREEN]}" "$rule_count" "${COLORS[CEND]}"
    echo -e "$rule_list"
    
    return 0
}

# 显示所有转发规则（IPv4 + IPv6）
show_all_rules() {
    local has_ipv4=0
    local has_ipv6=0
    
    # 检查 IPv4 规则
    local ipv4_rules=$(iptables -t nat -vnL PREROUTING | tail -n +3)
    if [ -n "$ipv4_rules" ]; then
        has_ipv4=1
    fi
    
    # 检查 IPv6 规则
    local ipv6_rules=$(ip6tables -t nat -vnL PREROUTING 2>/dev/null | tail -n +3)
    if [ -n "$ipv6_rules" ]; then
        has_ipv6=1
    fi
    
    if [ $has_ipv4 -eq 0 ] && [ $has_ipv6 -eq 0 ]; then
        print_color "CFAILURE" "[错误] 没有检测到任何转发规则"
        return 1
    fi
    
    echo
    print_color "CSUCCESS" "========== 转发规则列表 =========="
    echo
    
    # 显示 IPv4 规则
    if [ $has_ipv4 -eq 1 ]; then
        print_color "CMSG" "【IPv4 转发规则】"
        show_iptables_rules
    fi
    
    # 显示 IPv6 规则
    if [ $has_ipv6 -eq 1 ]; then
        if [ $has_ipv4 -eq 1 ]; then
            echo
        fi
        print_color "CMSG" "【IPv6 转发规则】"
        show_ip6tables_rules
    fi
    
    return 0
}

# 保存iptables规则
save_iptables() {
    # 安装必要软件包
    if [ "$RELEASE" = "debian" ] || [ "$RELEASE" = "ubuntu" ]; then
        if ! dpkg -l | grep -q iptables-persistent; then
            apt install -y iptables-persistent
        fi
    fi
    
    mkdir -p /etc/iptables
    
    print_color "CMSG" "[信息] 正在保存 iptables 转发规则中！"
    
    if [ "$RELEASE" = "centos" ]; then
        service iptables save
        if command -v ip6tables >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ip6tables.service'; then
            service ip6tables save
        fi
    else
        netfilter-persistent save
    fi
    
    print_color "CMSG" "[信息] 执行完毕！"
}

# 清空iptables规则
clear_iptables() {
    print_color "CMSG" "[信息] 正在清空所有转发规则中！"
    
    # 清空IPv4规则
    iptables -t nat -F
    iptables -t nat -X
    
    # 清空IPv6规则
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -t nat -F
        ip6tables -t nat -X
    fi
    
    save_iptables
    
    if [ -f "/etc/iptables/rules.v4" ] || [ -f "/etc/iptables/rules.v6" ]; then
        rm -rf /etc/iptables
    fi
    
    print_color "CMSG" "[信息] 执行完毕！"
}

# 显示菜单
show_menu() {
    printf "端口转发管理脚本 %b[v%s]%b\n\n" "${COLORS[CRED]}" "$VERSION" "${COLORS[CEND]}"
    print_color "CGREEN" " 0. 安装 iptables / 启用 IP 转发"
    printf "%s\n" "————————————"
    print_color "CGREEN" " 1. 添加转发规则"
    print_color "CGREEN" " 2. 删除转发规则"
    print_color "CGREEN" " 3. 查看转发规则"
    print_color "CGREEN" " 4. 清空所有转发规则"
    printf "%s\n\n" "————————————"
}

# 主程序
main() {
    check_root
    show_menu
    
    local code
    read -e -p "请输入数字 [0-4]: " code
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
            clear_iptables
            ;;
        *)
            print_color "CFAILURE" "[错误] 请输入正确的数字！"
            ;;
    esac
}

main "$@"
exit 0