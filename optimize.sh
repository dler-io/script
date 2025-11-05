#!/bin/bash

# Linux General System Performance Optimization Script
# Features: Time sync, kernel parameter tuning, network optimization, system limit adjustment
# Support: Ubuntu/Debian/CentOS

set -euo pipefail

# Color Output Function Definitions

# Detect compatible echo command
echo=echo
for cmd in echo /bin/echo; do
    $cmd >/dev/null 2>&1 || continue
    if ! $cmd -e "" | grep -qE '^-e'; then
        echo=$cmd
        break
    fi
done

# Define color codes
CSI=$($echo -e "\033[")
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CYELLOW="${CSI}1;33m"
CCYAN="${CSI}1;36m"

# Output functions
OUT_ALERT() {
    echo -e "${CYELLOW}[警告] $1${CEND}"
}

OUT_ERROR() {
    echo -e "${CRED}[错误] $1${CEND}"
}

OUT_INFO() {
    echo -e "${CCYAN}[信息] $1${CEND}"
}

OUT_SUCCESS() {
    echo -e "${CGREEN}[成功] $1${CEND}"
}

# System Detection Function

detect_os() {
    local release=""
    
    # Check /etc/redhat-release first
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    # Check /etc/issue
    elif [[ -f /etc/issue ]]; then
        if grep -qE -i "debian|raspbian" /etc/issue 2>/dev/null; then
            release="debian"
        elif grep -qE -i "ubuntu" /etc/issue 2>/dev/null; then
            release="ubuntu"
        elif grep -qE -i "centos|red hat|redhat" /etc/issue 2>/dev/null; then
            release="centos"
        fi
    fi
    
    # Fallback to /proc/version if not detected
    if [[ -z "$release" ]]; then
        if grep -qE -i "raspbian|debian" /proc/version 2>/dev/null; then
            release="debian"
        elif grep -qE -i "ubuntu" /proc/version 2>/dev/null; then
            release="ubuntu"
        elif grep -qE -i "centos|red hat|redhat" /proc/version 2>/dev/null; then
            release="centos"
        fi
    fi
    
    if [[ -z "$release" ]]; then
        OUT_ERROR "不支持的操作系统！"
        exit 1
    fi
    
    OUT_INFO "检测到操作系统: $release"
}

# Time Synchronization Configuration

setup_time_sync() {
    OUT_INFO "配置系统时间同步"
    
    if ! command -v chronyd >/dev/null 2>&1; then
        apt-get install -y chrony >/dev/null 2>&1
    fi
    
    if ! systemctl is-active --quiet chronyd; then
        systemctl enable --now chronyd
    fi
    
    timedatectl set-timezone Asia/Shanghai 2>/dev/null || true
    OUT_SUCCESS "时间同步配置完成"
}

# Random Number Generator Optimization

optimize_random_generator() {
    OUT_INFO "优化随机数生成器性能"
    
    # Install haveged (only one random number generator is needed)
    if [[ -z "$(command -v haveged)" ]]; then
        apt install haveged -y >/dev/null 2>&1
        systemctl enable haveged >/dev/null 2>&1
    fi
    
    OUT_SUCCESS "随机数生成器优化完成"
}

# Kernel Parameter Optimization

optimize_kernel_params() {
    OUT_INFO "优化内核参数"

    # Calculate TCP buffer size based on total system memory (using 1000 for decimal conversion)
    local mem_total_kb=$(free -k | grep Mem: | awk '{print $2}')
    local mem_total_mb=$((mem_total_kb / 1000))
    local mem_total_gb=$((mem_total_kb / 1000 / 1000))
    local mem_display=""
    local tcp_max_buffer=""

    # Format memory display (use MB if less than 1GB, otherwise use GB)
    if [ "$mem_total_gb" -gt 0 ]; then
        mem_display="${mem_total_gb}GB"
    else
        mem_display="${mem_total_mb}MB"
    fi

    # Adjust TCP buffer size based on system memory (thresholds in MB using decimal conversion)
    if [ "$mem_total_mb" -lt 2000 ]; then
        tcp_max_buffer="33554432"
        OUT_INFO "检测到内存: ${mem_display}，使用缓冲区 (32MB)"
    elif [ "$mem_total_mb" -lt 4000 ]; then
        tcp_max_buffer="134217728"
        OUT_INFO "检测到内存: ${mem_display}，使用缓冲区 (128MB)"
    elif [ "$mem_total_mb" -lt 8000 ]; then
        tcp_max_buffer="268435456"
        OUT_INFO "检测到内存: ${mem_display}，使用缓冲区 (256MB)"
    elif [ "$mem_total_mb" -lt 32000 ]; then
        tcp_max_buffer="536870912"
        OUT_INFO "检测到内存: ${mem_display}，使用缓冲区 (512MB)"
    else
        tcp_max_buffer="1073741824"
        OUT_INFO "检测到内存: ${mem_display}，使用缓冲区 (1GB)"
    fi

    # Calculate core buffer size (1/10 of max buffer, but cap at 64MB)
    local core_buffer_size=$((tcp_max_buffer / 10))
    if [ "$core_buffer_size" -gt 67108864 ]; then
        core_buffer_size="67108864"
    fi

    # Define sysctl parameters optimized for high bandwidth
    SYSCTL_CONFIG="net.core.default_qdisc          = fq
net.core.rmem_max               = ${core_buffer_size}
net.core.wmem_max               = ${core_buffer_size}
net.core.somaxconn              = 4096
net.ipv4.tcp_max_syn_backlog    = 4096
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_rmem               = 16384 16777216 ${tcp_max_buffer}
net.ipv4.tcp_wmem               = 16384 16777216 ${tcp_max_buffer}
net.ipv4.tcp_adv_win_scale      = 1
net.ipv4.tcp_sack               = 1
net.ipv4.tcp_timestamps         = 1
net.ipv4.tcp_fastopen           = 3
net.ipv4.ip_local_port_range    = 1024 65535
kernel.panic                    = 0
vm.swappiness                   = 0"

    # Ensure directory exists
    mkdir -p /etc/sysctl.d 2>/dev/null || true
    
    # Write to /etc/sysctl.d/99-sysctl.conf (for modern systems)
    rm -f /etc/sysctl.d/99-sysctl.conf 2>/dev/null || true
    echo "$SYSCTL_CONFIG" | tee /etc/sysctl.d/99-sysctl.conf > /dev/null 2>&1 || true

    # Also write to /etc/sysctl.conf (for compatibility with old systems)
    echo "$SYSCTL_CONFIG" | tee /etc/sysctl.conf > /dev/null 2>&1 || true

    sysctl --system >/dev/null 2>&1 || sysctl -p || true
    OUT_SUCCESS "内核参数优化完成"
}

# System Limit Adjustment

adjust_system_limits() {
    OUT_INFO "调整系统资源限制"
    
    cat <<'EOF' > /etc/security/limits.conf
# System Resource Limit Configuration
* soft nofile unlimited
* hard nofile unlimited
* soft nproc unlimited
* hard nproc unlimited
EOF

    cat <<'EOF' > /etc/systemd/system.conf
[Manager]
DefaultCPUAccounting=yes
DefaultIOAccounting=yes
DefaultIPAccounting=yes
DefaultMemoryAccounting=yes
DefaultTasksAccounting=yes
DefaultLimitCORE=infinity
DefaultLimitNPROC=infinity
DefaultLimitNOFILE=infinity
EOF

    OUT_SUCCESS "系统限制调整完成"
}

# Main Function

main() {
    OUT_ALERT "开始通用系统性能优化..."
    
    # Detect operating system
    detect_os
    
    # Execute various optimizations
    setup_time_sync
    optimize_random_generator
    optimize_kernel_params
    adjust_system_limits
    
    OUT_SUCCESS "通用系统性能优化完成！"
    OUT_INFO "建议重启系统以确保所有配置生效"
}

# Script Entry Point

    # Check if running as root
if [[ $EUID -ne 0 ]]; then
    OUT_ERROR "此脚本需要 root 权限运行"
    exit 1
fi

    # Execute main function
main

exit 0
