#!/usr/bin/env bash

# 功能：在debian base系统上创建Wi-Fi热点，通过shadowsocks实现透明代理
# 原作者：7sDream
# 修改者：Qv Junping

# 依赖：
#   - hostapd、dnsmasq、nmcli、rfkill、iptables、iproute2需要安装
#   - 支持AP模式的无线网卡, 并且当前没有连接任何Wi-Fi
#   - 如果要使用shadowsocks转发，需要安装shadowsocks-libev
#   - root权限

# ===== [用户配置] ====

# 此接口已经可以访问Internet，大多数情况是以太网卡，比如eth0或enp1s0
# 如果设空，将读取第一个参数或从向导中读取
WAN_INTERFACE=""

# 此接口将用来创建热点，大多数情况是无线网卡，比如wlan0或wlp2s0
# 如果设空，将读取第二个参数或从向导中读取
LAN_INTERFACE=""

# 热点SSID，即热点名，如果设空，将读取第三个参数或从向导中读取
AP_NAME=""

# 热点密码，如果设空，将读取第四个参数或从向导中读取
PASSWORD=""

# 使用shadowsocks转发，实现透明代理
# 值可以是yes或no
# 如果设空，将读取第五个参数或从向导中读取
ENABLE_SS_RELAY=""

# 当ENABLE_SS_RELAY = yes时，下边配置有效
SS_SERVER_ADDR=""       # Shadowsocks服务器地址（参数六）
SS_SERVER_PORT=""       # Shadowsocks服务器端口（参数七）
SS_PASSWORD=""          # Shadowsocks账户密码（参数八）
SS_METHOD=""            # Shadowsocks加密方式（参数九）
SS_LOCAL_PORT="12345"   # ss-redir本地端口（参数十）
SS_TIMEOUT="600"        # shadowsocks超时
SS_FAST_OPEN="false"    # 是否使用TCP fastopen
# =====

# 显示配置信息，等待用户确认
NEED_CONFIRM=0

DHCP_ROUTER_IP="192.168.43.1"
DHCP_RANGE_MIN="192.168.43.2"
DHCP_RANGE_MAX="192.168.43.10"

# DNSPod DNS
DNS_1="119.29.29.29"

# Google DNS
DNS_2="8.8.8.8"

# 其他可选DNS

# 阿里巴巴DNS
# DNS_1="223.5.5.5"
# DNS_2="223.6.6.6"

# 中科大LUG DNS
# 202.38.64.1       (中科大LUG)
# 202.38.93.153     (中科大LUG Education)
# 202.141.176.93    (中科大LUG China Mobile)
# 202.141.162.123   (中科大LUG China Telecom)

# ===== End of [用户配置] ====

# ===== [设置参数] =====
SCRIPTPATH=$(dirname $0)
IPTABLES_CHAIN_NAME="SHADOWSOCKS"
FWMARK="0x01/0x01"
IPROUTE2_TABLEID=100

read -d '' SS_CONF_TEMPLATE << EOF
{
    "server": "{SS_SERVER_ADDR}",
    "server_port": {SS_SERVER_PORT},
    "local_address": "0.0.0.0",
    "local_port": {SS_LOCAL_PORT},
    "password": "{SS_PASSWORD}",
    "timeout": {SS_TIMEOUT},
    "method": "{SS_METHOD}",
    "fast_open": {SS_FAST_OPEN}
}
EOF

read -d '' DNSMASQ_CONF_TEMPLATE << EOF
interface={LAN_INTERFACE}
bind-interfaces
dhcp-range={DHCP_RANGE_MIN},{DHCP_RANGE_MAX}
dhcp-option=option:router,{DHCP_ROUTER_IP}
dhcp-option=option:dns-server,{DHCP_ROUTER_IP}
no-resolv
no-poll
server={DNS_1}
server={DNS_2}
EOF

read -d '' HOSTAPD_CONF_TEMPLATE << EOF
interface={LAN_INTERFACE}
driver=nl80211
ssid={SSID}
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={PASSWORD}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

RED='\033[0;31m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'
# ===== End of [设置参数] =====

# ===== [定义函数] =====
function error() {
    echo -e -n "${RED}ERROR!${NC}: "
    echo -e $1
    exit 1
}

function command_test() {
    # 检查系统中[$1: command]是否存在。
    # 如果不存在，告诉用户安装[$2: the package]

    if [ -n "$2" ]; then PACKAGE="$2"; else PACKAGE="$1"; fi

    if [ -z "$(which $1)" ]; then
        error "Command [$1] not exist, please install package [$PACKAGE]."
    fi
}

function input_string() {
    # 从用户输入[$1: prompt string]中获取字符串
    # 确保字符串长度大于或等于[$2: min length]
    # 并小于[$3: max length]。

    PROMPT="Please input a string:"
    MIN_LENGTH=0
    MAX_LENGTH=80

    if [ -n "$1" ]; then PROMPT="$1"; fi
    if [ -n "$2" ]; then MIN_LENGTH="$2"; fi
    if [ -n "$3" ]; then MAX_LENGTH="$3"; fi

    read -p "$PROMPT" val

    until [ ${#val} -ge ${MIN_LENGTH} ] && [ ${#val} -lt ${MAX_LENGTH} ]; do
        read -p "$(echo -e "${RED}!!Invalid!!${NC} $PROMPT")" val
    done

    echo "$val"
}

function input_integer() {
    # 从用户输入[$1: prompt string]中获取整形数字
    # 确保字符串长度大于或等于[$2: min value]
    # 并小于[$3: max value]。

    PROMPT="Please input a integer:"
    MIN_INTEGER=0
    MAX_INTEGER=100000000

    if [ -n "$1" ]; then PROMPT="$1"; fi
    if [ -n "$2" ]; then MIN_INTEGER="$2"; fi
    if [ -n "$3" ]; then MAX_INTEGER="$3"; fi

    RE_INT=^[0-9]+$ # integer regex

    read -p "$PROMPT" val

    until [[ "$val" =~ ${RE_INT} ]] && \
    [ $val -ge ${MIN_INTEGER} ] && \
    [ $val -lt ${MAX_INTEGER} ]; do
        read -p "$(echo -e "${RED}!!Invalid!!${NC} $PROMPT")" val
    done

    echo "$val"
}

function iptables_chain_bypass_LAN() {
    # 增加要绕过的LAN地址规则到iptables [$1: table] [$2: chain] 

    iptables -t $1 -A $2 -d 0.0.0.0/8 -j RETURN
    iptables -t $1 -A $2 -d 10.0.0.0/8 -j RETURN
    iptables -t $1 -A $2 -d 127.0.0.0/8 -j RETURN
    iptables -t $1 -A $2 -d 169.254.0.0/16 -j RETURN
    iptables -t $1 -A $2 -d 172.16.0.0/12 -j RETURN
    iptables -t $1 -A $2 -d 192.168.0.0/16 -j RETURN
    iptables -t $1 -A $2 -d 224.0.0.0/4 -j RETURN
    iptables -t $1 -A $2 -d 240.0.0.0/4 -j RETURN
}

function clean_envirment() {

    killall dnsmasq
    killall hostapd

    if [ "$ENABLE_SS_RELAY" = "yes" ]; then
        kill -9 $(cat ss-redir.pid)
    fi

    # 删除NAT设置
    iptables -t nat -F

    # 删除SS转发设置
    if [ "$ENABLE_SS_RELAY" = "yes" ]; then
        iptables -t nat -X $IPTABLES_CHAIN_NAME1
        iptables -t mangle -F
        iptables -t mangle -X $IPTABLES_CHAIN_NAME
        ip rule del fwmark $FWMARK
        ip route flush table $IPROUTE2_TABLEID
    fi

    # 关闭 ip forward
    sysctl net.ipv4.ip_forward=0

    # 打开wlan
    nmcli r wifi on

    # 删除临时配置文件
    rm dnsmasq.conf hostapd.conf
    if [ "$ENABLE_SS_RELAY" = "yes" ]; then
        rm ss-redir.conf ss-redir.pid
    fi
}

# ===== End of [定义函数] =====

# ===== [准备工作] =====
# 确保开始执行前是root身份
(( EUID != 0 )) && exec sudo -- "$0" "$@"

# 清除命令
if [ "$1" = "clean" ]; then 
    clean_envirment
    exit 0
fi

if [ -n "$1" ]; then WAN_INTERFACE="$1"; fi
if [ -n "$2" ]; then LAN_INTERFACE="$2"; fi
if [ -n "$3" ]; then AP_NAME="$3"; fi
if [ -n "$4" ]; then PASSWORD="$4"; fi
if [ -n "$5" ]; then ENABLE_SS_RELAY="$5"; fi
if [ -n "$6" ]; then SS_SERVER_ADDR="$6"; fi
if [ -n "$7" ]; then SS_SERVER_PORT="$7"; fi
if [ -n "$8" ]; then SS_PASSWORD="$8"; fi
if [ -n "$9" ]; then SS_METHOD="$9"; fi
if [ -n "$10" ]; then SS_LOCAL_PORT="${10}"; fi

# 检查依赖
command_test "dnsmasq"
command_test "hostapd"
command_test "nmcli" "network-manager"
command_test "ip" "iproute2"
command_test "rfkill"
command_test "iptables"

# 进入当前目录，确保配置文件可读
cd "$SCRIPTPATH"
# ===== End of [准备工作] =====

# ===== [网卡配置] =====
# 获取网卡列表
IFS=$'\n' read -r -a interfaces -d '' <<< "$(ip link show | sed -rn 's/^[0-9]+: ((\w|\d)+):.*/\1/p')"

if [ -z "$WAN_INTERFACE" ] || [ -z "$LAN_INTERFACE" ]; then
    # 打印网卡；列表
    for i in ${!interfaces[@]}; do echo -e "$i: ${BLUE}${interfaces[$i]}${NC}"; done
    interface_count=${#interfaces[@]}
    # 设置无线网卡名
    if [ -z "$WAN_INTERFACE" ]; then
        idx="$(input_integer "Input index of your WAN interfaces name: " 0 $interface_count)"
        WAN_INTERFACE=${interfaces[$idx]}
    fi
    # 设置以太网卡名
    if [ -z "$LAN_INTERFACE" ]; then
        idx="$(input_integer "Input index of your LAN interfaces name: " 0 $interface_count)"
        LAN_INTERFACE=${interfaces[$idx]}
    fi
else
    if [ $(echo ${interfaces[@]} | grep "$WAN_INTERFACE" | wc -l) -ne 1 ]; then
        error "No interface named $WAN_INTERFACE."
    fi
    if [ $(echo ${interfaces[@]} | grep "$LAN_INTERFACE" | wc -l) -ne 1 ]; then
        error "No interface named $LAN_INTERFACE."
    fi
fi

if [ -z "$AP_NAME" ]; then
    AP_NAME=$(input_string "Input your AP name (default \"$(hostname) WiFi\"): " 0)
    if [ -z "$AP_NAME" ]; then AP_NAME="$(hostname) WiFi"; fi
fi

if [ -z "$PASSWORD" ] || [ ${#PASSWORD} -lt 8 ]; then
    PASSWORD=$(input_string "Input your AP password (8 chars at least): " 8)
fi

if [ -z $ENABLE_SS_RELAY ] || \
([ "$ENABLE_SS_RELAY" != "yes" ] && [ "$ENABLE_SS_RELAY" != "no" ]); then
    until [ "$ENABLE_SS_RELAY" = "yes" ] || [ "$ENABLE_SS_RELAY" = "no" ]; do
        read -p "Enable shadowsocks relay (yes/no): " ENABLE_SS_RELAY
    done
fi

if [ "$ENABLE_SS_RELAY" = "yes" ]; then
    command_test "ss-redir" "shadowsocks-libev"
fi

if [ "$ENABLE_SS_RELAY" = "yes" ]; then
    if [ -z "$SS_SERVER_ADDR" ]; then
        SS_SERVER_ADDR=$(input_string "Input your shadowsocks server address: " 1)
    fi
    if [ -z "$SS_SERVER_PORT" ]; then
        SS_SERVER_PORT=$(input_integer "Input your shadowsocks server port: " 1 65536)
    fi
    if [ -z "$SS_PASSWORD" ]; then
        SS_PASSWORD=$(input_string "Input your shadowsocks server password: " 1)
    fi
    if [ -z "$SS_METHOD" ]; then
        SS_METHOD=$(input_string "Input your shadowsocks encryption method(default aes-256-cfb): " 0)
        if [ -z "$SS_METHOD" ]; then SS_METHOD="aes-256-cfb"; fi
    fi
    if [ -z "$SS_LOCAL_PORT" ]; then
        SS_LOCAL_PORT=$(input_integer "Input your shadowsocks local port: " 0 65536)
    fi
fi
# ===== End of [网卡配置] =====

# ===== [核实输入] =====
if [ $NEED_CONFIRM -gt 0 ]; then
    clear

    echo -e "Your wifi AP configure: "
    echo -e "  - AP:"
    echo -e "    - SSID: ${GREEN}$AP_NAME${NC}"
    echo -e "    - PASSWROD: ${RED}$PASSWORD${NC}"
    echo -e "    - WAN: ${BLUE}$WAN_INTERFACE${NC}"
    echo -e "    - LAN: ${BLUE}$LAN_INTERFACE${NC}"
    echo -e "  - DHCP:"
    echo -e "    - ROUTER: $DHCP_ROUTER_IP"
    echo -e "    - RANGE: $DHCP_RANGE_MIN - $DHCP_RANGE_MAX"
    echo -e "    - DNS: $DNS_1, $DNS_2"

    if [ "$ENABLE_SS_RELAY" = "yes" ]; then
        echo -e "  - SS RELAY: ${GREEN}yes${NC}"
        echo -e "    - SERVER: ${GREEN}$SS_SERVER_ADDR${NC}, ${GREEN}$SS_SERVER_PORT${NC}"
        echo -e "    - PASSWORD: ${RED}$SS_PASSWORD${NC}"
        echo -e "    - METHOD: ${GREEN}$SS_METHOD${NC}"
        echo -e "    - LOCAL: 0.0.0.0, $SS_LOCAL_PORT"
        echo -e "    - TIMEOUT: $SS_TIMEOUT"
        echo -e "    - FAST OPEN: $SS_FAST_OPEN"
    else
        echo -e "  - SS RELAY: ${RED}no${NC}"
    fi

    echo

    read -n 1 -p "Please Confirm your configure, Enter to continue, Ctrl-C to exit."
    clear
fi
# ===== End of [核实输入] =====

echo -e "\n===== Creating WiFi AP... =====\n"

# ===== [清除环境] =====
# 关闭服务
service dnsmasq stop
service hostapd stop

# 杀死旧进程
killall dnsmasq
killall hostapd

# 重启无线网卡
nmcli r wifi off
rfkill unblock wlan
ifconfig $LAN_INTERFACE up

# 设置无线网卡IP
ifconfig $LAN_INTERFACE $DHCP_ROUTER_IP
# ===== End of [清除环境] =====

# ===== [配置NAT] =====
# 开启 ip forwoad
sysctl net.ipv4.ip_forward=1

# 删除NAT规则
iptables -t nat -F

# 添加一般NAT规则
iptables -P FORWARD ACCEPT
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
# ===== End of [配置NAT] =====

# ===== [配置shadowsocks转发] =====
if [ "$ENABLE_SS_RELAY" = "yes" ]; then
    # 添加TCP转发
    iptables -t nat -N $IPTABLES_CHAIN_NAME
    # Shadowsocks忽略自己的地址
    iptables -t nat -A $IPTABLES_CHAIN_NAME -d $SS_SERVER_ADDR -j RETURN
    # Shadowsocks忽略LAN和其他保留地址
    iptables_chain_bypass_LAN nat $IPTABLES_CHAIN_NAME
    # 其他地址都由shadowsocks转发
    iptables -t nat -A $IPTABLES_CHAIN_NAME -p tcp -j REDIRECT --to-ports $SS_LOCAL_PORT
    iptables -t nat -A PREROUTING -p tcp -j $IPTABLES_CHAIN_NAME

    # 开启UDP转发
    ip rule add fwmark $FWMARK table $IPROUTE2_TABLEID
    ip route add local 0.0.0.0/0 dev lo table $IPROUTE2_TABLEID
    iptables -t mangle -N $IPTABLES_CHAIN_NAME
    # Shadowsocks忽略LAN和其他保留地址
    iptables_chain_bypass_LAN mangle $IPTABLES_CHAIN_NAME
    # 其他地址都由shadowsocks转发
    iptables -t mangle -A $IPTABLES_CHAIN_NAME -p udp -j TPROXY --on-port $SS_LOCAL_PORT --tproxy-mark $FWMARK
    iptables -t mangle -A PREROUTING -j $IPTABLES_CHAIN_NAME
fi
# ===== End of [配置shadowsocks转发] =====

# ===== [生成配置文件] =====
echo "$DNSMASQ_CONF_TEMPLATE" | sed \
    -e "s/{LAN_INTERFACE}/$LAN_INTERFACE/" \
    -e "s/{DHCP_ROUTER_IP}/$DHCP_ROUTER_IP/" \
    -e "s/{DHCP_RANGE_MIN}/$DHCP_RANGE_MIN/" \
    -e "s/{DHCP_RANGE_MAX}/$DHCP_RANGE_MAX/" \
    -e "s/{DNS_1}/$DNS_1/" \
    -e "s/{DNS_2}/$DNS_2/" \
    > dnsmasq.conf

echo "$HOSTAPD_CONF_TEMPLATE" | sed \
    -e "s/{LAN_INTERFACE}/$LAN_INTERFACE/" \
    -e "s/{PASSWORD}/$PASSWORD/" \
    -e "s/{SSID}/$AP_NAME/" \
    > hostapd.conf

if [ "$ENABLE_SS_RELAY" = "yes" ]; then
    echo "$SS_CONF_TEMPLATE" | sed \
        -e "s/{SS_SERVER_ADDR}/$SS_SERVER_ADDR/" \
        -e "s/{SS_SERVER_PORT}/$SS_SERVER_PORT/" \
        -e "s/{SS_PASSWORD}/$SS_PASSWORD/" \
        -e "s/{SS_LOCAL_PORT}/$SS_LOCAL_PORT/" \
        -e "s/{SS_METHOD}/$SS_METHOD/" \
        -e "s/{SS_TIMEOUT}/$SS_TIMEOUT/" \
        -e "s/{SS_FAST_OPEN}/$SS_FAST_OPEN/" \
        > ss-redir.conf
fi
# ===== End of [生成配置文件] =====

# ===== [开启服务] =====
if [ "$ENABLE_SS_RELAY" = "yes" ]; then
    ss-redir -c ss-redir.conf -u -f ss-redir.pid &
fi

dnsmasq -C dnsmasq.conf
hostapd hostapd.conf

# !! 等待<Ctrl+C>结束 !!
# ===== End of [开启服务] =====

echo -e "\nWiFi Stop, Cleaning......\n"

# ===== [结束服务] =====
# Ctrl+C来结束hostapd

clean_envirment
# ===== End of [结束服务] =====

echo -e "\nDone!\n"
