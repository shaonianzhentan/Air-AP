# Air-AP - 一键创建透明代理的 WiFi 热点

## 用法

```bash
git clone https://github.com/qvjp/Air-AP.git
cd Air-AP
chmod +x proxy.sh
./proxy.sh
```

直接执行的话会进入向导模式。


如果你已经知道网卡名称，也可以在参数里提供：

```bash
./proxy.sh eth0 wlan0 NAME PASSWORD no
```

第五个参数 `no` 表示不开启透明代理模式，如果你想打开它，就用 `yes`。

参数按以下顺序提供：

`WAN LAN AP_NAME AP_PASSWORD yes/no [SS_ADDR SS_PORT SS_PASSWORD SS_METHOD SS_LOCAL_PORT]`

## 连接测试


只要连上 WiFi，然后无需任何配置，我们的流量就全都经过透明代理了。


我的测试环境：

- Shadowsocks 服务器: 1 CPU, 1G RAM，3M 带宽，腾讯月，HK
- 本地 Shadowsocks 客户端: i7-5500U，12G RAM，Ubuntu 18.04， **100M** 带宽，杭州
- WiFi 客户端: Oneplus 6，Android 9，OxygenOS

## 依赖

- hostapd
- dnsmasq
- nmcli (network-manager)
- rfkill (rfkill)
- ip (iproute2)
- iptables
- shadowsocks-libev （开启透明代理功能时才需要）
- run as root

## 自定义配置

打开 `proxy.sh`, 找到 `[用户配置]` 这一部分（从 13 行开始）。