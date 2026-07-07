"""
网络信息全面采集模块

采集三大类数据：
1. 系统网络配置 - 接口、IP、DNS、代理、防火墙、路由表
2. 当前连接状态 - WiFi、以太网、活跃连接、VPN
3. 已保存网络 - 已知 WiFi 列表、VPN 配置
"""

import json
import os
import plistlib
import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ═══════════════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class InterfaceInfo:
    """网络接口信息"""
    name: str
    display_name: str = ""
    hardware_type: str = ""
    mac_address: str = ""
    status: str = "unknown"          # active, inactive, unknown
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv4_netmask: str = ""
    ipv6_addresses: list[str] = field(default_factory=list)
    mtu: int = 0
    media: str = ""                  # 1000baseT, etc.
    is_primary: bool = False


@dataclass
class WiFiInfo:
    """WiFi 连接信息"""
    ssid: str = ""
    bssid: str = ""
    rssi: int = 0
    noise: int = 0
    channel: int = 0
    channel_band: str = ""           # 2.4GHz, 5GHz, 6GHz
    channel_width: str = ""          # 20MHz, 40MHz, 80MHz, 160MHz
    phy_mode: str = ""               # 802.11ac, 802.11ax, etc.
    transmit_rate: int = 0           # Mbps
    security: str = ""
    country_code: str = ""
    is_connected: bool = False


@dataclass
class DNSInfo:
    """DNS 配置"""
    servers: list[str] = field(default_factory=list)
    search_domains: list[str] = field(default_factory=list)
    dns_configs: list[dict] = field(default_factory=list)  # 按作用域分组的详细配置


@dataclass
class ProxyInfo:
    """代理配置"""
    http_enabled: bool = False
    http_server: str = ""
    http_port: int = 0
    https_enabled: bool = False
    https_server: str = ""
    https_port: int = 0
    socks_enabled: bool = False
    socks_server: str = ""
    socks_port: int = 0
    ftp_enabled: bool = False
    ftp_server: str = ""
    ftp_port: int = 0
    auto_discovery: bool = False
    auto_config_url: str = ""
    bypass_domains: list[str] = field(default_factory=list)
    exceptions_list: list[str] = field(default_factory=list)


@dataclass
class FirewallInfo:
    """防火墙配置"""
    enabled: bool = False
    block_all: bool = False
    allow_signed: bool = False
    stealth_mode: bool = False
    logging_enabled: bool = False
    apps_allowed: list[str] = field(default_factory=list)


@dataclass
class SavedWiFiNetwork:
    """已保存的 WiFi 网络"""
    ssid: str = ""
    security_type: str = ""
    last_connected: str = ""
    auto_join: bool = False
    hidden: bool = False
    bssid_list: list[str] = field(default_factory=list)


@dataclass
class RoutingInfo:
    """路由表信息"""
    default_gateway: str = ""
    default_interface: str = ""
    routes: list[dict] = field(default_factory=list)
    route_count: int = 0


@dataclass
class ActiveConnection:
    """活跃连接统计"""
    protocol: str = ""              # tcp, udp
    local_address: str = ""
    local_port: int = 0
    remote_address: str = ""
    remote_port: int = 0
    state: str = ""                 # ESTABLISHED, LISTEN, etc.
    pid: int = 0
    process_name: str = ""


@dataclass
class NetSummary:
    """网络状态汇总"""
    total_active: int = 0
    tcp_active: int = 0
    udp_active: int = 0
    listening: int = 0
    established: int = 0
    top_processes: list[dict] = field(default_factory=list)


@dataclass
class NetworkReport:
    """完整网络检测报告"""
    timestamp: str = ""
    hostname: str = ""
    computer_name: str = ""
    internet_connected: bool = False
    internet_latency: float = 0.0     # ms
    public_ip: str = ""
    primary_interface: str = ""
    interfaces: list[InterfaceInfo] = field(default_factory=list)
    wifi: WiFiInfo = field(default_factory=WiFiInfo)
    dns: DNSInfo = field(default_factory=DNSInfo)
    proxy: ProxyInfo = field(default_factory=ProxyInfo)
    firewall: FirewallInfo = field(default_factory=FirewallInfo)
    routing: RoutingInfo = field(default_factory=RoutingInfo)
    saved_wifi_networks: list[SavedWiFiNetwork] = field(default_factory=list)
    vpn_configs: list[dict] = field(default_factory=list)
    network_locations: list[str] = field(default_factory=list)
    net_summary: NetSummary = field(default_factory=NetSummary)
    active_connections: list[ActiveConnection] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
# 采集函数
# ═══════════════════════════════════════════════════════════════════════

def run_cmd(cmd: list[str], timeout: int = 10, check: bool = False) -> tuple[int, str, str]:
    """运行命令并返回 (返回码, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时"
    except FileNotFoundError:
        return -1, "", f"命令不存在: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def _get_hostname() -> tuple[str, str]:
    """获取主机名和计算机名"""
    hostname = socket.gethostname()
    # macOS ComputerName (系统偏好设置 -> 共享)
    _, computer_name, _ = run_cmd(["scutil", "--get", "ComputerName"])
    local_hostname = ""
    _, lh, _ = run_cmd(["scutil", "--get", "LocalHostName"])
    if lh:
        local_hostname = lh
    display = computer_name or hostname
    return hostname, display


def _get_interfaces() -> list[InterfaceInfo]:
    """获取所有网络接口"""
    interfaces = []

    # 获取所有接口列表
    _, output, _ = run_cmd(["ifconfig", "-l"])
    if not output:
        return interfaces

    iface_names = output.split()

    # 获取主接口
    primary_iface = _get_primary_interface()

    # 获取接口展示名称映射
    display_names = {}
    for name in iface_names:
        _, dn, _ = run_cmd(["networksetup", "-getfriendlyhardwarename", name])
        if dn:
            # 格式: "Hardware Port: Wi-Fi\nDevice: en0"
            for line in dn.split("\n"):
                if "Hardware Port:" in line:
                    display_names[name] = line.split(":", 1)[1].strip()

    # 批量获取所有接口的详细信息
    _, all_info, _ = run_cmd(["ifconfig"])
    iface_blocks = {}
    current_iface = None
    for line in all_info.split("\n"):
        if line and not line.startswith("\t") and ":" in line:
            current_iface = line.split(":")[0]
            iface_blocks[current_iface] = [line]
        elif current_iface:
            iface_blocks.setdefault(current_iface, []).append(line)

    for name in iface_names:
        info = InterfaceInfo(name=name)
        info.display_name = display_names.get(name, name)
        info.is_primary = (name == primary_iface)

        block = iface_blocks.get(name, [])

        for line in block:
            line = line.strip()
            if name in line and ": " in line:
                # 第一行: flags=... mtu ...
                flags_part = line.split(":", 1)[1].strip() if ":" in line else ""
                if "UP" in flags_part and "RUNNING" in flags_part:
                    info.status = "active"
                elif "UP" in flags_part:
                    info.status = "active"
                else:
                    info.status = "inactive"

                mtu_match = re.search(r"mtu\s+(\d+)", flags_part)
                if mtu_match:
                    info.mtu = int(mtu_match.group(1))

            elif "ether " in line:
                mac = line.split("ether ")[1].split()[0]
                info.mac_address = mac

            elif "inet " in line and "inet6" not in line:
                parts = line.split("inet ")[1].split()
                info.ipv4_addresses.append(parts[0])
                if "netmask" in line:
                    nm = line.split("netmask ")[1].split()[0]
                    # 十六进制转点分十进制
                    info.ipv4_netmask = _hex_to_ip(nm)

            elif "inet6 " in line:
                addr = line.split("inet6 ")[1].split()[0]
                # 过滤掉链路本地地址的 zone id
                if "%" in addr:
                    addr = addr.split("%")[0]
                info.ipv6_addresses.append(addr)

            elif "media:" in line:
                info.media = line.split("media: ")[1].split()[0] if "media: " in line else ""
                # 分离状态部分
                if " " in info.media:
                    info.media = info.media.split(" ")[0]

        # 硬件类型分类
        if name.startswith("en"):
            if name == "en0":
                info.hardware_type = "WiFi / 以太网"
            else:
                info.hardware_type = "以太网"
        elif name.startswith("wl"):
            info.hardware_type = "WiFi"
        elif name.startswith("lo"):
            info.hardware_type = "回环 (Loopback)"
        elif name.startswith("utun") or name.startswith("tun"):
            info.hardware_type = "VPN / 隧道"
        elif name.startswith("bridge"):
            info.hardware_type = "桥接"
        elif name.startswith("p2p"):
            info.hardware_type = "点对点"
        elif name.startswith("anpi"):
            info.hardware_type = "Apple 网络私有接口"
        elif name.startswith("awdl"):
            info.hardware_type = "AirDrop / AWDL"
        elif name.startswith("llw"):
            info.hardware_type = "低延迟无线"
        elif name.startswith("gif") or name.startswith("stf"):
            info.hardware_type = "隧道"
        elif name.startswith("ap"):
            info.hardware_type = "接入点"
        elif name.startswith("vlan"):
            info.hardware_type = "VLAN"
        else:
            info.hardware_type = "其他"

        interfaces.append(info)

    return interfaces


def _hex_to_ip(hex_str: str) -> str:
    """十六进制掩码转为点分十进制"""
    try:
        val = int(hex_str, 16)
        return socket.inet_ntoa(struct.pack("!I", val))
    except (ValueError, struct.error, OSError):
        return hex_str


def _is_valid_ip(ip: str) -> bool:
    """检查是否为有效的 IP 地址"""
    # IPv4: x.x.x.x
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            pass
    # IPv6: 包含冒号且不为纯前缀（如 fe80）
    if ":" in ip:
        # 过滤纯前缀和不完整地址
        if ip in ("fe80", "fe80:"):
            return False
        # 有效的 IPv6 地址至少要有 :: 或足够的段
        if "::" in ip or ip.count(":") >= 2:
            return True
        return False
    return False


def _get_primary_interface() -> str:
    """获取主网络接口"""
    # 通过路由表找默认路由使用的接口
    _, out, _ = run_cmd(["route", "-n", "get", "default"])
    for line in out.split("\n"):
        if "interface:" in line:
            return line.split("interface:")[1].strip()
    return "en0"


def _get_wifi_info() -> WiFiInfo:
    """获取 WiFi 连接信息"""
    wifi = WiFiInfo()

    # 方法1: CoreWLAN 通过 system_profiler
    _, out, _ = run_cmd(
        ["system_profiler", "SPAirPortDataType", "-detailLevel", "basic"],
        timeout=15,
    )

    current_block = False
    for line in out.split("\n"):
        line = line.strip()

        if "Current Network Information:" in line:
            current_block = True
            continue
        if current_block:
            if line.startswith("Other Local Networks:") or line.startswith("Software Versions:"):
                break
            if "PHY Mode:" in line:
                wifi.phy_mode = line.split("PHY Mode:")[1].strip()
                wifi.is_connected = bool(wifi.phy_mode)
            elif "BSSID:" in line:
                wifi.bssid = line.split("BSSID:")[1].strip()
            elif "Channel:" in line:
                ch = line.split("Channel:")[1].strip()
                try:
                    wifi.channel = int(ch.split(",")[0].strip())
                except ValueError:
                    pass
                # 解析频段
                if "5 GHz" in ch:
                    wifi.channel_band = "5 GHz"
                elif "2.4 GHz" in ch:
                    wifi.channel_band = "2.4 GHz"
                elif "6 GHz" in ch:
                    wifi.channel_band = "6 GHz"
            elif "Security:" in line:
                wifi.security = line.split("Security:")[1].strip()
            elif "RSSI:" in line and "Noise:" in line:
                # 格式: "RSSI: -55 dBm / Noise: -90 dBm"
                # 可能有多个 RSSI 条目，拆分处理
                pass
            elif "SSID:" in line and "SSID: " in line:
                wifi.ssid = line.split("SSID:")[1].strip()
            elif "Country Code:" in line:
                wifi.country_code = line.split("Country Code:")[1].strip()

    # 单独提取 RSSI 和 Noise（可能在多个地方出现）
    for line in out.split("\n"):
        line = line.strip()
        if "RSSI:" in line and "dBm" in line:
            try:
                rssi_match = re.search(r"RSSI:\s*(-?\d+)\s*dBm", line)
                if rssi_match:
                    wifi.rssi = int(rssi_match.group(1))
            except ValueError:
                pass
        if "Noise:" in line and "dBm" in line:
            try:
                noise_match = re.search(r"Noise:\s*(-?\d+)\s*dBm", line)
                if noise_match:
                    wifi.noise = int(noise_match.group(1))
            except ValueError:
                pass
        if "Transmit Rate:" in line:
            try:
                wifi.transmit_rate = int(line.split("Transmit Rate:")[1].strip().split()[0])
            except (ValueError, IndexError):
                pass

    # 如果 system_profiler 没有数据，尝试 networksetup
    if not wifi.is_connected:
        _, ssid_out, _ = run_cmd(["networksetup", "-getairportnetwork", "en0"])
        if "Current Wi-Fi Network:" in ssid_out:
            wifi.ssid = ssid_out.split("Current Wi-Fi Network:")[1].strip()
            wifi.is_connected = True

    # 获取信道宽度
    _, ch_out, _ = run_cmd(
        ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
        timeout=10,
    )
    for line in ch_out.split("\n"):
        line = line.strip()
        if "channel:" in line.lower():
            try:
                ch_val = line.split(":")[1].strip()
                # 格式可能是 "44 (80MHz)"
                if "(" in ch_val:
                    wifi.channel = int(ch_val.split("(")[0].strip())
                    wifi.channel_width = ch_val.split("(")[1].split(")")[0].strip()
                else:
                    wifi.channel = int(ch_val.split(",")[0].strip())
            except (ValueError, IndexError):
                pass

    return wifi


def _get_dns_info() -> DNSInfo:
    """获取 DNS 配置"""
    dns = DNSInfo()

    # 方法1: scutil --dns
    _, out, _ = run_cmd(["scutil", "--dns"], timeout=10)

    current_resolver = None
    for line in out.split("\n"):
        line = line.strip()

        if line.startswith("resolver #"):
            if current_resolver:
                dns.dns_configs.append(current_resolver)
            current_resolver = {}
            continue
        if current_resolver is not None:
            if "nameserver[" in line:
                ip = line.split(":")[1].strip()
                # 过滤无效 IP（如纯 IPv6 前缀 fe80）
                if _is_valid_ip(ip) and ip not in dns.servers:
                    dns.servers.append(ip)
                current_resolver.setdefault("nameservers", []).append(ip)
            elif "domain   :" in line:
                current_resolver["domain"] = line.split(":")[1].strip()
            elif "search domain[" in line:
                sd = line.split(":")[1].strip()
                if sd not in dns.search_domains:
                    dns.search_domains.append(sd)
            elif "flags    :" in line:
                current_resolver["flags"] = line.split(":")[1].strip().split()

    if current_resolver:
        dns.dns_configs.append(current_resolver)

    # 方法2: 从 /etc/resolv.conf 获取
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    ns = line.split()[1]
                    if ns not in dns.servers:
                        dns.servers.append(ns)
                elif line.startswith("search"):
                    for sd in line.split()[1:]:
                        if sd not in dns.search_domains:
                            dns.search_domains.append(sd)
    except Exception:
        pass

    return dns


def _get_proxy_info() -> ProxyInfo:
    """获取代理配置"""
    proxy = ProxyInfo()

    _, out, _ = run_cmd(["scutil", "--proxy"], timeout=10)

    for line in out.split("\n"):
        line = line.strip()
        try:
            if "HTTPEnable : 1" in line:
                proxy.http_enabled = True
            elif "HTTPProxy :" in line:
                proxy.http_server = line.split(":", 1)[1].strip()
            elif "HTTPPort :" in line:
                proxy.http_port = int(line.split(":", 1)[1].strip())
            elif "HTTPSEnable : 1" in line:
                proxy.https_enabled = True
            elif "HTTPSProxy :" in line:
                proxy.https_server = line.split(":", 1)[1].strip()
            elif "HTTPSPort :" in line:
                proxy.https_port = int(line.split(":", 1)[1].strip())
            elif "SOCKSEnable : 1" in line:
                proxy.socks_enabled = True
            elif "SOCKSProxy :" in line:
                proxy.socks_server = line.split(":", 1)[1].strip()
            elif "SOCKSPort :" in line:
                proxy.socks_port = int(line.split(":", 1)[1].strip())
            elif "FTPEnable : 1" in line:
                proxy.ftp_enabled = True
            elif "FTPProxy :" in line:
                proxy.ftp_server = line.split(":", 1)[1].strip()
            elif "FTPPort :" in line:
                proxy.ftp_port = int(line.split(":", 1)[1].strip())
            elif "ProxyAutoDiscoveryEnable : 1" in line:
                proxy.auto_discovery = True
            elif "ProxyAutoConfigEnable : 1" in line:
                pass
            elif "ProxyAutoConfigURLString :" in line:
                proxy.auto_config_url = line.split(":", 1)[1].strip()
            elif "ExceptionsList :" in line:
                pass
            elif line.strip() and line.strip()[0].isdigit() and " : " in line:
                parts = line.strip().split(":", 1)
                if len(parts) >= 2:
                    domain = parts[1].strip()
                    if domain:
                        proxy.exceptions_list.append(domain)
                        proxy.bypass_domains.append(domain)
        except (IndexError, ValueError):
            pass

    # 也从 networksetup 获取当前活跃服务的代理设置
    services = _get_network_services()
    for svc in services[:3]:  # 只查前几个
        _, po, _ = run_cmd(["networksetup", "-getwebproxy", svc])
        if "Enabled: Yes" in po and not proxy.http_enabled:
            proxy.http_enabled = True
            for pl in po.split("\n"):
                if "Server:" in pl:
                    proxy.http_server = pl.split("Server:")[1].strip()
                elif "Port:" in pl:
                    try:
                        proxy.http_port = int(pl.split("Port:")[1].strip())
                    except ValueError:
                        pass

    return proxy


def _get_firewall_info() -> FirewallInfo:
    """获取防火墙配置"""
    fw = FirewallInfo()

    _, out, _ = run_cmd(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        timeout=10,
    )
    if "Firewall is enabled" in out:
        fw.enabled = True

    if fw.enabled:
        _, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getblockall"],
            timeout=10,
        )
        if "Block all" in out:
            fw.block_all = "enabled" in out.lower()

        _, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getallowsigned"],
            timeout=10,
        )
        if "built-in" in out.lower() or "signed" in out.lower():
            fw.allow_signed = "enabled" in out.lower() or "allow" in out.lower()

        _, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"],
            timeout=10,
        )
        if "Stealth" in out:
            fw.stealth_mode = "enabled" in out.lower()

        _, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getloggingmode"],
            timeout=10,
        )
        if "Log" in out:
            fw.logging_enabled = "on" in out.lower() or "yes" in out.lower()

        # 获取允许的应用列表
        _, out, _ = run_cmd(
            ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--listapps"],
            timeout=10,
        )
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("/") and "Allow" in line:
                app = line.split("(")[0].strip()
                fw.apps_allowed.append(app)

    return fw


def _get_routing_info() -> RoutingInfo:
    """获取路由表信息"""
    routing = RoutingInfo()

    # 默认路由 - route 命令获取
    _, out, _ = run_cmd(["route", "-n", "get", "default"])
    for line in out.split("\n"):
        if "gateway:" in line and "link" not in line.lower():
            gw = line.split("gateway:")[1].strip()
            if gw and "." in gw:
                routing.default_gateway = gw
        elif "interface:" in line:
            routing.default_interface = line.split("interface:")[1].strip()

    # 如果 route 没拿到网关（VPN/tunnel 场景），从 netstat 获取
    if not routing.default_gateway:
        _, out, _ = run_cmd(["netstat", "-rn", "-f", "inet"])
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and (parts[0] == "0.0.0.0" or parts[0] == "default"):
                gw = parts[1]
                if "." in gw and gw not in ("link", "link#"):
                    routing.default_gateway = gw
                    if not routing.default_interface and len(parts) >= 4:
                        routing.default_interface = parts[3]
                    break

    # 完整路由表
    _, out, _ = run_cmd(["netstat", "-rn", "-f", "inet"])
    route_count = 0
    in_table = False
    for line in out.split("\n"):
        line = line.strip()
        if "Destination" in line and "Gateway" in line:
            in_table = True
            continue
        if in_table and line and not line.startswith("Internet"):
            parts = line.split()
            if len(parts) >= 4:
                route = {
                    "destination": parts[0],
                    "gateway": parts[1],
                    "flags": parts[2],
                    "interface": parts[3] if len(parts) > 3 else "",
                }
                routing.routes.append(route)
                route_count += 1
                if route_count >= 50:  # 限制数量
                    break

    routing.route_count = route_count
    return routing


def _get_saved_wifi_networks() -> list[SavedWiFiNetwork]:
    """获取已保存的 WiFi 网络列表"""
    networks = []

    # macOS 将已知 WiFi 存在
    # /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist
    plist_paths = [
        "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        os.path.expanduser("~/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"),
    ]

    for plist_path in plist_paths:
        if not os.path.exists(plist_path):
            continue
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.load(f)

            known = data.get("KnownNetworks", {})
            for ssid, net_info in known.items():
                nw = SavedWiFiNetwork()
                nw.ssid = ssid
                if isinstance(net_info, dict):
                    nw.auto_join = net_info.get("AutoJoin", False)
                    nw.hidden = net_info.get("Hidden", False)

                    # 安全类型
                    sec_type = net_info.get("SecurityType", "")
                    nw.security_type = sec_type

                    # 最后连接时间
                    last_connected = net_info.get("LastConnected")
                    if last_connected:
                        nw.last_connected = str(last_connected)

                    # 已知的 BSSID
                    bssids = net_info.get("RoamingProfileList", [])
                    if bssids:
                        nw.bssid_list = bssids

                networks.append(nw)
            break  # 找到一个就够了
        except Exception:
            continue

    # 备选: networksetup -listpreferredwirelessnetworks
    if not networks:
        _, out, _ = run_cmd(["networksetup", "-listpreferredwirelessnetworks", "en0"])
        for line in out.split("\n")[1:]:  # 跳过表头
            line = line.strip()
            if line and "\t" in line:
                nw = SavedWiFiNetwork()
                nw.ssid = line.strip()
                networks.append(nw)

    return networks


def _get_vpn_configs() -> list[dict]:
    """获取 VPN 配置"""
    vpns = []

    # macOS VPN 配置在 SystemConfiguration preferences 中
    _, out, _ = run_cmd(["scutil", "--nc", "list"], timeout=10)
    for line in out.split("\n"):
        line = line.strip()
        if not line or line.startswith("Available") or line.startswith("(Disconnected)"):
            # 跳过标题行
            if line.startswith("*"):
                # 这是一个连接
                parts = line[2:].strip().split("\t")
                vpn = {
                    "status": "connected",
                    "name": parts[0] if parts else "",
                }
                if len(parts) > 1:
                    vpn["type"] = "VPN"
                vpns.append(vpn)
            continue
        if line and "*" not in line:
            # 断开的连接
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                vpn = {
                    "status": "disconnected",
                    "name": parts[1] if len(parts) > 1 else parts[0],
                }
                if "VPN" in line or "L2TP" in line or "IPSec" in line or "IKEv2" in line:
                    vpn["type"] = "VPN"
                vpns.append(vpn)

    # 也检查 /etc/ppp/ 下的配置
    ppp_dir = Path("/etc/ppp")
    if ppp_dir.exists():
        for f in ppp_dir.glob("*.plist"):
            try:
                vpns.append({"name": f.stem, "type": "PPP/L2TP", "status": "configured", "source": str(f)})
            except Exception:
                pass

    return vpns


def _get_network_locations() -> list[str]:
    """获取网络位置列表"""
    _, out, _ = run_cmd(["networksetup", "-listlocations"], timeout=10)
    return [l.strip() for l in out.split("\n") if l.strip()]


def _get_network_services() -> list[str]:
    """获取网络服务列表"""
    _, out, _ = run_cmd(["networksetup", "-listallnetworkservices"], timeout=10)
    services = []
    for line in out.split("\n"):
        line = line.strip()
        if line and not line.startswith("An asterisk") and not line.startswith("*"):
            services.append(line)
    return services


def _get_net_summary() -> tuple[NetSummary, list[ActiveConnection]]:
    """获取网络连接汇总"""
    summary = NetSummary()
    connections: list[ActiveConnection] = []

    # netstat 获取连接
    _, out, _ = run_cmd(["netstat", "-an", "-p", "tcp"], timeout=10)

    for line in out.split("\n"):
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        conn = ActiveConnection()
        conn.protocol = parts[0].lower()
        if conn.protocol not in ("tcp", "tcp4", "tcp6"):
            continue

        conn.protocol = "tcp"

        # 解析本地地址
        local = parts[3]
        if "." in local:
            # IPv4: 192.168.1.1.54321
            last_dot = local.rfind(".")
            conn.local_address = local[:last_dot]
            try:
                conn.local_port = int(local[last_dot + 1:])
            except ValueError:
                pass

        # 解析远程地址
        remote = parts[4]
        if "." in remote:
            last_dot = remote.rfind(".")
            conn.remote_address = remote[:last_dot]
            try:
                conn.remote_port = int(remote[last_dot + 1:])
            except ValueError:
                pass

        # 状态
        if len(parts) >= 6:
            conn.state = parts[5]

        if conn.state == "LISTEN":
            summary.listening += 1
        elif conn.state == "ESTABLISHED":
            summary.established += 1

        summary.tcp_active += 1
        connections.append(conn)

    # UDP 计数
    _, out, _ = run_cmd(["netstat", "-an", "-p", "udp"], timeout=10)
    for line in out.split("\n"):
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] in ("udp", "udp4", "udp6"):
            summary.udp_active += 1

    summary.total_active = summary.tcp_active + summary.udp_active

    # 限制返回的连接数（避免过大）
    if len(connections) > 100:
        connections = connections[:100]

    return summary, connections


def _check_internet() -> tuple[bool, float, str]:
    """检测互联网连通性和公网 IP"""
    connected = False
    latency = 0.0
    public_ip = ""

    # 延迟检测：ping 多个目标取最小延迟
    targets = ["8.8.8.8", "114.114.114.114", "1.1.1.1"]
    best_latency = float("inf")

    for target in targets:
        code, out, _ = run_cmd([
            "ping", "-c", "2", "-W", "3", "-q", target
        ], timeout=8)
        if code == 0:
            connected = True
            # 解析平均延迟
            for line in out.split("\n"):
                if "avg" in line and " = " in line:
                    # 格式: round-trip min/avg/max/stddev = 10.123/15.456/20.789/3.123 ms
                    parts = line.split(" = ")[1].split("/")
                    if len(parts) >= 2:
                        try:
                            avg = float(parts[1])
                            if avg < best_latency:
                                best_latency = avg
                        except ValueError:
                            pass

    if connected:
        latency = round(best_latency, 1) if best_latency < float("inf") else -1

        # 获取公网 IP
        import urllib.request
        import urllib.error
        try:
            req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "netest/0.1"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                public_ip = data.get("ip", "")
        except Exception:
            # 备选
            try:
                req = urllib.request.Request("https://httpbin.org/ip", headers={"User-Agent": "netest/0.1"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    public_ip = data.get("origin", "")
            except Exception:
                pass

    return connected, latency, public_ip


# ═══════════════════════════════════════════════════════════════════════
# 主采集函数
# ═══════════════════════════════════════════════════════════════════════

def collect_all() -> NetworkReport:
    """并行采集所有网络信息，返回完整报告"""
    report = NetworkReport()
    report.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    hostname, computer_name = _get_hostname()
    report.hostname = hostname
    report.computer_name = computer_name

    # 定义可并行的采集任务
    tasks = {
        "interfaces": _get_interfaces,
        "wifi": _get_wifi_info,
        "dns": _get_dns_info,
        "proxy": _get_proxy_info,
        "firewall": _get_firewall_info,
        "routing": _get_routing_info,
        "saved_wifi": _get_saved_wifi_networks,
        "vpn": _get_vpn_configs,
        "locations": _get_network_locations,
        "net_summary": _get_net_summary,
        "internet": _check_internet,
    }

    results = {}
    with ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in as_completed(future_map):
            key = future_map[future]
            try:
                results[key] = future.result()
            except Exception as e:
                report.errors.append(f"{key}: {e}")

    # 填充报告
    report.interfaces = results.get("interfaces", [])

    wifi = results.get("wifi")
    if wifi and isinstance(wifi, WiFiInfo):
        report.wifi = wifi

    dns_data = results.get("dns")
    if dns_data and isinstance(dns_data, DNSInfo):
        report.dns = dns_data

    proxy = results.get("proxy")
    if proxy and isinstance(proxy, ProxyInfo):
        report.proxy = proxy

    fw = results.get("firewall")
    if fw and isinstance(fw, FirewallInfo):
        report.firewall = fw

    routing = results.get("routing")
    if routing and isinstance(routing, RoutingInfo):
        report.routing = routing
        report.primary_interface = routing.default_interface or "en0"

    report.saved_wifi_networks = results.get("saved_wifi", [])
    report.vpn_configs = results.get("vpn", [])
    report.network_locations = results.get("locations", [])

    net_data = results.get("net_summary")
    if net_data:
        report.net_summary, report.active_connections = net_data

    internet = results.get("internet")
    if internet:
        report.internet_connected, report.internet_latency, report.public_ip = internet

    return report


def report_to_dict(report: NetworkReport) -> dict:
    """将报告转为可 JSON 序列化的字典"""
    result = {
        "timestamp": report.timestamp,
        "hostname": report.hostname,
        "computer_name": report.computer_name,
        "internet_connected": report.internet_connected,
        "internet_latency": report.internet_latency,
        "public_ip": report.public_ip,
        "primary_interface": report.primary_interface,
        "interfaces": [asdict(i) for i in report.interfaces],
        "wifi": asdict(report.wifi),
        "dns": asdict(report.dns),
        "proxy": asdict(report.proxy),
        "firewall": asdict(report.firewall),
        "routing": asdict(report.routing),
        "saved_wifi_networks": [asdict(n) for n in report.saved_wifi_networks],
        "vpn_configs": report.vpn_configs,
        "network_locations": report.network_locations,
        "net_summary": asdict(report.net_summary),
        "active_connections": [asdict(c) for c in report.active_connections],
        "errors": report.errors,
    }
    return result


def report_to_json(report: NetworkReport) -> str:
    """将报告转为 JSON 字符串"""
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=2, default=str)


if __name__ == "__main__":
    import time as _time
    start = _time.time()
    report = collect_all()
    elapsed = _time.time() - start

    print(f"\n采集完成，耗时 {elapsed:.2f}s")
    print(f"主机名: {report.hostname} ({report.computer_name})")
    print(f"互联网: {'已连接' if report.internet_connected else '未连接'}")
    print(f"公网 IP: {report.public_ip}")
    print(f"延迟: {report.internet_latency}ms")
    print(f"接口数: {len(report.interfaces)}")
    print(f"WiFi: {report.wifi.ssid or 'N/A'}  RSSI: {report.wifi.rssi or 'N/A'}")
    print(f"DNS 服务器数: {len(report.dns.servers)}")
    print(f"已知 WiFi: {len(report.saved_wifi_networks)}")
    print(f"VPN 配置: {len(report.vpn_configs)}")
    print(f"活跃连接: {report.net_summary.total_active}")
    if report.errors:
        print(f"错误: {report.errors}")
