"""WiFi 信息采集模块"""

import subprocess
import re

from netest.output import console, print_warning, print_error, print_success, print_header
from netest.utils import rssi_quality

COREWLAN_AVAILABLE = False
CoreWLAN = None

try:
    import CoreWLAN  # type: ignore
    COREWLAN_AVAILABLE = True
except ImportError:
    pass


def run_wifi_diagnostic(interface="en0", detail=False):
    """执行 WiFi 质量检测"""
    print_header("WiFi 质量检测")
    wifi_info = None

    if COREWLAN_AVAILABLE:
        wifi_info = _get_wifi_info_corewlan(interface)

    if not wifi_info:
        if COREWLAN_AVAILABLE:
            print_warning("CoreWLAN 获取失败，使用 system_profiler 备用方案")
        else:
            print_warning("未安装 pyobjc-framework-CoreWLAN，使用 system_profiler 备用方案")
            console.print("[dim]安装方法: pip install pyobjc-framework-CoreWLAN[/dim]")
        wifi_info = _get_wifi_info_system_profiler()

    if not wifi_info:
        print_error("无法获取 WiFi 信息，请确认 WiFi 已连接")
        return

    _display_wifi_info(wifi_info, detail)


def _get_wifi_info_corewlan(interface):
    """使用 CoreWLAN 获取 WiFi 信息"""
    try:
        client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
        iface = client.interface()

        ssid = iface.ssid()
        bssid = iface.bssid()
        rssi = iface.rssiValue()
        noise = iface.noiseMeasurement()

        channel_obj = iface.wlanChannel()
        channel_num = None
        channel_width = None
        channel_band = None
        if channel_obj:
            channel_num = channel_obj.channelNumber()
            width_val = channel_obj.channelWidth()
            width_map = {0: "20 MHz", 1: "40 MHz", 2: "80 MHz", 3: "160 MHz"}
            channel_width = width_map.get(width_val, str(width_val))
            if channel_num:
                if channel_num <= 13:
                    channel_band = "2.4GHz"
                elif channel_num <= 196:
                    channel_band = "5GHz"
                else:
                    channel_band = "6GHz"

        transmit_rate = iface.transmitRate()

        phy_mode = None
        if hasattr(iface, "activePHYMode"):
            phy_val = iface.activePHYMode()
            phy_map = {
                1: "802.11a", 2: "802.11b", 4: "802.11g",
                8: "802.11n (Wi-Fi 4)", 16: "802.11ac (Wi-Fi 5)",
                32: "802.11ax (Wi-Fi 6)", 64: "802.11be (Wi-Fi 7)"
            }
            phy_mode = phy_map.get(phy_val, f"未知 ({phy_val})")

        security = None
        if hasattr(iface, "securityMode"):
            sec_val = iface.securityMode()
            if sec_val:
                security = str(sec_val)

        snr = (rssi - noise) if (rssi is not None and noise is not None) else None

        return {
            "ssid": ssid, "bssid": bssid,
            "rssi": rssi, "noise": noise, "snr": snr,
            "channel": channel_num, "channel_band": channel_band,
            "channel_width": channel_width, "transmit_rate": transmit_rate,
            "phy_mode": phy_mode, "security": security,
            "interface": interface, "source": "CoreWLAN",
        }
    except Exception as e:
        print_warning(f"CoreWLAN 获取失败: {e}")
        return None


def _get_wifi_info_system_profiler():
    """使用 system_profiler 获取 WiFi 信息（备用方案）"""
    try:
        result = subprocess.run(
            ["system_profiler", "SPAirPortDataType"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return _parse_system_profiler_text(result.stdout)
    except Exception as e:
        print_warning(f"system_profiler 执行失败: {e}")
    return None


def _parse_system_profiler_text(output):
    """解析 system_profiler 文本输出，只读取 Current Network Information 部分"""
    info = {}
    lines = output.split("\n")

    # 找到 Current Network Information 部分的起始行
    start = -1
    for i, line in enumerate(lines):
        if "Current Network Information" in line:
            start = i
            break

    if start == -1:
        return None

    # 从起始行之后开始解析，直到遇到顶格或同缩进的新节
    for i in range(start + 1, len(lines)):
        line = lines[i]
        stripped = line.strip()

        # 跳过空行
        if not stripped:
            continue

        # 如果遇到 Other Local 或 Interfaces 等节，停止解析
        if stripped.startswith("Other Local") or stripped.startswith("Interfaces:"):
            break

        # 跳过 <redacted> 行
        if stripped.startswith("<"):
            continue

        # 解析键值对
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()

            if key == "PHY Mode":
                info["phy_mode"] = val
            elif key == "Channel":
                _parse_channel_string(val, info)
            elif "Signal / Noise" in key:
                m = re.search(r"(-?\d+)\s*dBm.*?(-?\d+)\s*dBm", stripped)
                if m:
                    info["rssi"] = int(m.group(1))
                    info["noise"] = int(m.group(2))
            elif key == "Transmit Rate":
                m = re.search(r"(\d+)", val)
                if m:
                    info["transmit_rate"] = int(m.group(1))
            elif key == "MCS Index":
                try:
                    info["mcs_index"] = int(val)
                except ValueError:
                    pass
            elif key == "Security":
                info["security"] = val
            elif key == "Country Code":
                info["country_code"] = val

    # 计算 SNR
    if "rssi" in info and "noise" in info:
        info["snr"] = info["rssi"] - info["noise"]

    if not info:
        return None

    info["source"] = "system_profiler"
    info["interface"] = "en0"
    info["ssid_note"] = "system_profiler 会遮挡 SSID/BSSID，安装 CoreWLAN 可获取完整信息"
    return info


def _parse_channel_string(val, info):
    """解析 '48 (5GHz, 160MHz)' 格式的信道字符串"""
    m = re.search(r"(\d+)", val)
    if m:
        ch = int(m.group(1))
        info["channel"] = ch
        if ch <= 13:
            info["channel_band"] = "2.4GHz"
        elif ch <= 196:
            info["channel_band"] = "5GHz"
        else:
            info["channel_band"] = "6GHz"

    w = re.search(r"(\d+)\s*MHz", val)
    if w:
        info["channel_width"] = f"{w.group(1)} MHz"


def _display_wifi_info(info, detail=False):
    """显示 WiFi 信息（Rich 表格）"""
    from netest.output import wifi_table
    table = wifi_table(info)
    console.print(table)

    if info.get("ssid_note"):
        console.print(f"[dim]{info['ssid_note']}[/dim]")

    rssi = info.get("rssi")
    if rssi is not None:
        quality, color = rssi_quality(rssi)
        tips = {
            "优秀": "信号非常好，网络连接稳定。",
            "良好": "信号良好，适合日常使用。",
            "一般": "信号一般，靠近路由器可改善。",
            "较差": "信号较差，建议靠近路由器。",
            "很差": "信号很差，网络连接可能不稳定。",
        }
        tip = tips.get(quality, "")
        console.print(f"\n[{color}]信号质量: {quality}[/{color}]  {tip}")
