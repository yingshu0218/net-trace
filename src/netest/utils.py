"""工具函数"""


def format_speed(bps):
    """将 bps 转换为人类可读的速度格式"""
    if bps >= 1_000_000_000:
        return f"{bps / 1_000_000_000:.2f} Gbps"
    elif bps >= 1_000_000:
        return f"{bps / 1_000_000:.2f} Mbps"
    elif bps >= 1_000:
        return f"{bps / 1_000:.2f} Kbps"
    else:
        return f"{bps:.2f} bps"


def format_bytes(b):
    """将字节数转换为人类可读格式"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.2f} {unit}"
        b /= 1024
    return f"{b:.2f} PB"


def rssi_quality(rssi):
    """根据 RSSI 值返回信号质量评级和颜色"""
    if rssi is None:
        return "未知", "white"
    if rssi >= -50:
        return "优秀", "green"
    elif rssi >= -60:
        return "良好", "yellow"
    elif rssi >= -70:
        return "一般", "orange"
    elif rssi >= -80:
        return "较差", "red"
    else:
        return "很差", "red"


def format_rssi(rssi):
    """格式化 RSSI 值并给出质量评价"""
    if rssi is None:
        return "未知"
    quality, _ = rssi_quality(rssi)
    return f"{rssi} dBm ({quality})"


def snr_rating(snr):
    """根据信噪比返回评级"""
    if snr is None:
        return "未知"
    if snr >= 30:
        return "优秀"
    elif snr >= 20:
        return "良好"
    elif snr >= 10:
        return "一般"
    else:
        return "较差"


def is_valid_ip(ip):
    """检查是否为有效的 IPv4 地址"""
    import re
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    octets = ip.split(".")
    for octet in octets:
        if int(octet) > 255:
            return False
    return True


def parse_traceroute_time(time_str):
    """解析 traceroute 时间字符串，返回浮点数毫秒"""
    try:
        return float(time_str)
    except (ValueError, TypeError):
        return None
