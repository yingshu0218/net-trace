"""路由追踪模块 - 包装系统 traceroute 命令"""

import subprocess
import re
import urllib.request
import json

from netest.output import console, print_error, print_info, print_header


def run_traceroute(host, max_hops=30, queries_per_hop=3, timeout=5, show_geo=False):
    """执行路由追踪"""
    print_header(f"路由追踪: {host}")
    print_info(f"最大跳数: {max_hops}，每跳探测: {queries_per_hop} 次\n")

    try:
        cmd = [
            "traceroute",
            "-m", str(max_hops),
            "-q", str(queries_per_hop),
            "-w", str(timeout),
            host,
        ]

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        hops = []
        geo_cache = {}

        for line in process.stdout:
            hop_info = _parse_traceroute_line(line.strip())
            if hop_info:
                hops.append(hop_info)

                if show_geo and hop_info.get("ip"):
                    ip = hop_info["ip"]
                    if ip not in geo_cache:
                        geo_cache[ip] = _get_ip_geolocation(ip)
                    hop_info["geo"] = geo_cache[ip]

                _display_hop(hop_info, show_geo)

        process.wait()

        if hops:
            _display_summary(hops)
        else:
            print_error("未获取到任何路由信息")

    except FileNotFoundError:
        print_error("未找到 traceroute 命令，请确认系统完整性")
    except PermissionError:
        print_error("权限不足，无法执行 traceroute")
        console.print("[dim]提示: 在终端直接运行 `sudo netest trace <host>` 或以管理员权限运行[/dim]")
    except Exception as e:
        print_error(f"路由追踪失败: {e}")


def _parse_traceroute_line(line):
    """解析 traceroute 输出的一行"""
    if not line or line.startswith("traceroute") or line.startswith("tracert"):
        return None

    # 格式: " 1  gateway (192.168.1.1)  1.234 ms  1.345 ms  1.456 ms"
    m = re.match(r"\s*(\d+)\s+(.+)", line)
    if not m:
        return None

    hop_num = int(m.group(1))
    rest = m.group(2).strip()

    if rest.strip() == "* * *" or rest.strip().startswith("*"):
        return {"hop": hop_num, "hostname": None, "ip": None, "rtts": [], "timeout": True}

    # 提取 IP 和主机名
    ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", rest)
    if ip_match:
        ip = ip_match.group(1)
        hostname = rest[:ip_match.start()].strip()
        if hostname.endswith("("):
            hostname = hostname[:-1].strip()
    else:
        # 可能没有括号包裹的 IP
        parts = rest.split()
        hostname = parts[0] if parts else rest
        ip = None
        # 尝试从主机名提取 IP
        ip_in_host = re.search(r"(\d+\.\d+\.\d+\.\d+)", hostname)
        if ip_in_host:
            ip = ip_in_host.group(1)

    # 提取延迟
    rtts = []
    for t in re.findall(r"([\d\.]+)\s*ms", rest):
        try:
            rtts.append(float(t))
        except ValueError:
            pass

    avg_rtt = sum(rtts) / len(rtts) if rtts else None
    min_rtt = min(rtts) if rtts else None
    max_rtt = max(rtts) if rtts else None

    return {
        "hop": hop_num,
        "hostname": hostname if hostname else None,
        "ip": ip,
        "rtts": rtts,
        "timeout": False,
        "avg_rtt": avg_rtt,
        "min_rtt": min_rtt,
        "max_rtt": max_rtt,
    }


def _get_ip_geolocation(ip):
    """查询 IP 地址的地理位置（ip-api.com 免费 API）"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp&lang=zh-CN"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                }
    except Exception:
        pass
    return None


def _display_hop(hop_info, show_geo=False):
    """显示一跳的信息"""
    hop_num = hop_info["hop"]

    if hop_info.get("timeout"):
        console.print(f"  {hop_num:2d}. [red]* * * 请求超时[/red]")
        return

    ip = hop_info.get("ip") or ""
    hostname = hop_info.get("hostname") or ""
    display_name = f"{hostname} ({ip})" if hostname and ip else (hostname or ip or "*")

    rtts = hop_info.get("rtts", [])
    if rtts:
        rtt_str = "  ".join([f"{rtt:.3f} ms" for rtt in rtts])
        avg = hop_info.get("avg_rtt")
    else:
        rtt_str = "* * *"
        avg = None

    line = f"  {hop_num:2d}. {display_name:40s} {rtt_str}"
    if avg is not None:
        line += f"  [dim]avg: {avg:.3f} ms[/dim]"

    if show_geo and hop_info.get("geo"):
        geo = hop_info["geo"]
        geo_str = f"{geo.get('country', '')} {geo.get('city', '')}"
        if geo.get("isp"):
            geo_str += f" ({geo['isp']})"
        line += f"  [blue]{geo_str}[/blue]"

    console.print(line)


def _display_summary(hops):
    """显示追踪汇总"""
    valid_rtts = [h["avg_rtt"] for h in hops if h.get("avg_rtt") is not None]
    if not valid_rtts:
        return

    total = len(hops)
    avg_all = sum(valid_rtts) / len(valid_rtts)
    min_hop = min(hops, key=lambda h: h.get("avg_rtt") or float("inf"))
    max_hop = max(hops, key=lambda h: h.get("avg_rtt") or 0)

    console.print(f"\n[green]追踪完成！[/green]")
    console.print(f"  总跳数: {total}")
    console.print(f"  平均延迟: {avg_all:.3f} ms")
    console.print(f"  最小延迟: {min_hop['avg_rtt']:.3f} ms (第 {min_hop['hop']} 跳)")
    console.print(f"  最大延迟: {max_hop['avg_rtt']:.3f} ms (第 {max_hop['hop']} 跳)")
