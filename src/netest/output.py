"""Rich 统一输出格式化"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TaskProgressColumn, TimeElapsedColumn,
)

console = Console()


def print_header(title):
    """打印带样式的标题面板"""
    console.print(Panel(f"[bold blue]{title}[/bold blue]", expand=False))


def print_error(message):
    """打印错误信息"""
    console.print(f"[red]错误: {message}[/red]")


def print_warning(message):
    """打印警告信息"""
    console.print(f"[yellow]警告: {message}[/yellow]")


def print_success(message):
    """打印成功信息"""
    console.print(f"[green]{message}[/green]")


def print_info(message):
    """打印信息"""
    console.print(f"[blue]{message}[/blue]")


def speed_table(results):
    """网速测试结果表格"""
    table = Table(title="网速测试结果", show_header=True, header_style="bold cyan")
    table.add_column("项目", style="cyan", no_wrap=True)
    table.add_column("数值", style="green")
    table.add_column("单位", style="yellow")

    dl_mbps = results.get("download", 0) / 1_000_000
    ul_mbps = results.get("upload", 0) / 1_000_000
    ping = results.get("ping", 0)

    table.add_row("下载速度", f"{dl_mbps:.2f}", "Mbps")
    table.add_row("上传速度", f"{ul_mbps:.2f}", "Mbps")
    table.add_row("延迟", f"{ping:.2f}", "ms")

    server = results.get("server", {})
    if server:
        table.add_row("服务器", server.get("name", ""), "")
        table.add_row("位置", f"{server.get('country', '')} {server.get('city', '')}", "")

    return table


def wifi_table(info):
    """WiFi 信息表格"""
    from netest.utils import rssi_quality, format_rssi

    table = Table(title="WiFi 连接信息", show_header=True, header_style="bold cyan")
    table.add_column("属性", style="cyan", no_wrap=True)
    table.add_column("值", style="green")

    table.add_row("SSID", info.get("ssid", "未知"))
    table.add_row("BSSID", info.get("bssid", "未知"))

    rssi = info.get("rssi")
    if rssi is not None:
        quality, color = rssi_quality(rssi)
        table.add_row("信号强度 (RSSI)", f"{rssi} dBm [{color}]{quality}[/{color}]")
    else:
        table.add_row("信号强度 (RSSI)", "未知")

    noise = info.get("noise")
    table.add_row("噪声", f"{noise} dBm" if noise is not None else "未知")

    snr = info.get("snr")
    table.add_row("信噪比 (SNR)", f"{snr} dB" if snr is not None else "未知")

    table.add_row("信道", str(info.get("channel", "未知")))
    table.add_row("频段", info.get("channel_band", "未知"))
    table.add_row("信道宽度", info.get("channel_width", "未知"))
    table.add_row("PHY 模式", info.get("phy_mode", "未知"))
    table.add_row("传输速率", f"{info.get('transmit_rate', '未知')} Mbps" if info.get("transmit_rate") else "未知")
    table.add_row("安全类型", info.get("security", "未知"))

    return table


def traceroute_table(hops, show_geo=False):
    """路由追踪结果表格"""
    table = Table(title="路由追踪结果", show_header=True, header_style="bold cyan")
    table.add_column("跳数", style="cyan", no_wrap=True)
    table.add_column("主机", style="green")
    table.add_column("IP", style="yellow")
    table.add_column("延迟 (ms)", style="magenta")
    if show_geo:
        table.add_column("地理位置", style="blue")

    for hop in hops:
        hop_num = hop.get("hop", "")
        hostname = hop.get("hostname", "*")
        ip = hop.get("ip", "")
        rtts = hop.get("rtts", [])
        avg_rtt = hop.get("avg_rtt")

        if hop.get("timeout"):
            table.add_row(str(hop_num), "* * *", "请求超时", "-")
        else:
            rtt_str = f"{avg_rtt:.3f}" if avg_rtt else "-"
            geo_str = ""
            if show_geo and hop.get("geo"):
                geo = hop["geo"]
                geo_str = f"{geo.get('country', '')} {geo.get('city', '')}"
                if geo.get("isp"):
                    geo_str += f" ({geo['isp']})"
            table.add_row(str(hop_num), hostname, ip, rtt_str, geo_str if show_geo else "")

    return table


def make_progress():
    """创建统一风格的进度条"""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        transient=True,
    )
