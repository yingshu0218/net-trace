"""Ping 检测模块 - 检测多个服务器的延迟和丢包率"""

import re
import subprocess
import threading
import time
from typing import Dict, List, Tuple

from rich.console import Console
from rich.table import Table
from rich.status import Status

console = Console()

# 预设检测服务器列表
DEFAULT_SERVERS = [
    {"name": "阿里 DNS", "host": "223.5.5.5", "region": "国内"},
    {"name": "腾讯 DNS", "host": "119.29.29.29", "region": "国内"},
    {"name": "114 DNS", "host": "114.114.114.114", "region": "国内"},
    {"name": "百度", "host": "www.baidu.com", "region": "国内"},
    {"name": "淘宝", "host": "www.taobao.com", "region": "国内"},
    {"name": "腾讯", "host": "www.qq.com", "region": "国内"},
    {"name": "Google DNS", "host": "8.8.8.8", "region": "国际"},
    {"name": "Cloudflare DNS", "host": "1.1.1.1", "region": "国际"},
    {"name": "Google", "host": "www.google.com", "region": "国际"},
    {"name": "GitHub", "host": "github.com", "region": "国际"},
]


def parse_ping_output(output: str) -> Dict:
    """
    解析 ping 命令输出，提取统计信息
    
    macOS ping 输出格式示例:
    --- 8.8.8.8 ping statistics ---
    10 packets transmitted, 10 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 45.123/67.890/89.456/10.234 ms
    
    Returns:
        包含丢包率、最小/平均/最大延迟的字典
    """
    result = {
        "packet_loss": 100.0,
        "min_latency": None,
        "avg_latency": None,
        "max_latency": None,
        "stddev": None,
        "transmitted": 0,
        "received": 0,
    }
    
    # 解析丢包率
    loss_match = re.search(r'(\d+) packets transmitted, (\d+) packets received, ([\d.]+)% packet loss', output)
    if loss_match:
        result["transmitted"] = int(loss_match.group(1))
        result["received"] = int(loss_match.group(2))
        result["packet_loss"] = float(loss_match.group(3))
    
    # 解析延迟统计
    latency_match = re.search(r'round-trip min/avg/max/(?:stddev|mdev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
    if latency_match:
        result["min_latency"] = float(latency_match.group(1))
        result["avg_latency"] = float(latency_match.group(2))
        result["max_latency"] = float(latency_match.group(3))
        result["stddev"] = float(latency_match.group(4))
    
    return result


def ping_host_realtime(host: str, count: int = 10, timeout: int = 5, 
                       status: Status = None, progress_callback = None) -> Dict:
    """
    Ping 单个主机（实时进度更新）
    
    Args:
        host: 主机地址或域名
        count: 发送包数量
        timeout: 超时时间（秒）
        status: Rich Status 对象，用于更新状态消息
        progress_callback: 进度回调函数，每收到一个回复调用一次
        
    Returns:
        包含 ping 结果的字典
    """
    try:
        # macOS ping 命令
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-t", str(timeout), host]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        received = 0
        start_time = time.time()
        
        # 实时读取输出
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            
            if line:
                # 更新状态消息
                if status and received < count:
                    status.update(f"[yellow]正在 ping {host}... ({received}/{count} 个包)[/yellow]")
                
                # 检测 ping 回复
                if "bytes from" in line or "icmp_seq" in line:
                    received += 1
                    if progress_callback:
                        progress_callback(received, count)
        
        # 等待进程结束
        process.wait(timeout=5)
        
        # 读取完整输出用于解析统计信息
        full_output = ""
        for line in process.stdout:
            full_output += line
        
        #  also get stderr
        stderr_output = ""
        if process.stderr:
            stderr_output = process.stderr.read()
        
        # 重新运行一次来获取完整输出（因为上面已经读取了）
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )
        
        output = result.stdout + result.stderr
        stats = parse_ping_output(output)
        stats["host"] = host
        stats["success"] = result.returncode == 0 or stats["received"] > 0
        
        return stats
        
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "success": False,
            "packet_loss": 100.0,
            "min_latency": None,
            "avg_latency": None,
            "max_latency": None,
            "stddev": None,
            "transmitted": count,
            "received": 0,
            "error": "超时"
        }
    except Exception as e:
        return {
            "host": host,
            "success": False,
            "packet_loss": 100.0,
            "min_latency": None,
            "avg_latency": None,
            "max_latency": None,
            "stddev": None,
            "transmitted": count,
            "received": 0,
            "error": str(e)
        }


def ping_host(host: str, count: int = 10, timeout: int = 5) -> Dict:
    """
    Ping 单个主机（简化版，用于批量测试）
    
    Args:
        host: 主机地址或域名
        count: 发送包数量
        timeout: 超时时间（秒）
        
    Returns:
        包含 ping 结果的字典
    """
    try:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-t", str(timeout), host]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )
        
        output = result.stdout + result.stderr
        stats = parse_ping_output(output)
        stats["host"] = host
        stats["success"] = result.returncode == 0 or stats["received"] > 0
        
        return stats
        
    except subprocess.TimeoutExpired:
        return {
            "host": host,
            "success": False,
            "packet_loss": 100.0,
            "min_latency": None,
            "avg_latency": None,
            "max_latency": None,
            "stddev": None,
            "transmitted": count,
            "received": 0,
            "error": "超时"
        }
    except Exception as e:
        return {
            "host": host,
            "success": False,
            "packet_loss": 100.0,
            "min_latency": None,
            "avg_latency": None,
            "max_latency": None,
            "stddev": None,
            "transmitted": count,
            "received": 0,
            "error": str(e)
        }


def get_latency_color(avg_latency: float) -> str:
    """
    根据平均延迟返回颜色代码
    
    Args:
        avg_latency: 平均延迟（毫秒）
        
    Returns:
        Rich 颜色字符串
    """
    if avg_latency is None:
        return "dim"
    if avg_latency < 50:
        return "green"
    elif avg_latency < 100:
        return "yellow"
    elif avg_latency < 200:
        return "orange1"
    else:
        return "red"


def get_loss_color(loss: float) -> str:
    """
    根据丢包率返回颜色代码
    
    Args:
        loss: 丢包率（百分比）
        
    Returns:
        Rich 颜色字符串
    """
    if loss == 0:
        return "green"
    elif loss < 5:
        return "yellow"
    elif loss < 20:
        return "orange1"
    else:
        return "red"


def run_ping_test(servers: List[Dict] = None, count: int = 10, 
                  timeout: int = 5, use_defaults: bool = True) -> List[Dict]:
    """
    运行 ping 测试（带进度显示）
    
    Args:
        servers: 自定义服务器列表，为 None 时使用预设列表
        count: 每个服务器的 ping 包数量
        timeout: ping 超时时间（秒）
        use_defaults: 是否使用预设服务器列表
        
    Returns:
        所有服务器的 ping 结果列表
    """
    if servers is None or use_defaults:
        targets = DEFAULT_SERVERS
    else:
        targets = servers
    
    results = []
    total = len(targets)
    
    console.print(f"\n[bold]正在 ping {total} 个服务器（每个 {count} 个包）...[/bold]\n")
    
    with Status("[yellow]正在准备...[/yellow]", console=console, spinner="dots") as status:
        for i, server in enumerate(targets, 1):
            name = server["name"]
            host = server["host"]
            region = server.get("region", "")
            
            status.update(f"[yellow]正在 ping {name} ({host}) - ({i}/{total})[/yellow]")
            
            stats = ping_host(host, count, timeout)
            stats["name"] = name
            stats["region"] = region
            results.append(stats)
            
            # 显示单个结果
            if stats["success"]:
                avg = stats["avg_latency"]
                loss = stats["packet_loss"]
                status.stop()
                console.print(f"  ✓ [green]{name}[/green] ({host}): ", end="")
                console.print(f"平均延迟 [bold {get_latency_color(avg)}]{avg:.1f}ms[/bold {get_latency_color(avg)}], ", end="")
                console.print(f"丢包率 [bold {get_loss_color(loss)}]{loss:.1f}%[/bold {get_loss_color(loss)}]")
                status.start()
            else:
                error_msg = stats.get("error", "未知错误")
                status.stop()
                console.print(f"  ✗ [red]{name}[/red] ({host}): 失败 - {error_msg}")
                status.start()
    
    return results


def display_ping_results(results: List[Dict], show_all: bool = False):
    """
    用表格展示 ping 测试结果
    
    Args:
        results: ping 结果列表
        show_all: 是否显示所有结果（包括失败的）
    """
    # 分离成功和失败的结果
    success_results = [r for r in results if r["success"]]
    failed_results = [r for r in results if not r["success"]]
    
    if not success_results and not show_all:
        console.print("\n[red]所有服务器 ping 失败！请检查网络连接[/red]")
        return
    
    # 按区域分组显示
    console.print("\n[bold]Ping 测试结果[/bold]\n")
    
    # 按区域分组
    regions = {}
    for r in success_results:
        region = r.get("region", "其他")
        if region not in regions:
            regions[region] = []
        regions[region].append(r)
    
    # 按区域显示表格
    for region_name in ["国内", "国际", "其他"]:
        if region_name in regions:
            _display_region_table(f"{region_name}服务器", regions[region_name])
    
    # 显示其他未列出的区域
    for region_name in regions:
        if region_name not in ["国内", "国际", "其他"]:
            _display_region_table(f"{region_name}服务器", regions[region_name])
    
    # 失败服务器列表
    if failed_results:
        console.print("\n[bold red]无法访问的服务器：[/bold red]")
        for r in failed_results:
            error = r.get("error", "未知错误")
            console.print(f"  ✗ {r['name']} ({r['host']}): {error}")


def _display_region_table(region_name: str, results: List[Dict]):
    """
    显示单个区域的 ping 结果表格
    
    Args:
        region_name: 区域名称
        results: 该区域的 ping 结果
    """
    table = Table(title=f"{region_name} Ping 延迟检测", show_lines=True)
    table.add_column("服务器", style="cyan", no_wrap=True)
    table.add_column("地址", style="dim")
    table.add_column("最小延迟", justify="right")
    table.add_column("平均延迟", justify="right")
    table.add_column("最大延迟", justify="right")
    table.add_column("抖动", justify="right")
    table.add_column("丢包率", justify="right")
    
    # 按平均延迟排序
    sorted_results = sorted(results, key=lambda x: x["avg_latency"] if x["avg_latency"] else 999999)
    
    for r in sorted_results:
        avg = r["avg_latency"]
        min_lat = r["min_latency"]
        max_lat = r["max_latency"]
        stddev = r["stddev"]
        loss = r["packet_loss"]
        
        avg_color = get_latency_color(avg)
        loss_color = get_loss_color(loss)
        
        table.add_row(
            r["name"],
            r["host"],
            f"[{avg_color}]{min_lat:.1f}ms[/{avg_color}]" if min_lat else "[dim]—[/dim]",
            f"[bold {avg_color}]{avg:.1f}ms[/bold {avg_color}]" if avg else "[dim]—[/dim]",
            f"[{avg_color}]{max_lat:.1f}ms[/{avg_color}]" if max_lat else "[dim]—[/dim]",
            f"[{avg_color}]{stddev:.1f}ms[/{avg_color}]" if stddev else "[dim]—[/dim]",
            f"[bold {loss_color}]{loss:.1f}%[/bold {loss_color}]"
        )
    
    console.print(table)


def ping_command(server: str = None, count: int = 10, timeout: int = 5, 
                 region: str = None, quick: bool = False):
    """
    Ping 命令主入口
    
    Args:
        server: 指定单个服务器（为空则 ping 预设列表）
        count: ping 包数量
        timeout: 超时时间（秒）
        region: 只 ping 指定区域的服务器（"国内" 或 "国际"）
        quick: 快速模式（每个服务器只发 4 个包）
    """
    from .output import print_info, print_error
    
    if quick:
        count = 4
        console.print("[yellow]快速模式：每个服务器发送 4 个 ping 包[/yellow]")
    
    # 单个服务器 ping
    if server:
        console.print(f"\n[bold]Ping {server}[/bold]\n")
        
        with Status(f"[yellow]正在 ping {server}...[/yellow]", console=console, spinner="dots") as status:
            stats = ping_host(server, count, timeout)
        
        if stats["success"]:
            table = Table(title=f"Ping 结果: {server}", show_lines=True)
            table.add_column("指标", style="cyan")
            table.add_column("数值", justify="right")
            
            table.add_row("目标地址", stats["host"])
            table.add_row("发送包数", str(stats["transmitted"]))
            table.add_row("接收包数", str(stats["received"]))
            table.add_row("丢包率", f"[bold {get_loss_color(stats['packet_loss'])}]{stats['packet_loss']:.1f}%[/bold {get_loss_color(stats['packet_loss'])}]")
            
            if stats["avg_latency"]:
                table.add_row("最小延迟", f"{stats['min_latency']:.1f} ms")
                table.add_row("平均延迟", f"[bold {get_latency_color(stats['avg_latency'])}]{stats['avg_latency']:.1f} ms[/bold {get_latency_color(stats['avg_latency'])}]")
                table.add_row("最大延迟", f"{stats['max_latency']:.1f} ms")
                table.add_row("抖动", f"{stats['stddev']:.1f} ms")
            
            console.print(table)
        else:
            print_error(f"Ping 失败: {stats.get('error', '未知错误')}")
        return
    
    # 多服务器 ping
    targets = DEFAULT_SERVERS
    
    # 按区域筛选
    if region:
        targets = [s for s in targets if s.get("region") == region]
        if not targets:
            print_error(f"未找到区域 '{region}' 的服务器，请使用 '国内' 或 '国际'")
            return
    
    results = run_ping_test(targets, count, timeout)
    display_ping_results(results)
    
    # 显示总结
    success_count = sum(1 for r in results if r["success"])
    if success_count > 0:
        avg_loss = sum(r["packet_loss"] for r in results if r["success"]) / success_count
        avg_latency = sum(r["avg_latency"] for r in results if r["success"] and r["avg_latency"]) / success_count
        
        console.print(f"\n[bold]总结:[/bold] {success_count}/{len(results)} 个服务器可达, ", end="")
        console.print(f"平均丢包率 [bold {get_loss_color(avg_loss)}]{avg_loss:.1f}%[/bold {get_loss_color(avg_loss)}], ", end="")
        console.print(f"平均延迟 [bold {get_latency_color(avg_latency)}]{avg_latency:.1f}ms[/bold {get_latency_color(avg_latency)}]")
