"""netest CLI 入口 - Click 命令组"""

import click

from netest.output import print_header, print_error, print_info, print_success


@click.group()
@click.version_option(version="0.1.0", prog_name="netest")
def main():
    """netest - macOS 网络诊断工具

    支持网速测试、WiFi 质量检测、路由追踪、Ping 检测和网络信息全面采集。
    """
    pass


@main.command()
@click.option("--server", default=None, help="指定测速服务器 ID")
@click.option("--simple", is_flag=True, help="简化输出模式")
def speed(server, simple):
    """网速测试（下载/上传速度、延迟、抖动、丢包率）"""
    from netest.speedtest_module import run_speed_test
    run_speed_test(server_id=server, simple_output=simple)


@main.command()
@click.option("--interface", default="en0", help="WiFi 接口名称（默认: en0）")
@click.option("--detail", is_flag=True, help="显示详细信息")
def wifi(interface, detail):
    """WiFi 质量检测（信号强度、信道、噪声、连接质量等）"""
    from netest.wifi_module import run_wifi_diagnostic
    run_wifi_diagnostic(interface=interface, detail=detail)


@main.command()
@click.argument("host")
@click.option("--max-hops", default=30, help="最大跳数（默认: 30）")
@click.option("--queries", default=3, help="每跳探测次数（默认: 3）")
@click.option("--timeout", default=5, help="超时时间（秒，默认: 5）")
@click.option("--geo", is_flag=True, help="显示 IP 地理位置信息")
def trace(host, max_hops, queries, timeout, geo):
    """路由追踪（显示路径上每跳的延迟）

    HOST: 目标主机（IP 或域名）
    """
    from netest.traceroute_module import run_traceroute
    run_traceroute(
        host=host,
        max_hops=max_hops,
        queries_per_hop=queries,
        timeout=timeout,
        show_geo=geo,
    )


@main.command()
@click.argument("host", default=None, required=False)
@click.option("-c", "--count", default=10, help="每个服务器 ping 包数量（默认: 10）")
@click.option("-t", "--timeout", default=5, help="超时时间（秒，默认: 5）")
@click.option("-r", "--region", default=None, help="只 ping 指定区域（国内/国际）")
@click.option("-q", "--quick", is_flag=True, help="快速模式（每个服务器 4 个包）")
def ping(host, count, timeout, region, quick):
    """Ping 服务器检测延迟和丢包率

    预设多个常见检测服务器（阿里DNS、腾讯DNS、百度、Google等），
    可指定单个服务器或检测全部预设服务器。

    HOST: 指定要 ping 的单个服务器（可选）
    """
    from netest.ping_module import ping_command
    ping_command(server=host, count=count, timeout=timeout, region=region, quick=quick)


@main.command()
@click.option("--server", default=None, help="指定测速服务器 ID")
@click.option("--trace-host", default=None, help="指定路由追踪目标（默认: 8.8.8.8）")
@click.option("--geo", is_flag=True, help="路由追踪时显示 IP 地理位置")
def all(server, trace_host, geo):
    """运行所有诊断（WiFi 检测 + 网速测试 + 路由追踪）"""
    from netest.wifi_module import run_wifi_diagnostic
    from netest.speedtest_module import run_speed_test
    from netest.traceroute_module import run_traceroute

    print_header("netest 全面网络诊断")

    print_info("正在检测 WiFi...")
    run_wifi_diagnostic(interface="en0", detail=False)

    print_info("\n正在测速...")
    run_speed_test(server_id=server, simple_output=False)

    target = trace_host or "8.8.8.8"
    print_info(f"\n正在追踪路由到 {target}...")
    run_traceroute(
        host=target,
        max_hops=30,
        queries_per_hop=3,
        timeout=5,
        show_geo=geo,
    )

    print_success("\n全部诊断完成！")


@main.command()
@click.option("--port", default=8765, help="监听端口（默认: 8765）")
@click.option("--host", default="127.0.0.1", help="监听地址（默认: 127.0.0.1）")
@click.option("--no-browser", is_flag=True, help="不自动打开浏览器")
def dashboard(port, host, no_browser):
    """启动 Web 仪表盘（网络信息全面采集与可视化）"""
    import os
    import sys
    import threading
    import webbrowser

    # 确保 src 目录在路径中
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from dashboard_server import app

    if not no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
