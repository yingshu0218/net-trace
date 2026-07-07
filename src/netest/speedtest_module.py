"""网速测试模块

优先使用 speedtest-cli 库（Ookla 服务器），
备选方案：通过下载大文件测量下载速度。
"""

import time
import tempfile
import os

from netest.output import console, print_error, print_info, print_success, print_warning, print_header, speed_table, make_progress


def run_speed_test(server_id=None, simple_output=False):
    """执行网速测试"""
    print_header("网速测试")

    # 方法1: speedtest-cli 库
    try:
        import speedtest
        _run_speedtest_lib(server_id, simple_output)
        return
    except ImportError:
        print_info("speedtest-cli 库未找到，使用备选方案...")
    except Exception as e:
        print_warning(f"speedtest-cli 测速失败: {e}")
        print_info("切换至备选测速方案...")

    # 方法2: 通过下载文件测速
    _run_download_speed_test(simple_output)


def _run_speedtest_lib(server_id, simple_output):
    """使用 speedtest-cli 库测速"""
    import speedtest

    with make_progress() as progress:
        task = progress.add_task("正在获取测速服务器...", total=None)
        st = speedtest.Speedtest()

        if server_id:
            st.get_servers(servers=[server_id])
        else:
            st.get_servers()

        progress.update(task, description="正在选择最佳服务器...")
        st.get_best_server()

        progress.update(task, description="正在测试下载速度...")
        st.download()

        progress.update(task, description="正在测试上传速度...")
        st.upload()

        progress.update(task, description="测速完成！")

    results = st.results.dict()
    _display_speed_results(results, simple_output)


def _run_download_speed_test(simple_output):
    """备选方案：通过下载文件测量网速"""
    print_info("使用下载测速（仅测试下载速度）")

    # 使用公开的速度测试文件
    test_urls = [
        "http://speedtest.tele2.net/1MB.zip",
        "http://ipv4.download.thinkbroadband.com/1MB.zip",
    ]

    downloaded = 0
    speed_mbps = 0

    for url in test_urls:
        print_info(f"尝试从 {url.split('/')[2]} 下载...")
        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(url, headers={"User-Agent": "netest/0.1"})

            with make_progress() as progress:
                task = progress.add_task("正在下载测试文件...", total=None)

                start = time.time()
                with urllib.request.urlopen(req, timeout=15) as resp:
                    total_size = int(resp.headers.get("Content-Length", 0))
                    if total_size:
                        progress.update(task, total=total_size)

                    with tempfile.NamedTemporaryFile(delete=False) as f:
                        downloaded = 0
                        while True:
                            chunk = resp.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size:
                                progress.update(task, completed=downloaded)

                elapsed = time.time() - start

            # 计算速度
            if elapsed > 0:
                speed_bps = (downloaded * 8) / elapsed
                speed_mbps = speed_bps / 1_000_000

            # 清理临时文件
            try:
                os.unlink(f.name)
            except Exception:
                pass

            break

        except Exception as e:
            print_warning(f"从 {url.split('/')[2]} 下载失败: {e}")
            continue

    if simple_output:
        console.print(f"下载速度: {speed_mbps:.2f} Mbps（估算）")
    else:
        from rich.table import Table
        table = Table(title="网速测试结果（下载测速）")
        table.add_column("项目", style="cyan")
        table.add_column("数值", style="green")
        table.add_column("单位", style="yellow")
        table.add_row("下载速度（估算）", f"{speed_mbps:.2f}", "Mbps")
        table.add_row("测试方法", "文件下载测速", "")
        console.print(table)
        console.print("[dim]提示: 无法连接 speedtest.net，此为下载测速估算值[/dim]")


def _display_speed_results(results, simple=False):
    """显示 speedtest-cli 测速结果"""
    if simple:
        dl = results.get("download", 0) / 1_000_000
        ul = results.get("upload", 0) / 1_000_000
        ping = results.get("ping", 0)
        console.print(f"下载: {dl:.2f} Mbps")
        console.print(f"上传: {ul:.2f} Mbps")
        console.print(f"延迟: {ping:.2f} ms")
    else:
        from netest.output import speed_table
        table = speed_table(results)
        console.print(table)

        server = results.get("server", {})
        if server:
            console.print(f"\n[dim]服务器: {server.get('name', '')} ({server.get('country', '')} {server.get('city', '')}[/dim]")
