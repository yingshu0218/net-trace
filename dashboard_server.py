"""
netest Web Dashboard

基于 Flask 的网络质量检测 Web 仪表盘。
"""
import sys
import os
import json

# 确保 src 目录在路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

from netest.network_info import collect_all, report_to_dict

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), "src"))
CORS(app)


@app.route("/api/report")
def api_report():
    """获取完整网络检测报告"""
    try:
        report = collect_all()
        return jsonify({"ok": True, "data": report_to_dict(report)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/")
def index():
    """仪表盘首页"""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    if os.path.exists(dashboard_path):
        return send_from_directory(os.path.dirname(__file__), "dashboard.html")
    return "<h1>dashboard.html not found</h1>", 404


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory(os.path.dirname(__file__), path)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="netest Web Dashboard")
    parser.add_argument("--port", type=int, default=8765, help="监听端口 (默认 8765)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="监听地址")
    args = parser.parse_args()

    print(f"\n  netest Dashboard 启动中...")
    print(f"  ─────────────────────────────")
    print(f"  地址: http://{args.host}:{args.port}")
    print(f"  API:  http://{args.host}:{args.port}/api/report")
    print(f"  ─────────────────────────────\n")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
