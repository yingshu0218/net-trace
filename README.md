# Net-Trace 网络链路检测工具

可视化网络路径拓扑检测工具，通过网页输入域名即可查看完整的网络链路：本机出口、DNS、域名解析、IP 归属、路由跳转、TLS 连接、代理/隧道。

## 功能

- **SSE 流式进度**：每步检测实时推送，拓扑图逐步生长
- **可视化拓扑**：vis.js 层次布局，从左到右线性排列节点链路
- **7 步检测**：
  1. 本机出口（默认路由 + 本机 IP，识别 VPN/隧道）
  2. DNS 配置（系统 DNS 服务器）
  3. 域名解析（CNAME 链 + 识别 CDN/WAF/云服务）
  4. IP 归属（whois 查询 NetName/Country/Descr）
  5. 路由跳转（traceroute 逐跳路径 + RTT）
  6. TLS 连接（握手、证书、代理检测）
  7. 代理/隧道（系统代理 + 环境变量 + VPN 网卡）

## 技术栈

- 后端：Python + Flask（SSE 流式响应）
- 前端：HTML + vis.js 网络拓扑图
- 依赖系统命令：`netstat`、`ifconfig`、`scutil`、`dig`、`whois`、`traceroute`、`curl`

## 快速开始

```bash
# 安装依赖
pip install flask

# 启动服务
python network_check_server.py

# 浏览器访问
open http://127.0.0.1:8765
```

输入域名（如 `www.baidu.com`），点击「开始检测」即可。

> 注意：traceroute 步骤需要网络权限。macOS 沙箱环境下可能受限，请在终端直接运行。

## 文件说明

| 文件 | 说明 |
|------|------|
| `network_check_server.py` | Flask 后端，执行系统命令并通过 SSE 推送结果 |
| `network_check.html` | 前端页面，vis.js 拓扑图 + 实时进度面板 |

## CNAME 识别支持

自动识别常见云服务：阿里云 WAF/CDN、腾讯云 CDN/DSA/WAF/DDoS、Cloudflare、Akamai、AWS CloudFront、Azure CDN、网宿 CDN、百度 CDN、金山云 CDN、UCloud CDN 等。

## License

MIT
