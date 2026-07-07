#!/usr/bin/env python3
"""
网络链路检测后端服务 (SSE 流式版)
通过 Server-Sent Events 实时推送每一步检测进度和拓扑节点
"""

import subprocess
import json
import re
import os
import time
from flask import Flask, request, Response, send_from_directory

app = Flask(__name__)

STEP_CONFIG = [
    {"id": "local_exit",   "num": 1, "title": "本机出口",    "desc": "检测默认路由和本机 IP"},
    {"id": "dns",          "num": 2, "title": "DNS 配置",    "desc": "检测系统 DNS 服务器"},
    {"id": "resolution",   "num": 3, "title": "域名解析",    "desc": "解析目标域名和 CNAME 链路"},
    {"id": "ip_whois",     "num": 4, "title": "IP 归属",     "desc": "查询解析 IP 的归属信息"},
    {"id": "traceroute",   "num": 5, "title": "路由跳转",    "desc": "追踪到目标的逐跳路径"},
    {"id": "tls",          "num": 6, "title": "TLS 连接",    "desc": "测试 TLS 握手和证书"},
    {"id": "proxy_tunnel", "num": 7, "title": "代理/隧道",   "desc": "检测系统代理和 VPN 隧道"},
]

KNOWN_SERVICES = {
    "icloudwaf.com": ("阿里云 WAF", "waf"),
    "dsa.dnsv1.com.cn": ("腾讯云 DSA", "cdn"),
    "cdn.dnsv1.com": ("腾讯云 CDN", "cdn"),
    "qcloudcdn.com": ("腾讯云 CDN", "cdn"),
    "tcdn.qq.com": ("腾讯云 CDN", "cdn"),
    "alicdn.com": ("阿里云 CDN", "cdn"),
    "kunlun.com": ("阿里云 CDN", "cdn"),
    "cloudflare.com": ("Cloudflare", "cdn"),
    "fastly.com": ("Fastly", "cdn"),
    "akamai.net": ("Akamai", "cdn"),
    "edgekey.net": ("Akamai", "cdn"),
    "cloudfront.net": ("AWS CloudFront", "cdn"),
    "azureedge.net": ("Azure CDN", "cdn"),
    "cdn77.com": ("CDN77", "cdn"),
    "waf.dnsv1.com": ("腾讯云 WAF", "waf"),
    "ddos.dnsv1.com": ("腾讯云 DDoS", "ddos"),
    "qcloudwaf.com": ("腾讯云 WAF", "waf"),
    "cdn20.com": ("网宿 CDN", "cdn"),
    "lxdns.com": ("网宿 CDN", "cdn"),
    "wsdvs.com": ("网宿 CDN", "cdn"),
    "chinanetcenter.com": ("网宿 CDN", "cdn"),
    "bdydns.com": ("百度 CDN", "cdn"),
    "jomodns.com": ("金山云 CDN", "cdn"),
    "ucloud.cn": ("UCloud CDN", "cdn"),
    "dnspod.net": ("DNSPod", "dns"),
    "myqcloud.com": ("腾讯云", "cloud"),
}


def run_cmd(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


def emit(event, data):
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ---------- topology node/edge builders ----------

class TopoBuilder:
    """构建拓扑数据，跟踪已添加的节点避免重复"""
    def __init__(self):
        self.next_id = 0
        self.added = set()  # (type, label) 去重

    def _n(self):
        nid = self.next_id
        self.next_id += 1
        return nid

    def node(self, ntype, label, subtitle="", shape="dot", size=16):
        """添加节点，返回 id。如果已存在同类型同标签则复用"""
        key = (ntype, label)
        if key in self.added:
            return None  # 前端已有
        self.added.add(key)
        nid = self._n()
        return {
            "id": nid, "ntype": ntype, "label": label, "subtitle": subtitle,
            "shape": shape, "size": size,
        }

    def edge(self, from_id, to_id, label=""):
        return {"from": from_id, "to": to_id, "label": label}


# ---------- step implementations ----------

def step_local_exit():
    result = {"default_route": None, "local_ip": None, "is_vpn": False}
    out, _, _ = run_cmd("netstat -rn -f inet 2>/dev/null | grep default")
    if out:
        for line in out.split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "default":
                iface = parts[3]
                result["default_route"] = {"gateway": parts[1], "interface": iface}
                if any(x in iface.lower() for x in ["utun", "tun", "ppp", "ipsec", "wg"]):
                    result["is_vpn"] = True
                break
    iface = result["default_route"]["interface"] if result["default_route"] else "en0"
    out, _, _ = run_cmd(f"ifconfig {iface} 2>/dev/null | grep 'inet '")
    if out:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            result["local_ip"] = m.group(1)
    if not result["local_ip"]:
        out, _, _ = run_cmd("ifconfig en0 2>/dev/null | grep 'inet '")
        if out:
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
            if m:
                result["local_ip"] = m.group(1)
    return result


def step_dns():
    result = {"servers": [], "source": "unknown"}
    out, _, _ = run_cmd("scutil --dns 2>/dev/null")
    if out:
        servers = []
        for line in out.split("\n"):
            m = re.search(r"nameserver\[(\d+)\]\s*:\s*(\S+)", line)
            if m:
                servers.append(m.group(2))
        if servers:
            result["servers"] = servers
    out, _, _ = run_cmd("networksetup -getdnsservers Wi-Fi 2>/dev/null")
    if out and "There aren't any" not in out:
        dns = [d.strip() for d in out.split("\n") if d.strip()]
        if dns:
            result["servers"] = dns
            result["source"] = "Wi-Fi"
    seen = set()
    deduped = []
    for s in result["servers"]:
        if s and s not in seen:
            seen.add(s)
            deduped.append(s)
    result["servers"] = deduped
    return result


def step_resolution(domain):
    result = {"domain": domain, "ips": [], "cname_chain": []}
    out, _, _ = run_cmd(f"dig +short '{domain}' 2>/dev/null", timeout=10)
    if out:
        for line in out.split("\n"):
            line = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
                result["ips"].append(line)
    out, _, _ = run_cmd(f"dig '{domain}' 2>/dev/null", timeout=10)
    if out:
        cnames = []
        for line in out.split("\n"):
            if "CNAME" in line and ";" not in line:
                parts = line.split()
                if len(parts) >= 5:
                    cnames.append(parts[-1].rstrip("."))
        chain = [domain.rstrip(".")]
        for c in cnames:
            chain.append(c)
        result["cname_chain"] = chain
        in_answer = False
        for line in out.split("\n"):
            if "ANSWER SECTION" in line:
                in_answer = True
                continue
            if in_answer and line == "":
                break
            if in_answer and "A" in line and "CNAME" not in line:
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[-1]
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and ip not in result["ips"]:
                        result["ips"].append(ip)

    # 分析 CNAME 链路
    services = []
    for cname in chain[1:]:  # 跳过第一个（域名本身）
        for pattern, (name, svc_type) in KNOWN_SERVICES.items():
            if pattern in cname.lower():
                services.append({"cname": cname, "service": name, "type": svc_type})
                break
    result["cname_services"] = services
    return result


def step_ip_whois(ips):
    result = {}
    for ip in ips:
        info = {"netname": "", "country": "", "descr": ""}
        out, _, _ = run_cmd(f"whois '{ip}' 2>/dev/null | grep -iE 'netname|descr|country|org-name|OrgName' | head -8", timeout=10)
        if out:
            for line in out.split("\n"):
                ll = line.lower()
                if "netname" in ll:
                    info["netname"] = line.split(":", 1)[-1].strip() if ":" in line else line.split("NetName", 1)[-1].strip()
                elif "country" in ll:
                    info["country"] = line.split(":", 1)[-1].strip() if ":" in line else line.split("Country", 1)[-1].strip()
                elif "descr" in ll:
                    info["descr"] = line.split(":", 1)[-1].strip() if ":" in line else line.split("descr", 1)[-1].strip()
                elif "org-name" in ll or "orgname" in ll:
                    info["descr"] = line.split(":", 1)[-1].strip() if ":" in line else line.split("OrgName", 1)[-1].strip()
        result[ip] = info
    return result


def step_traceroute(target_ip):
    """使用 traceroute 追踪到目标 IP 的逐跳路由"""
    result = {"hops": [], "error": None, "target": target_ip}
    # 尝试 traceroute，沙箱内可能因权限失败
    out, err, rc = run_cmd(
        f"traceroute -n -m 15 -q 1 -w 2 '{target_ip}' 2>&1",
        timeout=30,
    )
    if rc != 0 or "Operation not permitted" in out or "not permitted" in err:
        result["error"] = "需要管理员权限才能追踪路由跳转（沙箱限制）"
        # 回退：用 route -n get 获取出口信息
        out2, _, _ = run_cmd(f"route -n get '{target_ip}' 2>/dev/null", timeout=5)
        route_info = {"interface": None, "gateway": None, "is_tunnel": False}
        if out2:
            for line in out2.split("\n"):
                if line.strip().startswith("interface:"):
                    iface = line.split(":", 1)[-1].strip()
                    route_info["interface"] = iface
                    if any(x in iface for x in ["utun", "tun", "ppp", "ipsec", "wg"]):
                        route_info["is_tunnel"] = True
                elif line.strip().startswith("gateway:"):
                    route_info["gateway"] = line.split(":", 1)[-1].strip()
        result["route_fallback"] = route_info
        return result

    # 解析 traceroute 输出
    # 格式: 1  192.168.1.1  2.123 ms
    for line in out.split("\n"):
        line = line.strip()
        if not line or "traceroute" in line.lower():
            continue
        # 提取跳数和 IP
        parts = line.split()
        if len(parts) >= 2:
            try:
                hop = int(parts[0])
            except ValueError:
                continue
            ip = parts[1]
            rtt = None
            # 提取 RTT
            for p in parts[2:]:
                p = p.replace("ms", "")
                try:
                    rtt = float(p)
                    break
                except ValueError:
                    continue
            result["hops"].append({
                "hop": hop,
                "ip": ip if ip != "*" else None,
                "rtt": rtt,
                "timeout": ip == "*",
            })
    return result


def step_tls(domain):
    result = {"connected": False, "tls_version": "", "cert_cn": "", "cert_issuer": "",
              "http_code": "", "proxy_detected": False, "proxy_info": ""}
    out, err, _ = run_cmd(
        f"curl -sv --connect-timeout 8 --max-time 10 -o /dev/null 'https://{domain}' 2>&1",
        timeout=15,
    )
    combined = out + "\n" + err
    if re.search(r"Trying\s+(127\.0\.0\.1|localhost|::1)", combined):
        result["proxy_detected"] = True
        m = re.search(r"Trying\s+(127\.0\.0\.1:\d+)", combined)
        if m:
            result["proxy_info"] = m.group(0)
    tls_m = re.search(r"(TLSv[\d.]+|SSLv[\d.]+)", combined)
    if tls_m:
        result["tls_version"] = tls_m.group(1)
        result["connected"] = True
    cn_m = re.search(r"subject:\s*(?:.*?CN\s*=\s*([^,\n]+))", combined, re.IGNORECASE)
    if cn_m:
        result["cert_cn"] = cn_m.group(1).strip()
    else:
        cn_m = re.search(r"CN=([^*,\s]+(?:\.[^*,\s]+)+)", combined)
        if cn_m:
            result["cert_cn"] = cn_m.group(1)
    iss_m = re.search(r"issuer:\s*(?:.*?O\s*=\s*([^,\n]+))", combined, re.IGNORECASE)
    if iss_m:
        result["cert_issuer"] = iss_m.group(1).strip()
    http_m = re.search(r"< HTTP/\d\.\d\s+(\d+)", combined)
    if http_m:
        result["http_code"] = http_m.group(1)
    http2_m = re.search(r"HTTP/(\d)\s+(\d+)", combined)
    if http2_m:
        result["http_code"] = http2_m.group(2)
    if not result["tls_version"] and re.search(r"Connected to", combined):
        result["connected"] = True
    return result


def step_proxy_tunnel():
    result = {"system_proxy": {}, "env_proxy": {}, "tunnel_interfaces": []}
    out, _, _ = run_cmd("scutil --proxy 2>/dev/null", timeout=5)
    if out:
        for line in out.split("\n"):
            for key in ["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy",
                         "HTTPSPort", "SOCKSEnable", "SOCKSProxy", "SOCKSPort"]:
                if line.strip().startswith(f"{key} :"):
                    result["system_proxy"][key] = line.split(":", 1)[-1].strip()
    for var in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY", "no_proxy", "NO_PROXY"]:
        val = os.environ.get(var)
        if val:
            result["env_proxy"][var] = val
    out, _, _ = run_cmd("ifconfig 2>/dev/null | grep -E '^(utun|tun|ppp|ipsec|wg)'", timeout=5)
    if out:
        result["tunnel_interfaces"] = [line.split(":")[0].strip() for line in out.split("\n") if line.strip()]
    return result


# ---------- SSE endpoint ----------

@app.route("/api/check")
def api_check():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return Response("data: " + json.dumps({"error": "请提供 domain 参数"}, ensure_ascii=False) + "\n\n",
                        mimetype="text/event-stream")

    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    def generate():
        topo = TopoBuilder()
        steps_data = {}

        # 发送所有步骤定义
        yield emit("steps_def", STEP_CONFIG)

        # === 步骤 1: 本机出口 ===
        yield emit("step_start", {"id": "local_exit"})
        data = step_local_exit()
        steps_data["local_exit"] = data

        # 拓扑: 本机节点
        local_ip = data.get("local_ip", "?")
        local_iface = data["default_route"]["interface"] if data["default_route"] else "?"
        local_gw = data["default_route"]["gateway"] if data["default_route"] else "?"
        is_vpn = data.get("is_vpn", False)

        local_node = topo.node("local", "本机" + (" [VPN]" if is_vpn else ""),
                               f"{local_ip}\n{local_iface}", "dot", 22)
        gw_node = topo.node("gateway", "网关", local_gw, "diamond", 16)

        topo_nodes = [n for n in [local_node, gw_node] if n]
        topo_edges = []
        if local_node and gw_node:
            topo_edges.append(topo.edge(local_node["id"], gw_node["id"], local_iface))

        yield emit("step_done", {"id": "local_exit", "data": data, "nodes": topo_nodes, "edges": topo_edges})
        time.sleep(0.3)  # 让前端有时间渲染动画

        # === 步骤 2: DNS 配置 ===
        yield emit("step_start", {"id": "dns"})
        data = step_dns()
        steps_data["dns"] = data

        dns_nodes = []
        dns_edges = []
        if local_node:
            for i, server in enumerate(data.get("servers", [])[:3]):
                dn = topo.node("dns", "DNS", server, "diamond", 14)
                if dn:
                    dns_nodes.append(dn)
                    dns_edges.append(topo.edge(local_node["id"], dn["id"], "DNS 查询" if i == 0 else ""))

        yield emit("step_done", {"id": "dns", "data": data, "nodes": dns_nodes, "edges": dns_edges})
        time.sleep(0.3)

        # === 步骤 3: 域名解析 ===
        yield emit("step_start", {"id": "resolution"})
        data = step_resolution(domain)
        steps_data["resolution"] = data

        res_nodes = []
        res_edges = []

        domain_node = topo.node("domain", domain, "", "dot", 18)
        if domain_node:
            res_nodes.append(domain_node)
            # DNS → 域名
            for dn in dns_nodes:
                res_edges.append(topo.edge(dn["id"], domain_node["id"], "解析" if dn == dns_nodes[0] else ""))

        # CNAME 链
        chain = data.get("cname_chain", [])
        services = data.get("cname_services", [])
        prev_id = domain_node["id"] if domain_node else None
        cname_ids = []

        for i in range(1, len(chain)):
            cname = chain[i]
            svc = next((s for s in services if s["cname"] == cname), None)
            ntype = svc["type"] if svc else "cname"
            label = svc["service"] if svc else cname
            cn = topo.node(ntype, label, cname if svc else "", "dot", 16)
            if cn:
                res_nodes.append(cn)
                cname_ids.append(cn["id"])
                if prev_id is not None:
                    res_edges.append(topo.edge(prev_id, cn["id"], "CNAME"))
                prev_id = cn["id"]

        yield emit("step_done", {"id": "resolution", "data": data, "nodes": res_nodes, "edges": res_edges})
        time.sleep(0.3)

        # === 步骤 4: IP 归属 ===
        ips = data.get("ips", [])
        yield emit("step_start", {"id": "ip_whois"})
        whois_data = step_ip_whois(ips)
        steps_data["ip_whois"] = whois_data

        ip_nodes = []
        ip_edges = []
        from_id = cname_ids[-1] if cname_ids else (domain_node["id"] if domain_node else None)
        local_id = local_node["id"] if local_node else None

        for ip in ips:
            w = whois_data.get(ip, {})
            extra = ""
            if w.get("country"):
                extra += w["country"]
            if w.get("netname"):
                extra += (" / " + w["netname"]) if extra else w["netname"]
            tn = topo.node("target", ip, extra, "dot", 18)
            if tn:
                ip_nodes.append(tn)
                if from_id is not None:
                    ip_edges.append(topo.edge(from_id, tn["id"], "A 记录"))

        yield emit("step_done", {"id": "ip_whois", "data": whois_data, "nodes": ip_nodes, "edges": ip_edges})
        time.sleep(0.3)

        # === 步骤 5: 路由跳转 (traceroute) ===
        yield emit("step_start", {"id": "traceroute"})
        trace_target = ips[0] if ips else domain
        trace_data = step_traceroute(trace_target)
        steps_data["traceroute"] = trace_data

        hop_nodes = []
        hop_edges = []

        hops = trace_data.get("hops", [])
        gw_id = gw_node["id"] if gw_node else None
        if hops:
            # 有真实 traceroute 数据
            prev_id = gw_id
            last_hop_id = None
            for h in hops:
                label = h["ip"] if h["ip"] else f"跳{h['hop']}"
                sub = f"{h['rtt']:.1f}ms" if h.get("rtt") else ("超时" if h.get("timeout") else "")
                hn = topo.node("hop", label, sub, "dot", 14)
                if hn:
                    hop_nodes.append(hn)
                    last_hop_id = hn["id"]
                    if prev_id is not None:
                        hop_edges.append(topo.edge(prev_id, hn["id"], f"跳{h['hop']}"))
                    prev_id = hn["id"]
            # 最后一跳连到目标 IP
            if last_hop_id is not None:
                for tip in ip_nodes:
                    hop_edges.append(topo.edge(last_hop_id, tip["id"], "到达"))
        elif gw_id is not None and trace_data.get("route_fallback"):
            # 沙箱回退：只有网关→目标IP
            rf = trace_data["route_fallback"]
            rlabel = "隧道" if rf.get("is_tunnel") else "直连"
            for tip in ip_nodes:
                hop_edges.append(topo.edge(gw_id, tip["id"], rlabel))

        yield emit("step_done", {"id": "traceroute", "data": trace_data, "nodes": hop_nodes, "edges": hop_edges})
        time.sleep(0.3)

        # === 步骤 6: TLS（目标IP → TLS 信息） ===
        yield emit("step_start", {"id": "tls"})
        tls_data = step_tls(domain)
        steps_data["tls"] = tls_data

        tls_nodes = []
        tls_edges = []
        if tls_data.get("connected"):
            tls_label = "代理中继" if tls_data.get("proxy_detected") else (tls_data.get("tls_version", "TLS"))
            tls_cert = tls_data.get("cert_cn", "")
            tn = topo.node("tls", tls_label, tls_cert, "dot", 16)
            if tn:
                tls_nodes.append(tn)
                # TLS 附加到第一个目标 IP
                for tip in ip_nodes:
                    tls_edges.append(topo.edge(tip["id"], tn["id"], "TLS 握手"))
                    break

        yield emit("step_done", {"id": "tls", "data": tls_data, "nodes": tls_nodes, "edges": tls_edges})
        time.sleep(0.3)

        # === 步骤 7: 代理/隧道（附加到本机） ===
        yield emit("step_start", {"id": "proxy_tunnel"})
        proxy_data = step_proxy_tunnel()
        steps_data["proxy_tunnel"] = proxy_data

        proxy_nodes = []
        proxy_edges = []

        env_proxy = proxy_data.get("env_proxy", {})
        sys_proxy = proxy_data.get("system_proxy", {})
        tunnels = proxy_data.get("tunnel_interfaces", [])

        if env_proxy or (sys_proxy.get("HTTPEnable") == "1"):
            label = "代理"
            sub = ""
            for k, v in env_proxy.items():
                if "proxy" in k.lower() and "no_" not in k.lower():
                    sub = v
                    break
            if not sub and sys_proxy.get("HTTPEnable") == "1":
                sub = f"{sys_proxy.get('HTTPProxy','?')}:{sys_proxy.get('HTTPPort','?')}"
            pn = topo.node("proxy", label, sub, "dot", 14)
            if pn and local_id is not None:
                proxy_nodes.append(pn)
                proxy_edges.append(topo.edge(local_id, pn["id"], "代理"))

        if tunnels:
            tn = topo.node("tunnel", "VPN 隧道", ", ".join(tunnels[:3]), "dot", 14)
            if tn and local_id is not None:
                proxy_nodes.append(tn)
                proxy_edges.append(topo.edge(local_id, tn["id"], "隧道"))

        yield emit("step_done", {"id": "proxy_tunnel", "data": proxy_data, "nodes": proxy_nodes, "edges": proxy_edges})

        # === 完成 ===
        yield emit("done", {"domain": domain})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/")
def index():
    return send_from_directory(".", "network_check.html")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8765, debug=False)
