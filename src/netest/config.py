"""netest 配置管理"""

# 默认值
DEFAULT_INTERFACE = "en0"
DEFAULT_MAX_HOPS = 30
DEFAULT_QUERIES_PER_HOP = 3
DEFAULT_TIMEOUT = 5  # 秒

# 速度测试配置
SPEEDTEST_CONFIG = {
    "download_threads": 4,
    "upload_threads": 4,
}

# WiFi 配置
WIFI_CONFIG = {
    "interface": "en0",
    "corewlan_available": False,
}

# Traceroute 配置
TRACEROUTE_CONFIG = {
    "max_hops": 30,
    "queries_per_hop": 3,
    "timeout": 5,
    "geo_api_url": "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp",
}

# 输出配置
OUTPUT_CONFIG = {
    "language": "zh_CN",
    "table_style": "rounded",
}
