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