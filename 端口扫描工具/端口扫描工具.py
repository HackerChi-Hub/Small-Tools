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