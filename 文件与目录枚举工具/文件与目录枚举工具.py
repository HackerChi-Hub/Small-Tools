import requests

# 定义目标URL和默认路径字典
target_url = input("请输入你需要探测的网址:")
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